use std::{net::SocketAddr, sync::Arc, time::Duration};

use compio::io::copy;
use compio_net::{TcpListener, TcpOpts, TcpStream};
use compio_quic::{
  Connection, Endpoint, EndpointConfig, IdleTimeout, ServerBuilder, VarInt, congestion,
};
use dashmap::DashMap;
use futures::future::{Either, select};
use log::{debug, error, info, warn};
use socket2::{Domain, Protocol, Socket, Type};

use crate::{
  config::{
    ServerConfig, ServiceDefinition, VERSION_MAJOR, control_read_frame,
    control_write_frame,
  },
  protocol::{ClientControlMessage, ServerControlMessage},
  tls::TlsCertConfig,
};

type RuntimeHandle = compio::runtime::JoinHandle<()>;
type PortRegistry = Arc<DashMap<u16, PortBinding>>;

static BIND_ADDR_TYPE: std::sync::OnceLock<BindAddrType> = std::sync::OnceLock::new();

#[derive(Debug)]
enum BindAddrType {
  Ipv4,      // 0.0.0.0
  Ipv6,      // [::]
  DualStack, // [::] with dual-stack enabled
}

impl BindAddrType {
  fn detect(addr: &SocketAddr) -> Self {
    match addr {
      SocketAddr::V4(_) => Self::Ipv4,
      SocketAddr::V6(v6) if v6.ip().is_unspecified() => Self::DualStack,
      SocketAddr::V6(_) => Self::Ipv6,
    }
  }
}

#[derive(Clone)]
struct ClientIdentity {
  remote_ip: std::net::IpAddr,
  identifier: uuid::Uuid,
}

impl ClientIdentity {
  fn from_socket_addr(addr: SocketAddr) -> Self {
    let remote_ip = match addr.ip() {
      std::net::IpAddr::V6(v6) => {
        if let Some(v4) = v6.to_ipv4_mapped() {
          std::net::IpAddr::V4(v4)
        } else {
          std::net::IpAddr::V6(v6)
        }
      }
      ip => ip,
    };
    Self { remote_ip, identifier: uuid::Uuid::new_v4() }
  }

  /// Check if this is the same logical client (same IP, possibly different connection)
  fn is_same_client(&self, other: &ClientIdentity) -> bool {
    self.remote_ip == other.remote_ip
  }

  /// Check if this is the exact same connection (same IP and UUID)
  fn is_same_connection(&self, other: &ClientIdentity) -> bool {
    self.remote_ip == other.remote_ip && self.identifier == other.identifier
  }

  /// Get all ports owned by this specific connection
  fn get_ports(&self, registry: &PortRegistry) -> Vec<u16> {
    registry
      .iter()
      .filter_map(|entry| {
        self.is_same_connection(&entry.client_identity).then_some(*entry.key())
      })
      .collect()
  }
}

impl std::fmt::Display for ClientIdentity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}({})", self.remote_ip, &self.identifier.to_string()[..8])
  }
}

struct PortBinding {
  client_identity: ClientIdentity,
  service_name: String,
  runtime_handle: RuntimeHandle,
}

/// Server entry point: bind UDP socket, accept QUIC connections, handle control protocol.
pub async fn run_server(config: ServerConfig) -> anyhow::Result<()> {
  info!("Server starting on {}", config.listen_addr);

  let (cert_der, key_der) = if config.cert.is_some() && config.key.is_some() {
    TlsCertConfig::from_pem_files(config.cert.unwrap(), config.key.unwrap()).load()?
  } else {
    TlsCertConfig::self_signed(vec!["localhost".to_owned()]).load()?
  };

  let alpn = if let Some(token) = config.token {
    format!("quic-proxy-{}-{}", VERSION_MAJOR, token)
  } else {
    format!("quic-proxy-{}", VERSION_MAJOR)
  };

  // Configure QUIC server
  let mut server_config = ServerBuilder::new_with_single_cert(cert_der, key_der)
    .map_err(|e| anyhow::anyhow!("Failed to create server config: {}", e))?
    .with_alpn_protocols(&[&alpn])
    .build();

  server_config.transport_config(create_transport_config()?);

  // Bind UDP socket with socket2 for advanced options
  let bind_addr: SocketAddr = config.listen_addr.parse()?;
  let _ = BIND_ADDR_TYPE.set(BindAddrType::detect(&bind_addr));
  let socket = create_udp_socket(bind_addr)?;
  let endpoint = create_endpoint(socket, server_config)?;

  info!(
    "Server listening on {} bind mode {:?}",
    endpoint.local_addr()?,
    BIND_ADDR_TYPE.get()
  );

  // Accept QUIC connections indefinitely
  accept_connections(endpoint).await?;

  Ok(())
}

/// Create QUIC transport configuration optimized for proxy workload.
fn create_transport_config() -> anyhow::Result<Arc<compio_quic::TransportConfig>> {
  let mut transport = compio_quic::TransportConfig::default();

  // Keep-alive to detect dead connections
  transport.keep_alive_interval(Some(Duration::from_secs(5)));

  // Longer idle timeout for server (handles multiple clients)
  transport.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(60))?));

  // High stream limit for busy proxies
  transport.max_concurrent_bidi_streams(VarInt::from_u64(500)?);

  transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));

  Ok(Arc::new(transport))
}

/// Create and configure UDP socket with optimal settings for QUIC.
fn create_udp_socket(bind_addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
  let socket =
    Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(Protocol::UDP))?;

  socket.set_nonblocking(true)?;
  socket.set_keepalive(true)?;
  socket.bind(&bind_addr.into())?;
  Ok(socket.into())
}

/// Create QUIC endpoint from UDP socket.
fn create_endpoint(
  udp_socket: std::net::UdpSocket,
  server_config: compio_quic::ServerConfig,
) -> anyhow::Result<Endpoint> {
  let socket = compio_net::UdpSocket::from_std(udp_socket)?;
  let endpoint =
    Endpoint::new(socket, EndpointConfig::default(), Some(server_config), None)?;
  Ok(endpoint)
}

/// Accept incoming QUIC connections and spawn handlers.
async fn accept_connections(endpoint: Endpoint) -> anyhow::Result<()> {
  let registry: PortRegistry = Arc::new(DashMap::new());

  loop {
    let incoming = match endpoint.wait_incoming().await {
      Some(inc) => inc,
      None => {
        warn!("Endpoint closed, shutting down");
        break;
      }
    };

    let remote_addr = incoming.remote_address();
    debug!("Incoming connection from {}", remote_addr);

    let registry = registry.clone();

    // Spawn handler for each connection
    compio::runtime::spawn(async move {
      match incoming.await {
        Ok(conn) => {
          let identity = ClientIdentity::from_socket_addr(remote_addr);
          info!("Connection established: {}", identity);

          if let Err(e) = handle_quic_connection(conn, &identity, &registry).await {
            warn!("Connection handler error for {}: {}", identity, e);
          }

          // Cleanup all listeners for this specific connection
          cleanup_listeners(&registry, &identity).await;
          info!("Connection closed: {}", identity);
        }
        Err(e) => {
          warn!("Handshake failed for {}: {}", remote_addr, e);
        }
      }
    })
    .detach();
  }

  Ok(())
}

async fn handle_quic_connection(
  conn: Connection,
  client_identity: &ClientIdentity,
  registry: &PortRegistry,
) -> anyhow::Result<()> {
  let (mut control_send, mut control_recv) = conn.accept_bi().await?;
  debug!("Control stream established for {}", client_identity);

  loop {
    match control_read_frame::<ClientControlMessage>(&mut control_recv).await {
      Ok(ClientControlMessage::RegisterService(def)) => {
        if let Err(e) = handle_register_service(
          def,
          &mut control_send,
          &conn,
          client_identity,
          registry,
        )
        .await
        {
          warn!("handle_register_service error: {:?}", e);
        }
      }
      Ok(ClientControlMessage::UnregisterService(def)) => {
        if let Err(e) =
          handle_unregister_service(def, &mut control_send, client_identity, registry)
            .await
        {
          warn!("handle_unregister_service error: {:?}", e);
        }
      }
      Err(e) => {
        debug!("Control stream ended for {}: {}", client_identity, e);
        break;
      }
    }
  }

  Ok(())
}

async fn handle_register_service(
  def: ServiceDefinition,
  control_send: &mut compio_quic::SendStream,
  conn: &Connection,
  client_identity: &ClientIdentity,
  registry: &PortRegistry,
) -> anyhow::Result<()> {
  debug!("RegisterService: {:?} from {}", def, client_identity);

  let need_takeover = {
    if let Some(existing) = registry.get(&def.remote_port) {
      if client_identity.is_same_connection(&existing.client_identity) {
        // Same connection re-registering - already registered
        info!(
          "Port {} already registered by this connection {}",
          def.remote_port, client_identity
        );
        let ack = ServerControlMessage::ServiceRegistered {
          service_name: def.service_name,
          success: true,
          error: Some("Already registered".to_string()),
        };
        control_write_frame(control_send, &ack).await?;
        return Ok(());
      } else if client_identity.is_same_client(&existing.client_identity) {
        // Same client, different connection (reconnect) - take over
        true
      } else {
        // Different client - reject
        error!(
          "Port {} conflict: requested by {} but owned by {} (service: {})",
          def.remote_port,
          client_identity,
          existing.client_identity,
          existing.service_name
        );
        let ack = ServerControlMessage::ServiceRegistered {
          service_name: def.service_name,
          success: false,
          error: Some(format!(
            "Port {} is already in use by another client",
            def.remote_port
          )),
        };
        control_write_frame(control_send, &ack).await?;
        return Ok(());
      }
    } else {
      false
    }
  };

  if need_takeover {
    info!(
      "Port {} owned by stale connection, taking over for {}",
      def.remote_port, client_identity
    );
    if let Some((_, old_binding)) = registry.remove(&def.remote_port) {
      debug!(
        "Cancelling listener for port {} (client={}, service={})",
        def.remote_port, old_binding.client_identity, old_binding.service_name
      );
      old_binding.runtime_handle.cancel().await;
    }
  }

  let listener = match create_tcp_listener_with_retry(&def, 3).await {
    Ok(l) => l,
    Err(e) => {
      warn!(
        "Failed to create listener for port {} ({}): {}",
        def.remote_port, client_identity, e
      );
      let ack = ServerControlMessage::ServiceRegistered {
        service_name: def.service_name,
        success: false,
        error: Some(format!("{}", e)),
      };
      control_write_frame(control_send, &ack).await?;
      return Ok(());
    }
  };

  info!(
    "Created listener for service '{}' on port {} for {}",
    def.service_name, def.remote_port, client_identity
  );

  let l_client_identity = client_identity.clone();
  let l_registry = registry.clone();
  let l_port = def.remote_port;
  let l_conn = conn.clone();
  let l_def = def.clone();

  let accept_task = compio::runtime::spawn(async move {
    accept_tcp_connections(&l_conn, listener, &l_def).await;
    // Remove from registry if still owned by this connection
    if let Some(entry) = l_registry.get(&l_port)
      && l_client_identity.is_same_connection(&entry.client_identity)
    {
      drop(entry);
      l_registry.remove(&l_port);
    }
  });

  // Track in global registry
  registry.insert(
    def.remote_port,
    PortBinding {
      client_identity: client_identity.clone(),
      service_name: def.service_name.clone(),
      runtime_handle: accept_task,
    },
  );

  let ack = ServerControlMessage::ServiceRegistered {
    service_name: def.service_name,
    success: true,
    error: None,
  };
  control_write_frame(control_send, &ack).await?;

  Ok(())
}

async fn handle_unregister_service(
  def: ServiceDefinition,
  control_send: &mut compio_quic::SendStream,
  client_identity: &ClientIdentity,
  registry: &PortRegistry,
) -> anyhow::Result<()> {
  debug!("UnregisterService: {:?} from {}", def, client_identity);

  let mut success = false;

  if let Some(entry) = registry.get(&def.remote_port) {
    if client_identity.is_same_connection(&entry.client_identity) {
      drop(entry);
      if let Some((_, binding)) = registry.remove(&def.remote_port) {
        binding.runtime_handle.cancel().await;
        info!(
          "Unregistered service '{}' on port {} for {}",
          def.service_name, def.remote_port, client_identity
        );
        success = true;
      }
    } else {
      debug!(
        "Port {} not owned by this connection {}, ignoring unregister",
        def.remote_port, client_identity
      );
    }
  } else {
    debug!("No active listener found for port {} ({})", def.remote_port, client_identity);
  }

  let ack = ServerControlMessage::ServiceUnregistered {
    service_name: def.service_name,
    success,
    error: if success {
      None
    } else {
      Some("Port not owned by this connection".to_string())
    },
  };
  control_write_frame(control_send, &ack).await?;

  Ok(())
}

async fn accept_tcp_connections(
  conn: &Connection,
  listener: TcpListener,
  service: &ServiceDefinition,
) {
  let port = service.remote_port;
  info!(
    "Accepting TCP connections on port {} for service '{}'",
    port, service.service_name
  );

  loop {
    match listener.accept().await {
      Ok((tcp_stream, peer_addr)) => {
        debug!("Accepted TCP connection on port {} from {}", port, peer_addr);

        let conn_clone = conn.clone();

        compio::runtime::spawn(async move {
          if let Err(e) =
            handle_tcp_connection(conn_clone, tcp_stream, port, peer_addr).await
          {
            warn!("TCP connection handler error for {}: {}", peer_addr, e);
          }
        })
        .detach();
      }
      Err(e) => {
        warn!("TCP accept error on port {}: {}", port, e);
        compio::time::sleep(Duration::from_millis(100)).await;
      }
    }
  }
}

async fn handle_tcp_connection(
  conn: Connection,
  tcp_stream: TcpStream,
  port: u16,
  peer_addr: SocketAddr,
) -> anyhow::Result<()> {
  let (mut quic_send, mut quic_recv) = conn
    .open_bi_wait()
    .await
    .map_err(|e| anyhow::anyhow!("Failed to open QUIC stream: {}", e))?;

  debug!("Opened QUIC stream for TCP peer {}", peer_addr);

  let port_header = port.to_be_bytes();
  quic_send
    .write_all(&port_header)
    .await
    .map_err(|e| anyhow::anyhow!("Failed to write port header: {}", e))?;

  proxy_tcp_to_quic(tcp_stream, &mut quic_send, &mut quic_recv).await?;

  debug!("TCP connection {} closed", peer_addr);
  Ok(())
}

async fn proxy_tcp_to_quic(
  tcp: TcpStream,
  quic_send: &mut compio_quic::SendStream,
  quic_recv: &mut compio_quic::RecvStream,
) -> anyhow::Result<()> {
  let (mut tcp_r, mut tcp_w) = tcp.split();

  let upstream = async {
    let result = copy(&mut tcp_r, quic_send).await;
    let _ = quic_send.finish();
    result
  };

  let downstream = async { copy(quic_recv, &mut tcp_w).await };

  let upstream = std::pin::pin!(upstream);
  let downstream = std::pin::pin!(downstream);

  match select(upstream, downstream).await {
    Either::Left((res, _)) => {
      if let Err(e) = res {
        debug!("Upstream (TCP->QUIC) error: {}", e);
      }
    }
    Either::Right((res, _)) => {
      if let Err(e) = res {
        debug!("Downstream (QUIC->TCP) error: {}", e);
      }
    }
  }

  Ok(())
}

async fn create_tcp_listener_with_retry(
  service: &ServiceDefinition,
  max_retries: u32,
) -> anyhow::Result<TcpListener> {
  let bind_addr = match BIND_ADDR_TYPE.get_or_init(|| BindAddrType::Ipv4) {
    BindAddrType::Ipv4 => format!("0.0.0.0:{}", service.remote_port),
    BindAddrType::DualStack | BindAddrType::Ipv6 => {
      format!("[::]:{}", service.remote_port)
    }
  };
  let opts = TcpOpts::new()
    .nodelay(true)
    .keepalive(true)
    .reuse_port(true)
    .write_timeout(Duration::from_secs(2))
    .read_timeout(Duration::from_secs(2));

  let mut last_error = None;

  for attempt in 0..=max_retries {
    match TcpListener::bind_with_options(&bind_addr, opts).await {
      Ok(listener) => {
        if attempt > 0 {
          debug!(
            "Successfully bound TCP listener on {} after {} retries",
            bind_addr, attempt
          );
        } else {
          debug!("Bound TCP listener: {}", bind_addr);
        }
        return Ok(listener);
      }
      Err(e) => {
        last_error = Some(e);
        if attempt < max_retries {
          debug!(
            "Failed to bind {} (attempt {}), retrying in 100ms: {}",
            bind_addr,
            attempt + 1,
            last_error.as_ref().unwrap()
          );
          compio::time::sleep(Duration::from_millis(100)).await;
        }
      }
    }
  }

  Err(anyhow::anyhow!(
    "Failed to bind {} after {} attempts: {}",
    bind_addr,
    max_retries + 1,
    last_error.unwrap()
  ))
}

/// Cleanup all listeners owned by this specific connection
async fn cleanup_listeners(registry: &PortRegistry, client: &ClientIdentity) {
  let ports = client.get_ports(registry);
  let mut cleaned = 0;

  for port in ports {
    // Double-check this connection still owns it (not taken over)
    if let Some(entry) = registry.get(&port) {
      if client.is_same_connection(&entry.client_identity) {
        drop(entry);
        if let Some((_, binding)) = registry.remove(&port) {
          binding.runtime_handle.cancel().await;
          debug!("Cleaned up port {} (service: {})", port, binding.service_name);
          cleaned += 1;
        }
      } else {
        debug!(
          "Port {} was taken over by {}, skipping cleanup",
          port, entry.client_identity
        );
      }
    }
  }

  if cleaned > 0 {
    info!("Cleaned up {} ports for {}", cleaned, client);
  }
}
