use std::{net::SocketAddr, sync::Arc, time::Duration};

use compio::io::copy;
use compio_net::{TcpListener, TcpOpts, TcpStream};
use compio_quic::{
  Connection, Endpoint, EndpointConfig, ServerBuilder, VarInt, congestion,
};
use dashmap::DashMap;
use futures::future::{Either, select};
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{debug, info, warn};

use crate::{
  config::{ServerConfig, ServiceDefinition, VERSION_MAJOR},
  protocol::{ClientControlMessage, ServerControlMessage, read_frame, write_frame},
  tls::TlsCertConfig,
};

type RuntimeHandle = compio::runtime::JoinHandle<()>;
type PortRegistry = Arc<DashMap<u16, PortBinding>>;

static BIND_ADDR_TYPE: std::sync::OnceLock<BindAddrType> = std::sync::OnceLock::new();

enum RegisterServiceResult {
  Registered(TcpListener),
  AlreadyRegistered(String),
  Unsolicited(String),
  OsError(String),
}

#[derive(Debug, Clone, Copy)]
enum BindAddrType {
  Ipv4,
  Ipv6,
  DualStack,
}

impl BindAddrType {
  #[inline]
  fn detect(addr: &SocketAddr) -> Self {
    match addr {
      SocketAddr::V4(_) => Self::Ipv4,
      SocketAddr::V6(v6) if v6.ip().is_unspecified() => Self::DualStack,
      SocketAddr::V6(_) => Self::Ipv6,
    }
  }

  #[inline]
  fn bind_addr(self, port: u16) -> SocketAddr {
    match self {
      Self::Ipv4 => SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port),
      Self::DualStack | Self::Ipv6 => {
        SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port)
      }
    }
  }
}

#[derive(Clone)]
struct ClientIdentity {
  remote_ip: std::net::IpAddr,
  identifier: uuid::Uuid,
}

impl From<SocketAddr> for ClientIdentity {
  #[inline]
  fn from(addr: SocketAddr) -> Self {
    let remote_ip = match addr.ip() {
      std::net::IpAddr::V6(v6) => v6
        .to_ipv4_mapped()
        .map(std::net::IpAddr::V4)
        .unwrap_or_else(|| std::net::IpAddr::V6(v6)),
      ip => ip,
    };
    Self { remote_ip, identifier: uuid::Uuid::new_v4() }
  }
}

impl ClientIdentity {
  #[inline]
  fn is_same_client(&self, other: &Self) -> bool {
    self.remote_ip == other.remote_ip
  }

  #[inline]
  fn is_same_connection(&self, other: &Self) -> bool {
    self.remote_ip == other.remote_ip && self.identifier == other.identifier
  }

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
    // Pre-format UUID slice to avoid allocation in hot path
    let uuid_str = self.identifier.as_hyphenated();
    write!(f, "{}({:.8})", self.remote_ip, uuid_str)
  }
}

struct PortBinding {
  client_identity: ClientIdentity,
  service_name: Box<str>, // Use Box<str> instead of String for immutable data
  runtime_handle: RuntimeHandle,
}

/// Server entry point
pub async fn run_server(config: ServerConfig) -> anyhow::Result<()> {
  info!("Server starting on {}", config.listen_addr);

  let (cert_der, key_der) = match (config.cert, config.key) {
    (Some(cert), Some(key)) => TlsCertConfig::from_pem_files(cert, key).load()?,
    _ => TlsCertConfig::self_signed(vec!["localhost"]).load()?,
  };

  let alpn = match config.token {
    Some(token) => format!("quic-proxy-{}-{}", VERSION_MAJOR, token),
    None => format!("quic-proxy-{}", VERSION_MAJOR),
  };

  let mut server_config = ServerBuilder::new_with_single_cert(cert_der, key_der)
    .map_err(|e| anyhow::anyhow!("Failed to create server config: {}", e))?
    .with_alpn_protocols(&[&alpn])
    .build();

  server_config.transport_config(create_transport_config()?);

  let bind_addr: SocketAddr = config.listen_addr.parse()?;
  let _ = BIND_ADDR_TYPE.set(BindAddrType::detect(&bind_addr));
  let socket = create_udp_socket(bind_addr)?;
  let endpoint = create_endpoint(socket, server_config)?;

  info!(
    "Server listening on {} bind mode {:?}",
    endpoint.local_addr()?,
    BIND_ADDR_TYPE.get().unwrap()
  );

  accept_connections(endpoint).await
}

fn create_transport_config() -> anyhow::Result<Arc<compio_quic::TransportConfig>> {
  let mut transport = compio_quic::TransportConfig::default();
  transport.max_concurrent_bidi_streams(VarInt::from_u64(500)?);
  transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
  // Additional optimizations
  transport.send_window(8 * 1024 * 1024); // 8MB send window
  transport.stream_receive_window(VarInt::from_u64(2 * 1024 * 1024)?); // 2MB per stream
  transport.receive_window(VarInt::from_u64(16 * 1024 * 1024)?); // 16MB total receive

  transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));

  Ok(Arc::new(transport))
}

fn create_udp_socket(bind_addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
  let socket =
    Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(Protocol::UDP))?;

  socket.set_nonblocking(true)?;
  // Note: UDP sockets don't support keepalive - removed invalid call

  // Increase buffer sizes (4MB each for high throughput)
  const BUFFER_SIZE: usize = 4 * 1024 * 1024;
  socket.set_recv_buffer_size(BUFFER_SIZE)?;
  socket.set_send_buffer_size(BUFFER_SIZE)?;

  #[cfg(target_os = "linux")]
  configure_linux_socket(&socket);

  socket.bind(&bind_addr.into())?;
  Ok(socket.into())
}

#[cfg(target_os = "linux")]
fn configure_linux_socket(socket: &Socket) {
  use std::os::fd::AsRawFd;

  const UDP_GRO: libc::c_int = 104;
  const UDP_SEGMENT: libc::c_int = 103; // GSO for send offload

  let fd = socket.as_raw_fd();
  let enable: libc::c_int = 1;

  // Enable UDP GRO (receive offload)
  let result = unsafe {
    libc::setsockopt(
      fd,
      libc::SOL_UDP,
      UDP_GRO,
      &enable as *const _ as *const libc::c_void,
      std::mem::size_of::<libc::c_int>() as libc::socklen_t,
    )
  };
  if result == 0 {
    debug!("UDP_GRO enabled");
  } else {
    debug!("UDP_GRO not available: {}", std::io::Error::last_os_error());
  }

  // Enable UDP GSO (send offload) with segment size
  let segment_size: u16 = 1472; // Typical MTU - IP/UDP headers
  let result = unsafe {
    libc::setsockopt(
      fd,
      libc::SOL_UDP,
      UDP_SEGMENT,
      &segment_size as *const _ as *const libc::c_void,
      std::mem::size_of::<u16>() as libc::socklen_t,
    )
  };
  if result == 0 {
    debug!("UDP_GSO enabled with segment size {}", segment_size);
  } else {
    debug!("UDP_GSO not available: {}", std::io::Error::last_os_error());
  }

  // Set IP_TOS for lower latency (DSCP EF)
  let tos: libc::c_int = 0xB8; // DSCP EF (Expedited Forwarding)
  let _ = unsafe {
    libc::setsockopt(
      fd,
      libc::IPPROTO_IP,
      libc::IP_TOS,
      &tos as *const _ as *const libc::c_void,
      std::mem::size_of::<libc::c_int>() as libc::socklen_t,
    )
  };
}

fn create_endpoint(
  udp_socket: std::net::UdpSocket,
  server_config: compio_quic::ServerConfig,
) -> anyhow::Result<Endpoint> {
  let socket = compio_net::UdpSocket::from_std(udp_socket)?;
  Endpoint::new(socket, EndpointConfig::default(), Some(server_config), None)
    .map_err(Into::into)
}

async fn accept_connections(endpoint: Endpoint) -> anyhow::Result<()> {
  let registry: PortRegistry = Arc::new(DashMap::with_capacity(64));

  loop {
    let Some(incoming) = endpoint.wait_incoming().await else {
      warn!("Endpoint closed, shutting down");
      break;
    };

    let remote_addr = incoming.remote_address();
    debug!("Incoming connection from {}", remote_addr);

    let registry = Arc::clone(&registry);
    compio::runtime::spawn(async move {
      match incoming.await {
        Ok(conn) => {
          let identity = ClientIdentity::from(remote_addr);
          info!("Connection established: {}", identity);
          if let Err(e) = handle_quic_connection(conn, &identity, &registry).await {
            warn!("Connection handler error for {}: {}", identity, e);
          }
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
    match read_frame::<ClientControlMessage>(&mut control_recv).await {
      Ok(ClientControlMessage::RegisterService(def)) => {
        handle_register_service(def, &conn, &mut control_send, client_identity, registry)
          .await?;
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
  conn: &Connection,
  control_send: &mut compio_quic::SendStream,
  client_identity: &ClientIdentity,
  registry: &PortRegistry,
) -> anyhow::Result<()> {
  let service_name = def.name.clone();
  let service_port = def.remote_port;

  let tcp_listener = match register_service(&def, client_identity, registry).await {
    RegisterServiceResult::Registered(tcp_listener) => tcp_listener,
    RegisterServiceResult::OsError(msg)
    | RegisterServiceResult::AlreadyRegistered(msg)
    | RegisterServiceResult::Unsolicited(msg) => {
      let ack = ServerControlMessage::ServiceRegistered {
        service_name,
        success: false,
        error: Some(msg),
      };
      write_frame(control_send, &ack).await?;
      return Ok(());
    }
  };

  // Send success ACK before spawning listener
  let ack = ServerControlMessage::ServiceRegistered {
    service_name: service_name.clone(),
    success: true,
    error: None,
  };
  write_frame(control_send, &ack).await?;

  let conn_clone = conn.clone();
  let def_clone = def.clone();
  let runtime_handle = compio::runtime::spawn(async move {
    accept_tcp_connections(&conn_clone, tcp_listener, &def_clone).await;
  });

  let port_binding = PortBinding {
    client_identity: client_identity.clone(),
    service_name: service_name.into_boxed_str(),
    runtime_handle,
  };
  registry.insert(service_port, port_binding);

  Ok(())
}

async fn register_service(
  def: &ServiceDefinition,
  client_identity: &ClientIdentity,
  registry: &PortRegistry,
) -> RegisterServiceResult {
  debug!("RegisterService: {:?} from {}", def, client_identity);

  // Check existing registration - minimize lock duration
  let takeover_needed = registry.get(&def.remote_port).map(|existing| {
    if client_identity.is_same_connection(&existing.client_identity) {
      Err(format!(
        "Port {} already registered by this connection {}",
        def.remote_port, client_identity
      ))
    } else if client_identity.is_same_client(&existing.client_identity) {
      Ok(true) // Same client, different connection - takeover
    } else {
      Err(format!(
        "Port {} conflict: requested by {} but owned by {} (service: {})",
        def.remote_port, client_identity, existing.client_identity, existing.service_name
      ))
    }
  });

  match takeover_needed {
    Some(Err(msg)) if msg.contains("already registered") => {
      info!("{}", msg);
      return RegisterServiceResult::AlreadyRegistered(msg);
    }
    Some(Err(msg)) => {
      return RegisterServiceResult::Unsolicited(msg);
    }
    Some(Ok(true)) => {
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
    _ => {}
  }

  match create_tcp_listener_with_retry(def, 3).await {
    Ok(listener) => {
      info!(
        "Created listener for service '{}' on port {} for {}",
        def.name, def.remote_port, client_identity
      );
      RegisterServiceResult::Registered(listener)
    }
    Err(e) => {
      let msg = format!(
        "Failed to create listener for port {} ({}): {}",
        def.remote_port, client_identity, e
      );
      warn!("{}", msg);
      RegisterServiceResult::OsError(msg)
    }
  }
}

async fn create_tcp_listener_with_retry(
  service: &ServiceDefinition,
  max_retries: u32,
) -> anyhow::Result<TcpListener> {
  let bind_addr = BIND_ADDR_TYPE
    .get()
    .copied()
    .unwrap_or(BindAddrType::Ipv4)
    .bind_addr(service.remote_port);

  let opts = TcpOpts::new()
    .nodelay(true)
    .keepalive(true)
    .reuse_port(true)
    .write_timeout(Duration::from_secs(2))
    .read_timeout(Duration::from_secs(2));

  let mut last_error = None;
  let retry_delay = Duration::from_millis(100);

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
            "Failed to bind {} (attempt {}), retrying: {}",
            bind_addr,
            attempt + 1,
            last_error.as_ref().unwrap()
          );
          compio::time::sleep(retry_delay).await;
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

async fn handle_unregister_service(
  def: ServiceDefinition,
  control_send: &mut compio_quic::SendStream,
  client_identity: &ClientIdentity,
  registry: &PortRegistry,
) -> anyhow::Result<()> {
  debug!("UnregisterService: {:?} from {}", def, client_identity);

  let success = remove_port(def.remote_port, registry, client_identity).await;

  let ack = ServerControlMessage::ServiceUnregistered {
    service_name: def.name,
    success,
    error: (!success).then(|| "Port not owned by this connection".to_string()),
  };
  write_frame(control_send, &ack).await?;

  Ok(())
}

async fn accept_tcp_connections(
  conn: &Connection,
  listener: TcpListener,
  service: &ServiceDefinition,
) {
  let port = service.remote_port;
  info!("Accepting TCP connections on port {} for service '{}'", port, service.name);

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

  // Write port header - use array directly without intermediate variable
  quic_send
    .write_all(&port.to_be_bytes())
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
    let _ = quic_send.finish(); // Ignore finish errors in fast path
    result
  };

  let downstream = copy(quic_recv, &mut tcp_w);

  let upstream = std::pin::pin!(upstream);
  let downstream = std::pin::pin!(downstream);

  // Use select for first-completion semantics
  match select(upstream, downstream).await {
    Either::Left((Err(e), _)) => debug!("Upstream (TCP->QUIC) error: {}", e),
    Either::Right((Err(e), _)) => debug!("Downstream (QUIC->TCP) error: {}", e),
    _ => {}
  }

  Ok(())
}

/// Remove a port binding if owned by the given client. Returns true if removed.
async fn remove_port(
  port: u16,
  registry: &PortRegistry,
  client: &ClientIdentity,
) -> bool {
  // Check ownership first with minimal lock time
  let owns_port = registry
    .get(&port)
    .map(|entry| client.is_same_connection(&entry.client_identity))
    .unwrap_or(false);

  if owns_port {
    if let Some((_, binding)) = registry.remove(&port) {
      binding.runtime_handle.cancel().await;
      debug!("Cleaned up port {} (service: {})", port, binding.service_name);
      return true;
    }
  } else if registry.contains_key(&port) {
    debug!("Port {} was taken over, skipping cleanup", port);
  }

  false
}

async fn cleanup_listeners(registry: &PortRegistry, client: &ClientIdentity) {
  let ports = client.get_ports(registry);
  if ports.is_empty() {
    return;
  }

  let mut cleaned = 0u32;
  for port in ports {
    if remove_port(port, registry, client).await {
      cleaned += 1;
    }
  }

  if cleaned > 0 {
    info!("Cleaned up {} ports for {}", cleaned, client);
  }
}
