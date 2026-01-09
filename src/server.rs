use crate::protocol::{ServerAckMessage, write_frame};
use crate::{
  config::{ServiceDefinition, VERSION_MAJOR},
  protocol::{ClientControlMessage, read_frame},
  tls::TlsServerCertConfig,
};
use dashmap::DashMap;
use futures::future::{Either, select};
use quinn::{
  Connection, Endpoint, EndpointConfig, IdleTimeout, RecvStream, SendStream, ServerConfig, TransportConfig, VarInt,
  crypto::rustls::QuicServerConfig, default_runtime,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::copy;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

type PortRegistry = Arc<DashMap<u16, PortBinding>>;

pub async fn run_server(config: crate::config::ServerConfig) -> anyhow::Result<()> {
  info!("server starting on {}", config.listen_addr);

  let mut server_crypto = match (config.cert, config.key) {
    (Some(cert), Some(key)) => TlsServerCertConfig::from_pem_files(cert, key).into_server_config()?,
    _ => TlsServerCertConfig::self_signed(vec!["localhost"]).into_server_config()?,
  };

  let alpn = match config.token {
    Some(token) => format!("quic-proxy-{}-{}", VERSION_MAJOR, token).into_bytes(),
    None => format!("quic-proxy-{}", VERSION_MAJOR).into_bytes(),
  };

  server_crypto.alpn_protocols = vec![alpn];
  let server_crypto = Arc::new(QuicServerConfig::try_from(server_crypto)?);

  let mut server_config = ServerConfig::with_crypto(server_crypto);
  server_config.transport_config(create_transport_config()?);

  let bind_addr: SocketAddr = config.listen_addr.parse()?;
  let socket = create_udp_socket(bind_addr)?;
  let endpoint_config = EndpointConfig::default();
  let runtime = default_runtime().unwrap();
  let endpoint = Endpoint::new(endpoint_config, Some(server_config), socket, runtime)?;

  info!("server listening on {}", endpoint.local_addr()?);

  let registry: PortRegistry = Arc::new(DashMap::with_capacity(10));

  loop {
    let Some(incoming) = endpoint.accept().await else {
      warn!("endpoint closed, shutting down");
      continue;
    };

    let registry = Arc::clone(&registry);
    tokio::spawn(async move {
      let result = handle_connection(incoming, registry).await;
      debug!("result: {:?}", result);
    });
  }
}

async fn handle_connection(incoming: quinn::Incoming, registry: PortRegistry) -> anyhow::Result<()> {
  let connection = incoming.await?;
  let remote_address = connection.remote_address();
  debug!("new incoming connection from {} with id {}", remote_address, connection.stable_id());

  let client_identity = ClientIdentity::from(remote_address);
  trace!("new client with identity {}", client_identity);

  let (mut control_send, mut control_recv) = connection.accept_bi().await?; // Control Stream from client
  debug!("Control stream established for {}", client_identity);

  loop {
    match read_frame::<ClientControlMessage, _>(&mut control_recv).await {
      Ok(ClientControlMessage::RegisterService(def)) => {
        handle_register_service(def, &connection, &mut control_send, &client_identity, &registry).await?;
      }
      Ok(ClientControlMessage::DeregisterService(def)) => {
        if let Err(e) = handle_unregister_service(def, &mut control_send, &client_identity, &registry).await {
          warn!("handle_unregister_service error: {:?}", e);
        }
      }
      Err(e) => {
        debug!("Control stream ended for {}: {}", client_identity, e);
        break;
      }
    }
  }

  cleanup_listeners(&registry, &client_identity);
  Ok(())
}

async fn handle_register_service(
  def: ServiceDefinition,
  conn: &Connection,
  control_send: &mut SendStream,
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
      let ack = ServerAckMessage::ServiceRegistered { service_name, success: false, error: Some(msg) };
      write_frame(control_send, &ack).await?;
      return Ok(());
    }
  };

  // Send success ACK before spawning listener
  let ack = ServerAckMessage::ServiceRegistered { service_name: service_name.clone(), success: true, error: None };
  write_frame(control_send, &ack).await?;

  let conn_clone = conn.clone();
  let def_clone = def.clone();
  let runtime_handle = tokio::spawn(async move {
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
      Err(format!("Port {} already registered by this connection {}", def.remote_port, client_identity))
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
      info!("Port {} owned by stale connection, taking over for {}", def.remote_port, client_identity);
      if let Some((_, old_binding)) = registry.remove(&def.remote_port) {
        debug!(
          "Cancelling listener for port {} (client={}, service={})",
          def.remote_port, old_binding.client_identity, old_binding.service_name
        );
        old_binding.runtime_handle.abort();
      }
    }
    _ => {}
  }

  match create_tcp_listener_with_retry(def, 3).await {
    Ok(listener) => {
      info!("Created listener for service '{}' on port {} for {}", def.name, def.remote_port, client_identity);
      RegisterServiceResult::Registered(listener)
    }
    Err(e) => {
      let msg = format!("Failed to create listener for port {} ({}): {}", def.remote_port, client_identity, e);
      warn!("{}", msg);
      RegisterServiceResult::OsError(msg)
    }
  }
}

async fn create_tcp_listener_with_retry(service: &ServiceDefinition, max_retries: u32) -> anyhow::Result<TcpListener> {
  let mut last_error = None;
  let retry_delay = Duration::from_millis(100);
  let bind_addr = format!("0.0.0.0:{}", service.remote_port);

  for attempt in 0..=max_retries {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_tcp_nodelay(true)?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let bin = bind_addr.parse::<std::net::SocketAddr>()?;
    socket.bind(&bin.into())?;
    socket.listen(128)?;
    let std_listener: std::net::TcpListener = socket.into();

    match tokio::net::TcpListener::try_from(std_listener) {
      Ok(listener) => {
        if attempt > 0 {
          debug!("Successfully bound TCP listener on {} after {} retries", bind_addr, attempt);
        } else {
          debug!("Bound TCP listener: {}", bind_addr);
        }
        return Ok(listener);
      }
      Err(e) => {
        last_error = Some(e);
        if attempt < max_retries {
          debug!("Failed to bind {} (attempt {}), retrying: {}", bind_addr, attempt + 1, last_error.as_ref().unwrap());
          tokio::time::sleep(retry_delay).await;
        }
      }
    }
  }

  Err(anyhow::anyhow!("Failed to bind {} after {} attempts: {}", bind_addr, max_retries + 1, last_error.unwrap()))
}

async fn accept_tcp_connections(conn: &Connection, listener: TcpListener, service: &ServiceDefinition) {
  let port = service.remote_port;
  info!("Accepting TCP connections on port {} for service '{}'", port, service.name);

  loop {
    match listener.accept().await {
      Ok((tcp_stream, peer_addr)) => {
        debug!("Accepted TCP connection on port {} from {}", port, peer_addr);
        let conn_clone = conn.clone();
        tokio::spawn(async move {
          if let Err(e) = handle_tcp_connection(conn_clone, tcp_stream, port, peer_addr).await {
            warn!("TCP connection handler error for {}: {}", peer_addr, e);
          }
        });
      }
      Err(e) => {
        warn!("TCP accept error on port {}: {}", port, e);
        tokio::time::sleep(Duration::from_millis(100)).await;
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
  let (mut quic_send, mut quic_recv) =
    conn.open_bi().await.map_err(|e| anyhow::anyhow!("Failed to open QUIC stream: {}", e))?;
  debug!("Opened QUIC stream for TCP peer {}", peer_addr);

  // Write port header
  quic_send.write_all(&port.to_be_bytes()).await.map_err(|e| anyhow::anyhow!("Failed to write port header: {}", e))?;

  proxy_tcp_to_quic(tcp_stream, &mut quic_send, &mut quic_recv).await?;
  debug!("TCP connection {} closed", peer_addr);
  Ok(())
}

async fn proxy_tcp_to_quic(
  mut tcp: TcpStream,
  quic_send: &mut SendStream,
  quic_recv: &mut RecvStream,
) -> anyhow::Result<()> {
  let (mut tcp_r, mut tcp_w) = tcp.split();

  let upstream = async {
    let result = copy(&mut tcp_r, quic_send).await;
    let _ = quic_send.finish(); // Ignore finish errors
    result
  };

  let downstream = async { copy(quic_recv, &mut tcp_w).await };

  let upstream = std::pin::pin!(upstream);
  let downstream = std::pin::pin!(downstream);

  match select(upstream, downstream).await {
    Either::Left((res, _)) => {
      if let Err(e) = res {
        debug!("Upstream (TCP->QUIC) {}", e);
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

async fn handle_unregister_service(
  def: ServiceDefinition,
  control_send: &mut SendStream,
  client_identity: &ClientIdentity,
  registry: &PortRegistry,
) -> anyhow::Result<()> {
  debug!("UnregisterService: {:?} from {}", def, client_identity);

  let success = remove_port(def.remote_port, registry, client_identity);

  let ack = ServerAckMessage::ServiceUnregistered {
    service_name: def.name,
    success,
    error: (!success).then(|| "Port not owned by this connection".to_string()),
  };
  write_frame(control_send, &ack).await?;
  Ok(())
}

fn cleanup_listeners(registry: &PortRegistry, client: &ClientIdentity) {
  let ports = client.get_ports(registry);
  if ports.is_empty() {
    return;
  }

  let mut cleaned = 0u32;
  for port in ports {
    if remove_port(port, registry, client) {
      cleaned += 1;
    }
  }

  if cleaned > 0 {
    info!("Cleaned up {} ports for {}", cleaned, client);
  }
}

fn remove_port(port: u16, registry: &PortRegistry, client: &ClientIdentity) -> bool {
  let owns_port = registry.get(&port).map(|entry| client.is_same_connection(&entry.client_identity)).unwrap_or(false);

  if owns_port {
    if let Some((_, binding)) = registry.remove(&port) {
      binding.runtime_handle.abort();
      debug!("Cleaned up port {} (service: {})", port, binding.service_name);
      return true;
    }
  } else if registry.contains_key(&port) {
    debug!("Port {} was taken over, skipping cleanup", port);
  }
  false
}

// ──────────────────────────────────────────────────────────────
// Configuration helpers
// ──────────────────────────────────────────────────────────────
fn create_transport_config() -> anyhow::Result<Arc<TransportConfig>> {
  let mut transport = TransportConfig::default();
  transport.keep_alive_interval(Some(Duration::from_secs(5)));
  transport.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(20))?));
  transport.max_concurrent_bidi_streams(VarInt::from_u64(500)?);
  transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
  Ok(Arc::new(transport))
}

fn create_udp_socket(bind_addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
  let socket = Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(Protocol::UDP))?;
  socket.set_nonblocking(true)?;
  socket.set_keepalive(true)?;

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

  // Enable UDP GSO (send offload)
  let segment_size: u16 = 1472; // Typical MTU - headers
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
  let tos: libc::c_int = 0xB8; // DSCP EF
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

struct PortBinding {
  client_identity: ClientIdentity,
  service_name: Box<str>,
  runtime_handle: JoinHandle<()>,
}

#[derive(Clone, Debug)]
struct ClientIdentity {
  remote_ip: std::net::IpAddr,
  identifier: uuid::Uuid,
}

impl From<SocketAddr> for ClientIdentity {
  fn from(addr: SocketAddr) -> Self {
    let remote_ip = match addr.ip() {
      std::net::IpAddr::V6(v6) => {
        v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or_else(|| std::net::IpAddr::V6(v6))
      }
      ip => ip,
    };
    Self { remote_ip, identifier: uuid::Uuid::new_v4() }
  }
}

impl ClientIdentity {
  fn is_same_client(&self, other: &Self) -> bool {
    self.remote_ip == other.remote_ip
  }

  fn is_same_connection(&self, other: &Self) -> bool {
    self.remote_ip == other.remote_ip && self.identifier == other.identifier
  }

  fn get_ports(&self, registry: &PortRegistry) -> Vec<u16> {
    registry
      .iter()
      .filter_map(|entry| self.is_same_connection(&entry.client_identity).then_some(*entry.key()))
      .collect()
  }
}

impl std::fmt::Display for ClientIdentity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let uuid_str = self.identifier.as_hyphenated();
    write!(f, "{}({:.8})", self.remote_ip, uuid_str)
  }
}

enum RegisterServiceResult {
  Registered(TcpListener),
  AlreadyRegistered(String),
  Unsolicited(String),
  OsError(String),
}
