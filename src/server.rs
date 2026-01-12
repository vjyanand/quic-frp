use crate::protocol::{ServerAckMessage, write_frame, write_port_header};
use crate::{
  config::ServiceDefinition,
  protocol::{ClientControlMessage, read_frame},
};
use dashmap::DashMap;
use futures::future::{Either, select};
use smux::Session;
use socket2::{Domain, Protocol, Socket, Type};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncWriteExt, copy, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_kcp::{KcpConfig, KcpListener, KcpStream};
use tracing::{debug, info, trace, warn};

type PortRegistry = Arc<DashMap<u16, PortBinding>>;

pub async fn run_server(config: crate::config::ServerConfig) -> anyhow::Result<()> {
  info!("server starting on {}", config.listen_addr);
  let kcp_config = KcpConfig::default();

  let mut listener = KcpListener::bind(kcp_config, &config.listen_addr).await?;
  info!("server listening on {}", listener.local_addr()?);

  let registry: PortRegistry = Arc::new(DashMap::with_capacity(10));

  loop {
    let Ok((kcp_stream, socket_addr)) = listener.accept().await else {
      warn!("endpoint closed, shutting down");
      continue;
    };

    let registry = Arc::clone(&registry);
    tokio::spawn(async move {
      let result = handle_connection(kcp_stream, socket_addr, registry).await;
      debug!("result: {:?}", result);
    });
  }
}

async fn handle_connection(
  kcp_stream: KcpStream,
  socket_addr: SocketAddr,
  registry: PortRegistry,
) -> anyhow::Result<()> {
  let client_identity = ClientIdentity::from(socket_addr);
  trace!("new client with identity {}", client_identity);
  let smux_session = Session::server(kcp_stream, smux::Config::default()).await?;
  let mut smux_stream = smux_session.accept_stream().await?; // Control Stream from client
  debug!("Control stream established for {}", client_identity);

  loop {
    match read_frame::<ClientControlMessage, _>(&mut smux_stream).await {
      Ok(ClientControlMessage::RegisterService(def)) => {
        handle_register_service(smux_session.clone(), def, &mut smux_stream, &client_identity, &registry).await?;
      }
      Ok(ClientControlMessage::DeregisterService(def)) => {
        if let Err(e) = handle_unregister_service(def, &mut smux_stream, &client_identity, &registry).await {
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
  smux_session: Session,
  def: ServiceDefinition,
  control_send: &mut smux::Stream,
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

  let def_clone = def.clone();
  let runtime_handle = tokio::spawn(async move {
    accept_tcp_connections(smux_session, tcp_listener, &def_clone).await;
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

  let (domain, bind_addr) = match service.prefer_ipv6.unwrap_or_default() {
    true => (Domain::IPV6, format!("[::]:{}", service.remote_port)),
    false => (Domain::IPV4, format!("0.0.0.0:{}", service.remote_port)),
  };

  for attempt in 0..=max_retries {
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
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

async fn accept_tcp_connections(smux_session: Session, listener: TcpListener, service: &ServiceDefinition) {
  let port = service.remote_port;
  info!("Accepting TCP connections on port {} for service '{}'", port, service.name);

  loop {
    match listener.accept().await {
      Ok((tcp_stream, peer_addr)) => {
        debug!("Accepted TCP connection on port {} from {}", port, peer_addr);

        tokio::spawn({
          let smux_session = smux_session.clone();
          async move {
            if let Err(e) = handle_tcp_connection(smux_session, tcp_stream, port, peer_addr).await {
              warn!("TCP connection handler error for {}: {}", peer_addr, e);
            }
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
  smux_session: Session,
  tcp_stream: TcpStream,
  port: u16,
  peer_addr: SocketAddr,
) -> anyhow::Result<()> {
  debug!("Opening QUIC stream for TCP peer {}", peer_addr);
  let mut smux_stream =
    smux_session.open_stream().await.map_err(|e| anyhow::anyhow!("Failed to open QUIC stream: {}", e))?;
  debug!("Opened QUIC stream for TCP peer {}", peer_addr);

  // Write port header
  write_port_header(&mut smux_stream, port).await.map_err(|e| anyhow::anyhow!("Failed to write port header: {}", e))?;

  proxy_tcp_to_quic(tcp_stream, &mut smux_stream).await?;
  debug!("TCP connection {} closed", peer_addr);
  Ok(())
}

async fn proxy_tcp_to_quic(mut tcp: TcpStream, smux_stream: &mut smux::Stream) -> anyhow::Result<()> {
  let (mut tcp_r, mut tcp_w) = tcp.split();
  let (mut smux_stream_r, mut smux_stream_w) = split(smux_stream);

  let upstream = async {
    let result = copy(&mut tcp_r, &mut smux_stream_w).await;
    let _ = smux_stream_w.shutdown().await; // Ignore finish errors
    result
  };

  let downstream = async { copy(&mut smux_stream_r, &mut tcp_w).await };

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
  control_send: &mut smux::Stream,
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
