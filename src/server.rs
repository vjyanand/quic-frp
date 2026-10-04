use crate::protocol::{ServerAckMessage, StreamHeader, constant_time_eq, write_frame, write_stream_header};
use crate::{
  config::ServiceDefinition,
  protocol::{ClientControlMessage, ClientHello, read_frame},
  tls::{self, TlsServerCertConfig},
};
use dashmap::DashMap;
use quinn::{
  Connection, Endpoint, EndpointConfig, IdleTimeout, RecvStream, SendStream, ServerConfig, TransportConfig, VarInt,
  crypto::rustls::QuicServerConfig, default_runtime,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::copy;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

type PortRegistry = Arc<DashMap<u16, PortBinding>>;

/// How long a new connection has to send its `ClientHello`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// QUIC application close code sent when the client fails authentication.
const CLOSE_UNAUTHORIZED: u32 = 0x401;

pub async fn run_server(config: crate::config::ServerConfig) -> anyhow::Result<()> {
  info!("server starting on {}", config.listen_addr);

  let mut server_crypto = match (config.cert, config.key) {
    (Some(cert), Some(key)) => TlsServerCertConfig::from_pem_files(cert, key).into_server_config()?,
    _ => TlsServerCertConfig::self_signed(vec!["localhost"]).into_server_config()?,
  };

  let alpn = tls::alpn();
  server_crypto.alpn_protocols = vec![alpn.into()];
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
  let token: Arc<Option<String>> = Arc::new(config.token);

  loop {
    let Some(incoming) = endpoint.accept().await else {
      warn!("endpoint closed, shutting down");
      break;
    };

    let registry = Arc::clone(&registry);
    let token = Arc::clone(&token);
    tokio::spawn(async move {
      let result = handle_connection(incoming, registry, &token).await;
      debug!("result: {:?}", result);
    });
  }

  Ok(())
}

async fn handle_connection(
  incoming: quinn::Incoming,
  registry: PortRegistry,
  token: &Option<String>,
) -> anyhow::Result<()> {
  let connection = incoming.await?;
  let remote_address = connection.remote_address();
  debug!("new incoming connection from {} with id {}", remote_address, connection.stable_id());

  let client_identity = ClientIdentity::from(remote_address);
  trace!("new client with identity {}", client_identity);

  let (mut control_send, mut control_recv) = connection.accept_bi().await?; // Control Stream from client
  debug!("control stream established for {}", client_identity);

  let hello = tokio::time::timeout(HELLO_TIMEOUT, read_frame::<ClientHello, _>(&mut control_recv))
    .await
    .map_err(|_| anyhow::anyhow!("client {} did not send hello within {:?}", client_identity, HELLO_TIMEOUT))??;
  if !is_authorized(token, &hello.token) {
    warn!("rejecting {}: invalid token", client_identity);
    connection.close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"unauthorized");
    return Err(anyhow::anyhow!("client {} failed authentication", client_identity));
  }

  let loop_result: anyhow::Result<()> = async {
    loop {
      match read_frame::<ClientControlMessage, _>(&mut control_recv).await {
        Ok(ClientControlMessage::RegisterService(def)) => {
          if let Err(e) =
            handle_register_service(def, &connection, &mut control_send, &client_identity, &registry).await
          {
            warn!("handle_register_service error: {:?}", e);
            return Err(e);
          }
        }
        Ok(ClientControlMessage::DeregisterService(def)) => {
          if let Err(e) = handle_unregister_service(def, &mut control_send, &client_identity, &registry).await {
            warn!("handle_unregister_service error: {:?}", e);
          }
        }
        Err(e) => {
          debug!("control stream ended for {}: {:#}  (chain: {:?})", client_identity, e, e);
          break;
        }
      }
    }
    Ok(())
  }
  .await;

  cleanup_listeners(&registry, &client_identity);
  loop_result
}

fn is_authorized(expected: &Option<String>, presented: &Option<String>) -> bool {
  match (expected, presented) {
    (None, _) => true,
    (Some(expected), Some(presented)) => constant_time_eq(expected.as_bytes(), presented.as_bytes()),
    (Some(_), None) => false,
  }
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
    | RegisterServiceResult::UnSolicited(msg) => {
      let ack = ServerAckMessage::ServiceRegistered { service_name, success: false, error: Some(msg) };
      write_frame(control_send, &ack).await?;
      return Ok(());
    }
  };

  // Send success ACK before spawning listener
  let ack = ServerAckMessage::ServiceRegistered { service_name: service_name.clone(), success: true, error: None };
  write_frame(control_send, &ack).await?;

  let cancel = CancellationToken::new();
  let conn_clone = conn.clone();
  let def_clone = def.clone();
  let listener_cancel = cancel.clone();
  tokio::spawn(async move {
    accept_tcp_connections(&conn_clone, tcp_listener, &def_clone, listener_cancel).await;
  });

  let port_binding =
    PortBinding { client_identity: client_identity.clone(), service_name: service_name.into_boxed_str(), cancel };

  registry.insert(service_port, port_binding);
  Ok(())
}

async fn register_service(
  def: &ServiceDefinition,
  client_identity: &ClientIdentity,
  registry: &PortRegistry,
) -> RegisterServiceResult {
  debug!("registerService: {:?} from {}", def, client_identity);

  // Classify any existing owner, then release the shard read lock before mutating:
  // calling `registry.remove` while a `registry.get` guard on the same key is alive deadlocks.
  let existing = registry.get(&def.remote_port).map(|existing| {
    if client_identity == &existing.client_identity {
      ExistingOwner::SameConnection
    } else if client_identity.is_same_client(&existing.client_identity) {
      ExistingOwner::StaleConnection
    } else {
      ExistingOwner::Other(format!("{} (service: {})", existing.client_identity, existing.service_name))
    }
  });

  match existing {
    None => {}
    Some(ExistingOwner::SameConnection) => {
      return RegisterServiceResult::AlreadyRegistered(format!(
        "port {} already registered by this connection {}",
        def.remote_port, client_identity
      ));
    }
    Some(ExistingOwner::StaleConnection) => {
      info!("Port {} owned by stale connection, taking over for {}", def.remote_port, client_identity);
      if let Some((_, old_binding)) = registry.remove(&def.remote_port) {
        debug!(
          "cancelling listener for port {} (client={}, service={})",
          def.remote_port, old_binding.client_identity, old_binding.service_name
        );
        old_binding.cancel.cancel();
      }
    }
    Some(ExistingOwner::Other(owner)) => {
      return RegisterServiceResult::UnSolicited(format!(
        "port {} conflict: requested by {} but owned by {}",
        def.remote_port, client_identity, owner
      ));
    }
  }

  match create_tcp_listener_with_retry(def, 3).await {
    Ok(listener) => {
      info!("created listener for service '{}' on port {} for {}", def.name, def.remote_port, client_identity);
      RegisterServiceResult::Registered(listener)
    }
    Err(e) => {
      let msg = format!("failed to create listener for port {} ({}): {}", def.remote_port, client_identity, e);
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

  let bind_addr: SocketAddr = bind_addr.parse()?;

  // Retry the bind itself: on a stale-connection takeover the previous listener is
  // closed asynchronously by its accept task, so the port may still be held briefly.
  for attempt in 0..=max_retries {
    match bind_tcp_listener(domain, bind_addr) {
      Ok(listener) => {
        if attempt > 0 {
          debug!("successfully bound TCP listener on {} after {} retries", bind_addr, attempt);
        } else {
          debug!("bound TCP listener: {}", bind_addr);
        }
        return Ok(listener);
      }
      Err(e) => {
        last_error = Some(e);
        if attempt < max_retries {
          debug!("failed to bind {} (attempt {}), retrying: {}", bind_addr, attempt + 1, last_error.as_ref().unwrap());
          tokio::time::sleep(retry_delay).await;
        }
      }
    }
  }

  Err(anyhow::anyhow!("failed to bind {} after {} attempts: {}", bind_addr, max_retries + 1, last_error.unwrap()))
}

fn bind_tcp_listener(domain: Domain, bind_addr: SocketAddr) -> std::io::Result<TcpListener> {
  let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
  socket.set_tcp_nodelay(true)?;
  socket.set_nonblocking(true)?;
  socket.set_reuse_address(true)?;
  socket.bind(&bind_addr.into())?;
  socket.listen(128)?;
  let std_listener: std::net::TcpListener = socket.into();
  TcpListener::from_std(std_listener)
}

async fn accept_tcp_connections(
  conn: &Connection,
  listener: TcpListener,
  service: &ServiceDefinition,
  cancel: CancellationToken,
) {
  let port = service.remote_port;
  info!("accepting TCP connections on port {} for service '{}'", port, service.name);

  loop {
    tokio::select! {
      biased;
      _ = cancel.cancelled() => {
        debug!("listener for port {} cancelled, releasing", port);
        break;
      }
      accept_result = listener.accept() => {
        match accept_result {
          Ok((tcp_stream, peer_addr)) => {
            debug!("accepted TCP connection on port {} from {}", port, peer_addr);
            let conn_clone = conn.clone();
            let compression = service.compression.unwrap_or_default();
            let conn_cancel = cancel.child_token();

            tokio::spawn(async move {
              if let Err(e) =
                handle_tcp_connection(conn_clone, tcp_stream, port, peer_addr, compression, conn_cancel).await
              {
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
  }
}

async fn handle_tcp_connection(
  conn: Connection,
  tcp_stream: TcpStream,
  port: u16,
  peer_addr: SocketAddr,
  compression: bool,
  cancel: CancellationToken,
) -> anyhow::Result<()> {
  debug!("opening QUIC stream for TCP peer {}", peer_addr);
  let (mut quic_send, mut quic_recv) = tokio::select! {
    biased;
    _ = cancel.cancelled() => return Ok(()),
    res = conn.open_bi() => res.map_err(|e| anyhow::anyhow!("failed to open QUIC stream: {}", e))?,
  };
  debug!("opened QUIC stream for TCP peer {}", peer_addr);

  write_stream_header(&mut quic_send, &StreamHeader { port, compression })
    .await
    .map_err(|e| anyhow::anyhow!("failed to write stream header: {}", e))?;

  tokio::select! {
    biased;
    _ = cancel.cancelled() => {
      debug!("TCP connection {} cancelled mid-proxy", peer_addr);
      let _ = quic_send.reset(VarInt::from_u32(0));
      let _ = quic_recv.stop(VarInt::from_u32(0));
    }
    res = proxy_tcp_to_quic(tcp_stream, &mut quic_send, &mut quic_recv, compression) => {
      res?;
    }
  }
  debug!("TCP connection {} closed", peer_addr);
  Ok(())
}

async fn proxy_tcp_to_quic(
  mut tcp: TcpStream,
  quic_send: &mut SendStream,
  quic_recv: &mut RecvStream,
  compression: bool,
) -> anyhow::Result<()> {
  use tokio::io::AsyncWriteExt;
  let (mut tcp_r, mut tcp_w) = tcp.split();

  let upstream = async {
    if compression {
      let mut snappy_send = tokio_snappy::SnappyIO::new(quic_send);
      let result = copy(&mut tcp_r, &mut snappy_send).await;
      let _ = snappy_send.into_inner().finish();
      result
    } else {
      let result = copy(&mut tcp_r, quic_send).await;
      let _ = quic_send.finish();
      result
    }
  };

  let downstream = async {
    let res = if compression {
      let mut snappy_recv = tokio_snappy::SnappyIO::new(quic_recv);
      copy(&mut snappy_recv, &mut tcp_w).await
    } else {
      copy(quic_recv, &mut tcp_w).await
    };
    let _ = tcp_w.shutdown().await;
    res
  };

  trace!("compression {compression}");

  let (up, down) = tokio::join!(upstream, downstream);
  if let Err(e) = up {
    debug!("upstream (TCP->QUIC) {}", e);
  }
  if let Err(e) = down {
    debug!("downstream (QUIC->TCP) error: {}", e);
  }

  Ok(())
}

async fn handle_unregister_service(
  def: ServiceDefinition,
  control_send: &mut SendStream,
  client_identity: &ClientIdentity,
  registry: &PortRegistry,
) -> anyhow::Result<()> {
  debug!("unregisterService: {:?} from {}", def, client_identity);

  let success = remove_port(def.remote_port, registry, client_identity);

  let ack = ServerAckMessage::ServiceUnregistered {
    service_name: def.name,
    success,
    error: (!success).then(|| "port not owned by this connection".to_string()),
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
    info!("cleaned up {} ports for {}", cleaned, client);
  }
}

fn remove_port(port: u16, registry: &PortRegistry, client: &ClientIdentity) -> bool {
  let owns_port = registry.get(&port).map(|entry| client == &entry.client_identity).unwrap_or(false);

  if owns_port {
    if let Some((_, binding)) = registry.remove(&port) {
      binding.cancel.cancel();
      debug!("cleaned up port {} (service: {})", port, binding.service_name);
      return true;
    }
  } else if registry.contains_key(&port) {
    debug!("port {} was taken over, skipping cleanup", port);
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
  // Limits streams the *client* may open; it only ever opens the control stream.
  transport.max_concurrent_bidi_streams(VarInt::from_u32(4));
  transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
  Ok(Arc::new(transport))
}

fn create_udp_socket(bind_addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
  let socket = Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(Protocol::UDP))?;
  socket.set_nonblocking(true)?;

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
  cancel: CancellationToken,
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

  fn get_ports(&self, registry: &PortRegistry) -> Vec<u16> {
    registry.iter().filter_map(|entry| (self == &entry.client_identity).then_some(*entry.key())).collect()
  }
}

impl PartialEq for ClientIdentity {
  fn eq(&self, other: &Self) -> bool {
    self.remote_ip == other.remote_ip && self.identifier == other.identifier
  }
}

impl std::fmt::Display for ClientIdentity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let uuid_str = self.identifier.as_hyphenated();
    write!(f, "{}({:.8})", self.remote_ip, uuid_str)
  }
}

enum ExistingOwner {
  SameConnection,
  StaleConnection,
  Other(String),
}

enum RegisterServiceResult {
  Registered(TcpListener),
  AlreadyRegistered(String),
  UnSolicited(String),
  OsError(String),
}

#[cfg(test)]
mod tests {
  use super::*;

  fn service(port: u16) -> ServiceDefinition {
    ServiceDefinition {
      local_addr: "127.0.0.1:1".into(),
      name: "svc".into(),
      remote_port: port,
      prefer_ipv6: None,
      compression: None,
    }
  }

  fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port()
  }

  /// Bind `def` for `owner` and hold the listener until the binding is cancelled,
  /// like `accept_tcp_connections` does.
  async fn bind_for(def: &ServiceDefinition, owner: &ClientIdentity, registry: &PortRegistry) {
    let RegisterServiceResult::Registered(listener) = register_service(def, owner, registry).await else {
      panic!("initial registration failed");
    };
    let cancel = CancellationToken::new();
    let held = cancel.clone();
    tokio::spawn(async move {
      held.cancelled().await;
      drop(listener);
    });
    let binding = PortBinding { client_identity: owner.clone(), service_name: def.name.clone().into(), cancel };
    registry.insert(def.remote_port, binding);
  }

  /// A DashMap deadlock blocks the thread outright, so `tokio::time::timeout` cannot catch it.
  /// Run on a separate OS thread and bound the wait from outside.
  fn run_with_deadline<F: std::future::Future<Output = ()> + Send + 'static>(fut: F) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
      tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(fut);
      let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(10)).expect("test hung (deadlock?)");
  }

  #[test]
  fn stale_connection_takeover_rebinds_port() {
    run_with_deadline(async {
      let registry: PortRegistry = Arc::new(DashMap::new());
      let def = service(free_tcp_port());
      let addr: SocketAddr = "203.0.113.7:5000".parse().unwrap();
      let stale = ClientIdentity::from(addr);
      bind_for(&def, &stale, &registry).await;

      // Reconnect from the same IP while the old listener is still open: must not deadlock,
      // and must retry the bind until the old listener is released.
      let fresh = ClientIdentity::from(addr);
      let result = register_service(&def, &fresh, &registry).await;
      assert!(matches!(result, RegisterServiceResult::Registered(_)));
      assert!(!registry.contains_key(&def.remote_port), "stale binding should have been removed");
    });
  }

  #[test]
  fn conflicting_registrations_rejected() {
    run_with_deadline(async {
      let registry: PortRegistry = Arc::new(DashMap::new());
      let def = service(free_tcp_port());
      let owner = ClientIdentity::from("203.0.113.7:5000".parse::<SocketAddr>().unwrap());
      bind_for(&def, &owner, &registry).await;

      let result = register_service(&def, &owner, &registry).await;
      assert!(matches!(result, RegisterServiceResult::AlreadyRegistered(_)));

      let other = ClientIdentity::from("198.51.100.9:5000".parse::<SocketAddr>().unwrap());
      let result = register_service(&def, &other, &registry).await;
      assert!(matches!(result, RegisterServiceResult::UnSolicited(_)));
      assert!(registry.contains_key(&def.remote_port), "owner's binding must survive a conflicting request");
    });
  }

  #[test]
  fn token_authorization() {
    let expected = Some("secret".to_string());
    assert!(is_authorized(&None, &None));
    assert!(is_authorized(&None, &Some("anything".into())));
    assert!(is_authorized(&expected, &Some("secret".into())));
    assert!(!is_authorized(&expected, &Some("wrong".into())));
    assert!(!is_authorized(&expected, &None));
  }
}
