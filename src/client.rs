use std::{
  collections::HashSet,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
  pin::pin,
  sync::Arc,
  time::Duration,
};

use compio::io::copy;
use compio_net::{TcpOpts, TcpStream};
use compio_quic::{
  ClientBuilder, Connection, Endpoint, IdleTimeout, RecvStream, SendStream, VarInt,
};
use compio_signal::ctrl_c;
use dashmap::DashMap;
use futures::future::{Either, select};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, info, trace, warn};

use crate::{
  backoff::ExponentialBackoff,
  config::{ClientConfig, Config, ServiceDefinition, VERSION_MAJOR},
  protocol::{
    ClientControlMessage, ServerControlMessage, read_frame, read_port_header, write_frame,
  },
};

type ServiceRegistry = Arc<DashMap<u16, ServiceDefinition>>;

/// Client entry point
pub async fn run_client(config: ClientConfig, config_path: &str) -> anyhow::Result<()> {
  info!("Client connecting to {}", config.remote_addr);

  // Resolve server address
  let (server_addr, local_bind) = resolve_server_addr(&config)?;

  // Create QUIC endpoint
  let endpoint = Endpoint::client(local_bind).await?;

  // Transport config with keep-alive
  let transport_config = create_transport_config()?;

  // Reconnect backoff
  let retry_secs = config.retry_interval.unwrap_or(5);
  let mut backoff =
    ExponentialBackoff::new(Duration::from_secs(retry_secs), Duration::from_secs(30));

  let services: ServiceRegistry = Arc::new(DashMap::new());
  for svc in &config.services {
    services.insert(svc.remote_port, svc.clone());
  }

  let alpn = if let Some(token) = config.token {
    format!("quic-proxy-{}-{}", VERSION_MAJOR, token)
  } else {
    format!("quic-proxy-{}", VERSION_MAJOR)
  };
  // Main reconnection loop
  loop {
    match connect_to_server(&endpoint, server_addr, &alpn, &transport_config).await {
      Ok(conn) => {
        info!("Connected to server");
        backoff.reset();

        // Handle connection until it ends
        match handle_connection(conn, &services, config_path).await {
          Ok(LoopControl::Shutdown) => {
            info!("Clean shutdown requested");
            break;
          }
          Ok(LoopControl::Reconnect) => {
            info!("Reconnecting...");
          }
          Err(e) => {
            warn!("Connection error: {}", e);
          }
        }
      }
      Err(e) => {
        let delay = backoff.next_delay();
        warn!("Connection failed: {}, retrying in {}s", e, delay.as_secs());
        compio::time::sleep(delay).await;
      }
    }
  }

  Ok(())
}

/// Control flow for main loop
enum LoopControl {
  Shutdown,
  Reconnect,
}

// =============================================================================
// QUIC Connection Setup
// =============================================================================

/// Resolve server address, preferring IPv6 if configured
fn resolve_server_addr(
  config: &ClientConfig,
) -> anyhow::Result<(SocketAddr, SocketAddr)> {
  let prefer_v6 = config.prefer_ipv6.unwrap_or(false);
  let addrs: Vec<_> = config.remote_addr.to_socket_addrs()?.collect();

  let chosen = addrs
    .iter()
    .find(|a| if prefer_v6 { a.is_ipv6() } else { a.is_ipv4() })
    .or_else(|| addrs.first())
    .copied()
    .ok_or_else(|| anyhow::anyhow!("No address found for {}", config.remote_addr))?;

  let local_bind = SocketAddr::new(
    if chosen.is_ipv6() {
      IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
      IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    },
    0,
  );

  debug!("Resolved server: {}, local bind: {}", chosen, local_bind);
  Ok((chosen, local_bind))
}

/// Create transport config for client
fn create_transport_config() -> anyhow::Result<Arc<compio_quic::TransportConfig>> {
  let mut config = compio_quic::TransportConfig::default();

  config.keep_alive_interval(Some(Duration::from_secs(5)));
  config.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(10))?));
  config.max_concurrent_bidi_streams(VarInt::from_u64(10)?);

  Ok(Arc::new(config))
}

/// Establish QUIC connection to server
async fn connect_to_server(
  endpoint: &Endpoint,
  server_addr: SocketAddr,
  alpn: &str,
  transport_config: &Arc<compio_quic::TransportConfig>,
) -> anyhow::Result<Connection> {
  let mut client_config =
    ClientBuilder::new_with_no_server_verification().with_alpn_protocols(&[alpn]).build();

  client_config.transport_config(transport_config.clone());

  let conn = endpoint.connect(server_addr, "localhost", Some(client_config))?.await?;

  Ok(conn)
}

// =============================================================================
// Connection Handler
// =============================================================================

/// Handle an established connection: control stream, data streams, hot reload
async fn handle_connection(
  conn: Connection,
  services: &ServiceRegistry,
  config_path: &str,
) -> anyhow::Result<LoopControl> {
  // Open control stream (first bidirectional stream)
  let (mut ctrl_send, mut ctrl_recv) = conn.open_bi()?;
  debug!("Control stream opened");

  // Register all current services
  register_services(&mut ctrl_send, services).await?;

  // Spawn task to accept data streams from server

  let services_ref = Arc::clone(services);

  let accept_task =
    compio::runtime::spawn(async move { accept_data_streams(conn, services_ref).await });

  // Spawn task to receive control messages (acks)
  // Returns when control stream closes (connection lost)

  let quic_ctrl_task = compio::runtime::spawn(async move {
    receive_control_messages(&mut ctrl_recv).await;
    // Signal that connection is dead
    true
  });

  // Set up config file watcher for hot reload
  let (reload_tx, reload_rx) = std::sync::mpsc::channel();
  let config_path_owned = config_path.to_string();

  let _watcher = setup_config_watcher(&config_path_owned, reload_tx)?;

  // Main event loop - returns Shutdown on ctrl-c, Reconnect on connection loss
  let result = event_loop_with_connection_monitor(
    &mut ctrl_send,
    services,
    config_path,
    reload_rx,
    quic_ctrl_task,
  )
  .await;

  // Cleanup: unregister all services (best effort)
  for svc in services.iter() {
    let _ =
      write_frame(&mut ctrl_send, &ClientControlMessage::UnregisterService(svc.clone()))
        .await;
  }
  let _ = ctrl_send.finish();

  // Cancel background accept task
  accept_task.cancel().await;

  result
}

/// Main event loop: handle ctrl-c, config reload, and connection health
async fn event_loop_with_connection_monitor(
  ctrl_send: &mut SendStream,
  services: &ServiceRegistry,
  config_path: &str,
  reload_rx: std::sync::mpsc::Receiver<()>,
  quic_ctrl_task: compio::runtime::JoinHandle<bool>,
) -> anyhow::Result<LoopControl> {
  // Convert JoinHandle to a future we can poll
  let mut conn_dead = pin!(quic_ctrl_task);

  loop {
    // Check for config reload (non-blocking)
    if reload_rx.try_recv().is_ok() {
      info!("Config file changed, reloading...");

      if let Err(e) = handle_config_reload(ctrl_send, services, config_path).await {
        warn!("Config reload failed: {}", e);
      }
    }

    // Race between: ctrl-c, timeout, connection death
    let ctrl_c_fut = pin!(ctrl_c());
    let sleep_fut = pin!(compio::time::sleep(Duration::from_millis(500)));

    // Check if connection monitor task completed (connection dead)
    let conn_check = async { (&mut conn_dead).await };
    let conn_check = pin!(conn_check);

    // Three-way race using nested select
    let ctrl_c_or_sleep = select(ctrl_c_fut, sleep_fut);
    let ctrl_c_or_sleep = pin!(ctrl_c_or_sleep);

    match select(conn_check, ctrl_c_or_sleep).await {
      Either::Left(_) => {
        // Connection monitor returned - connection is dead
        info!("Connection lost, will reconnect");
        return Ok(LoopControl::Reconnect);
      }
      Either::Right((inner_result, _)) => {
        match inner_result {
          Either::Left(_) => {
            // Ctrl-C
            info!("Ctrl-C received, shutting down");
            return Ok(LoopControl::Shutdown);
          }
          Either::Right(_) => {
            // Timeout - continue loop
          }
        }
      }
    }
  }
}

/// Set up file watcher for hot reload
fn setup_config_watcher(
  config_path: &str,
  tx: std::sync::mpsc::Sender<()>,
) -> anyhow::Result<notify::RecommendedWatcher> {
  let config = notify::Config::default()
    .with_poll_interval(Duration::from_secs(10))
    .with_compare_contents(true);
  let mut watcher = RecommendedWatcher::new(
    move |res: Result<Event, _>| {
      if let Ok(event) = res
        && event.kind.is_modify()
      {
        let _ = tx.send(());
      }
    },
    config,
  )?;

  watcher.watch(std::path::Path::new(config_path), RecursiveMode::NonRecursive)?;
  debug!("Watching config file: {}", config_path);

  Ok(watcher)
}

/// Handle config reload: compute diff, register new, unregister removed
async fn handle_config_reload(
  ctrl_send: &mut SendStream,
  services: &ServiceRegistry,
  config_path: &str,
) -> anyhow::Result<()> {
  let new_config = Config::load_client(config_path)?;

  // Build set of new ports for comparison
  let new_ports: HashSet<u16> =
    new_config.services.iter().map(|s| s.remote_port).collect();
  let current_ports: HashSet<u16> = services.iter().map(|e| *e.key()).collect();

  // Find services to remove (in current but not in new)
  let to_remove: Vec<u16> = current_ports.difference(&new_ports).copied().collect();

  // Find services to add (in new but not in current)
  let to_add: Vec<ServiceDefinition> = new_config
    .services
    .iter()
    .filter(|s| !current_ports.contains(&s.remote_port))
    .cloned()
    .collect();

  // Unregister removed services
  for port in to_remove {
    if let Some((_, svc)) = services.remove(&port) {
      info!("Unregistering removed service: {}", svc.name);
      write_frame(ctrl_send, &ClientControlMessage::UnregisterService(svc.clone()))
        .await?;
    }
  }

  // Register new services and add to registry
  for svc in to_add {
    info!("Registering new service: {}", svc.name);
    write_frame(ctrl_send, &ClientControlMessage::RegisterService(svc.clone())).await?;
    services.insert(svc.remote_port, svc);
  }

  // Update existing services (in case local_addr changed)
  for new_svc in &new_config.services {
    if let Some(mut entry) = services.get_mut(&new_svc.remote_port)
      && entry.value().local_addr != new_svc.local_addr
    {
      info!(
        "Updating service {} local_addr: {} -> {}",
        new_svc.name,
        entry.value().local_addr,
        new_svc.local_addr
      );
      *entry.value_mut() = new_svc.clone();
    }
  }
  debug!("updated services list - {:?}", services);
  Ok(())
}

// =============================================================================
// Service Registration
// =============================================================================

/// Register all services on the control stream
async fn register_services(
  ctrl_send: &mut SendStream,
  services: &ServiceRegistry,
) -> anyhow::Result<()> {
  for svc in services.iter() {
    let msg = ClientControlMessage::RegisterService(svc.clone());
    if let Err(e) = write_frame(ctrl_send, &msg).await {
      warn!("Failed to register {}: {}", svc.name, e);
    } else {
      debug!("Sent register for {}", svc.name);
    }
  }
  Ok(())
}

/// Receive and log control messages from server
async fn receive_control_messages(ctrl_recv: &mut RecvStream) {
  loop {
    match read_frame::<ServerControlMessage>(ctrl_recv).await {
      Ok(msg) => match &msg {
        ServerControlMessage::ServiceRegistered { service_name, success, error } => {
          if *success {
            info!("Service '{}' registered", service_name);
          } else {
            warn!("Service '{}' registration failed: {:?}", service_name, error);
          }
        }
        ServerControlMessage::ServiceUnregistered { service_name, success, .. } => {
          if *success {
            info!("Service '{}' unregistered", service_name);
          }
        }
      },
      Err(e) => {
        debug!("Control receive ended: {}", e);
        break;
      }
    }
  }
}

// =============================================================================
// Data Stream Handling
// =============================================================================

/// Accept incoming data streams from server and proxy to local services
async fn accept_data_streams(conn: Connection, services: ServiceRegistry) {
  loop {
    match conn.accept_bi().await {
      Ok((mut quic_send, mut quic_recv)) => {
        debug!("Accepted data stream from server");
        let services_clone = services.clone();

        compio::runtime::spawn(async move {
          if let Err(e) =
            handle_data_stream(&mut quic_send, &mut quic_recv, &services_clone).await
          {
            debug!("Data stream error: {}", e);
            if let Err(e) = quic_send.reset(VarInt::from_u32(1)) {
              warn!("Send Stream closed error {}", e);
            } else {
              info!("Send Stream closed");
            }

            if let Err(e) = quic_recv.stop(VarInt::from_u32(1)) {
              warn!("Received stream closed error {}", e);
            } else {
              info!("Received stream closed");
            }
          }
        })
        .detach();
      }
      Err(e) => {
        debug!("Accept stream failed: {}", e);
        break;
      }
    }
  }
}

/// Handle a single data stream: read port header, connect to local service, proxy
async fn handle_data_stream(
  quic_send: &mut SendStream,
  quic_recv: &mut RecvStream,
  services: &ServiceRegistry,
) -> anyhow::Result<()> {
  // Read port header to identify target service
  let port = read_port_header(quic_recv).await?;

  // Find matching service
  let service = services.iter().find(|s| s.remote_port == port).ok_or_else(|| {
    anyhow::anyhow!(
      "No service configured for port {} from services list {:?}",
      port,
      services
    )
  })?;

  debug!("Proxying to local service: {} ({})", service.name, service.local_addr);

  // Connect to local service
  let opts =
    TcpOpts::new().nodelay(true).keepalive(true).write_timeout(Duration::from_secs(2));
  let local_tcp = TcpStream::connect_with_options(&service.local_addr, opts).await?;

  debug!("Connected to local service: {}", service.local_addr);

  // Bidirectional proxy
  proxy_quic_to_tcp(local_tcp, quic_send, quic_recv).await;
  Ok(())
}

/// Copy data bidirectionally between TCP and QUIC streams
/// When either direction ends (stream closed or error), signal the other side and finish.
async fn proxy_quic_to_tcp(
  tcp: TcpStream,
  quic_send: &mut SendStream,
  quic_recv: &mut RecvStream,
) {
  let (mut tcp_r, mut tcp_w) = tcp.split();

  // Local TCP -> QUIC (upstream to server)
  let upstream = async {
    let result = copy(&mut tcp_r, quic_send).await;
    // Local service closed their send side, signal to server
    let _ = quic_send.finish();
    result
  };

  // QUIC -> Local TCP (downstream from server)
  let downstream = async {
    let res = copy(quic_recv, &mut tcp_w).await;
    // When this returns, server closed their send side (external client disconnected)
    // TCP write half will be dropped, signaling EOF to local service
    trace!("send side (external client disconnected)");
    res
  };

  let upstream = pin!(upstream);
  let downstream = pin!(downstream);

  // Race both directions - when one finishes, the other will be dropped
  match select(upstream, downstream).await {
    Either::Left((res, _other)) => {
      // Upstream finished first (local service closed)
      if let Err(e) = res {
        debug!("Upstream (Local->QUIC) error: {}", e);
      } else {
        debug!("Upstream (Local->QUIC) completed, local service closed");
      }
    }
    Either::Right((res, _other)) => {
      // Downstream finished first (server/external client closed)
      if let Err(e) = res {
        debug!("Downstream (QUIC->Local) error: {}", e);
      } else {
        debug!("Downstream (QUIC->Local) completed, external client closed");
      }
    }
  }
}
