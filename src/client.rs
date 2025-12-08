use std::{
  collections::HashSet,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
  pin::pin,
  sync::Arc,
  time::Duration,
};

use compio::io::copy;
use compio_net::{TcpOpts, TcpStream};
use compio_quic::{ClientBuilder, Connection, Endpoint, IdleTimeout, RecvStream, SendStream, VarInt, congestion};
use compio_signal::ctrl_c;
use dashmap::DashMap;
use futures::future::{Either, select};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, info, trace, warn};

use crate::{
  backoff::ExponentialBackoff,
  config::{ClientConfig, Config, ServiceDefinition, VERSION_MAJOR},
  protocol::{ClientControlMessage, ServerControlMessage, read_frame, read_port_header, write_frame},
};

type ServiceRegistry = Arc<DashMap<u16, ServiceDefinition>>;

/// Client entry point
pub async fn run_client(config: ClientConfig, config_path: &str) -> anyhow::Result<()> {
  info!("Client connecting to {}", config.remote_addr);

  let (server_addr, local_bind) = resolve_server_addr(&config)?;
  let endpoint = Endpoint::client(local_bind).await?;
  let transport_config = create_transport_config()?;

  let retry_secs = config.retry_interval.unwrap_or(5);
  let mut backoff = ExponentialBackoff::new(Duration::from_secs(retry_secs), Duration::from_secs(30));

  // Pre-allocate with expected capacity
  let services: ServiceRegistry = Arc::new(DashMap::with_capacity(config.services.len()));
  for svc in config.services {
    services.insert(svc.remote_port, svc);
  }

  let alpn = match config.token {
    Some(token) => format!("quic-proxy-{}-{}", VERSION_MAJOR, token),
    None => format!("quic-proxy-{}", VERSION_MAJOR),
  };

  loop {
    match connect_to_server(&endpoint, server_addr, &alpn, &transport_config).await {
      Ok(conn) => {
        info!("Connected to server");
        backoff.reset();

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

enum LoopControl {
  Shutdown,
  Reconnect,
}

// =============================================================================
// QUIC Connection Setup
// =============================================================================

#[inline]
fn resolve_server_addr(config: &ClientConfig) -> anyhow::Result<(SocketAddr, SocketAddr)> {
  let prefer_v6 = config.prefer_ipv6.unwrap_or(false);
  let addrs: Vec<_> = config.remote_addr.to_socket_addrs()?.collect();

  let chosen = addrs
    .iter()
    .find(|a| if prefer_v6 { a.is_ipv6() } else { a.is_ipv4() })
    .or_else(|| addrs.first())
    .copied()
    .ok_or_else(|| anyhow::anyhow!("No address found for {}", config.remote_addr))?;

  let local_bind = SocketAddr::new(
    if chosen.is_ipv6() { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) },
    0,
  );

  debug!("Resolved server: {}, local bind: {}", chosen, local_bind);
  Ok((chosen, local_bind))
}

fn create_transport_config() -> anyhow::Result<Arc<compio_quic::TransportConfig>> {
  let mut transport = compio_quic::TransportConfig::default();

  transport.keep_alive_interval(Some(Duration::from_secs(5)));
  transport.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(10))?));
  transport.max_concurrent_bidi_streams(VarInt::from_u64(100)?); // Increased from 10
  transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
  // Flow control tuning for better throughput
  transport.send_window(4 * 1024 * 1024); // 4MB send window
  transport.stream_receive_window(VarInt::from_u64(1024 * 1024)?); // 1MB per stream
  transport.receive_window(VarInt::from_u64(8 * 1024 * 1024)?); // 8MB total

  // Initial RTT estimate (can help with initial congestion window)
  transport.initial_rtt(Duration::from_millis(100));

  Ok(Arc::new(transport))
}

async fn connect_to_server(
  endpoint: &Endpoint,
  server_addr: SocketAddr,
  alpn: &str,
  transport_config: &Arc<compio_quic::TransportConfig>,
) -> anyhow::Result<Connection> {
  let mut client_config = ClientBuilder::new_with_no_server_verification().with_alpn_protocols(&[alpn]).build();

  client_config.transport_config(Arc::clone(transport_config));

  endpoint.connect(server_addr, "localhost", Some(client_config))?.await.map_err(Into::into)
}

// =============================================================================
// Connection Handler
// =============================================================================

async fn handle_connection(
  conn: Connection,
  services: &ServiceRegistry,
  config_path: &str,
) -> anyhow::Result<LoopControl> {
  let (mut ctrl_send, mut ctrl_recv) = conn.open_bi()?;
  debug!("Control stream opened");

  register_services(&mut ctrl_send, services).await?;

  let services_ref = Arc::clone(services);
  let accept_task = compio::runtime::spawn(async move { accept_data_streams(conn, services_ref).await });

  let quic_ctrl_task = compio::runtime::spawn(async move {
    receive_control_messages(&mut ctrl_recv).await;
    true
  });

  let (reload_tx, reload_rx) = std::sync::mpsc::channel();
  let _watcher = setup_config_watcher(config_path, reload_tx)?;

  let result =
    event_loop_with_connection_monitor(&mut ctrl_send, services, config_path, reload_rx, quic_ctrl_task).await;

  // Best-effort cleanup - batch unregister messages
  for svc in services.iter() {
    let _ = write_frame(&mut ctrl_send, &ClientControlMessage::UnregisterService(svc.clone())).await;
  }
  let _ = ctrl_send.finish();

  accept_task.cancel().await;

  result
}

async fn event_loop_with_connection_monitor(
  ctrl_send: &mut SendStream,
  services: &ServiceRegistry,
  config_path: &str,
  reload_rx: std::sync::mpsc::Receiver<()>,
  quic_ctrl_task: compio::runtime::JoinHandle<bool>,
) -> anyhow::Result<LoopControl> {
  let mut conn_dead = pin!(quic_ctrl_task);
  let poll_interval = Duration::from_millis(500);

  loop {
    // Drain all pending reload signals (coalesce rapid changes)
    let mut reload_pending = false;
    while reload_rx.try_recv().is_ok() {
      reload_pending = true;
    }

    if reload_pending {
      info!("Config file changed, reloading...");
      if let Err(e) = handle_config_reload(ctrl_send, services, config_path).await {
        warn!("Config reload failed: {}", e);
      }
    }

    let ctrl_c_fut = pin!(ctrl_c());
    let sleep_fut = pin!(compio::time::sleep(poll_interval));
    let conn_check = pin!(async { (&mut conn_dead).await });

    let ctrl_c_or_sleep = pin!(select(ctrl_c_fut, sleep_fut));

    match select(conn_check, ctrl_c_or_sleep).await {
      Either::Left(_) => {
        info!("Connection lost, will reconnect");
        return Ok(LoopControl::Reconnect);
      }
      Either::Right((inner_result, _)) => {
        if let Either::Left(_) = inner_result {
          info!("Ctrl-C received, shutting down");
          return Ok(LoopControl::Shutdown);
        }
        // Timeout - continue loop
      }
    }
  }
}

fn setup_config_watcher(config_path: &str, tx: std::sync::mpsc::Sender<()>) -> anyhow::Result<RecommendedWatcher> {
  let config = notify::Config::default().with_poll_interval(Duration::from_secs(10)).with_compare_contents(true);

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

async fn handle_config_reload(
  ctrl_send: &mut SendStream,
  services: &ServiceRegistry,
  config_path: &str,
) -> anyhow::Result<()> {
  let new_config = Config::load_client(config_path)?;

  // Use iterators directly without intermediate HashSet allocations where possible
  let new_ports: HashSet<u16> = new_config.services.iter().map(|s| s.remote_port).collect();
  let current_ports: HashSet<u16> = services.iter().map(|e| *e.key()).collect();

  // Collect removals and additions
  let to_remove: Vec<u16> = current_ports.difference(&new_ports).copied().collect();

  // Unregister removed services
  for port in to_remove {
    if let Some((_, svc)) = services.remove(&port) {
      info!("Unregistering removed service: {}", svc.name);
      write_frame(ctrl_send, &ClientControlMessage::UnregisterService(svc)).await?;
    }
  }

  // Register new services
  for svc in new_config.services {
    if !current_ports.contains(&svc.remote_port) {
      info!("Registering new service: {}", svc.name);
      write_frame(ctrl_send, &ClientControlMessage::RegisterService(svc.clone())).await?;
      services.insert(svc.remote_port, svc);
    } else if let Some(mut entry) = services.get_mut(&svc.remote_port) {
      // Update existing service if local_addr changed
      if entry.value().local_addr != svc.local_addr {
        info!("Updating service {} local_addr: {} -> {}", svc.name, entry.value().local_addr, svc.local_addr);
        *entry.value_mut() = svc;
      }
    }
  }

  debug!("Updated services list - {:?}", services);
  Ok(())
}

// =============================================================================
// Service Registration
// =============================================================================

async fn register_services(ctrl_send: &mut SendStream, services: &ServiceRegistry) -> anyhow::Result<()> {
  for svc in services.iter() {
    let msg = ClientControlMessage::RegisterService(svc.value().clone());
    if let Err(e) = write_frame(ctrl_send, &msg).await {
      warn!("Failed to register {}: {}", svc.name, e);
    } else {
      debug!("Sent register for {}", svc.name);
    }
  }
  Ok(())
}

async fn receive_control_messages(ctrl_recv: &mut RecvStream) {
  loop {
    match read_frame::<ServerControlMessage>(ctrl_recv).await {
      Ok(msg) => match msg {
        ServerControlMessage::ServiceRegistered { service_name, success, error } => {
          if success {
            info!("Service '{}' registered", service_name);
          } else {
            warn!("Service '{}' registration failed: {:?}", service_name, error);
          }
        }
        ServerControlMessage::ServiceUnregistered { service_name, success, .. } => {
          if success {
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

async fn accept_data_streams(conn: Connection, services: ServiceRegistry) {
  loop {
    match conn.accept_bi().await {
      Ok((mut quic_send, mut quic_recv)) => {
        debug!("Accepted data stream from server");
        let services_clone = Arc::clone(&services);

        compio::runtime::spawn(async move {
          match handle_data_stream(&mut quic_send, &mut quic_recv, &services_clone).await {
            Ok(()) => {}
            Err(e) => {
              debug!("Data stream error: {}", e);
              // Best-effort cleanup
              let code = VarInt::from_u32(1);
              if quic_send.reset(code).is_ok() {
                trace!("Send stream reset");
              }
              if quic_recv.stop(code).is_ok() {
                trace!("Receive stream stopped");
              }
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

async fn handle_data_stream(
  quic_send: &mut SendStream,
  quic_recv: &mut RecvStream,
  services: &ServiceRegistry,
) -> anyhow::Result<()> {
  let port = read_port_header(quic_recv).await?;

  // Direct lookup by port instead of iteration
  let service = services.get(&port).ok_or_else(|| anyhow::anyhow!("No service configured for port {}", port))?;

  let local_addr = service.local_addr.clone();
  let service_name = service.name.clone();
  drop(service); // Release lock before async operations

  debug!("Proxying to local service: {} ({})", service_name, local_addr);

  // TCP connection options
  let opts = TcpOpts::new()
    .nodelay(true)
    .keepalive(true)
    .write_timeout(Duration::from_secs(5))
    .read_timeout(Duration::from_secs(5));

  let local_tcp = TcpStream::connect_with_options(&local_addr, opts).await?;
  debug!("Connected to local service: {}", local_addr);

  proxy_quic_to_tcp(local_tcp, quic_send, quic_recv).await;
  Ok(())
}

async fn proxy_quic_to_tcp(tcp: TcpStream, quic_send: &mut SendStream, quic_recv: &mut RecvStream) {
  let (mut tcp_r, mut tcp_w) = tcp.split();

  let upstream = async {
    let result = copy(&mut tcp_r, quic_send).await;
    let _ = quic_send.finish();
    result
  };

  let downstream = async {
    let res = copy(quic_recv, &mut tcp_w).await;
    trace!("Server side closed (external client disconnected)");
    res
  };

  let upstream = pin!(upstream);
  let downstream = pin!(downstream);

  match select(upstream, downstream).await {
    Either::Left((res, _)) => {
      if let Err(e) = res {
        debug!("Upstream (Local->QUIC) error: {}", e);
      } else {
        debug!("Upstream completed, local service closed");
      }
    }
    Either::Right((res, _)) => {
      if let Err(e) = res {
        debug!("Downstream (QUIC->Local) error: {}", e);
      } else {
        debug!("Downstream completed, external client closed");
      }
    }
  }
}
