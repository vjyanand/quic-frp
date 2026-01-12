use std::{collections::HashSet, net::ToSocketAddrs, sync::Arc, time::Duration};

use dashmap::DashMap;
use futures::future::{Either, select};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use smux::{Session, Stream};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
  io::{AsyncWriteExt, WriteHalf, copy, split},
  task::JoinHandle,
};
use tokio_kcp::{KcpConfig, KcpNoDelayConfig, KcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::{
  backoff::ExponentialBackoff,
  config::{Config, ServiceDefinition},
  protocol::{ClientControlMessage, ServerAckMessage, read_frame, read_port_header, write_frame},
};

type ServiceRegistry = Arc<DashMap<u16, ServiceDefinition>>;

/// Client entry point
pub async fn run_client(config: crate::config::ClientConfig, config_path: &str) -> anyhow::Result<()> {
  info!("Client connecting to {}", config.remote_addr);

  let retry_secs = config.retry_interval.unwrap_or(5);
  let mut backoff = ExponentialBackoff::new(Duration::from_secs(retry_secs), Duration::from_secs(30));

  // Pre-allocate with expected capacity
  let services = DashMap::with_capacity(config.services.len());
  for svc in config.services {
    services.insert(svc.remote_port, svc);
  }
  let services = Arc::new(services);

  let shutdown = CancellationToken::new();
  tokio::spawn({
    let shutdown = shutdown.clone();
    async move {
      tokio::signal::ctrl_c().await.ok();
      info!("Ctrl-C received");
      shutdown.cancel();
    }
  });

  loop {
    match connect_to_server(&config.remote_addr, config.prefer_ipv6.unwrap_or_default()).await {
      Ok(conn) => {
        info!("Connected to server");
        backoff.reset();

        match handle_connection(conn, &services, config_path, shutdown.clone()).await {
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
        tokio::select! {
          _ = tokio::time::sleep(delay) => {
            warn!("Connection failed: {}, retrying in {}s", e, delay.as_secs());
          }
          _ = shutdown.cancelled() => {
            info!("Shutdown during retry backoff");
            break;
          }
        }
      }
    }
  }

  Ok(())
}

enum LoopControl {
  Shutdown,
  Reconnect,
}

async fn connect_to_server(remote_addr: &str, prefer_v6: bool) -> anyhow::Result<KcpStream> {
  let mut kcp_config = KcpConfig::default();
  kcp_config.nodelay = KcpNoDelayConfig::normal();
  let addrs: Vec<_> = remote_addr.to_socket_addrs()?.collect();
  let chosen = addrs
    .iter()
    .find(|a| if prefer_v6 { a.is_ipv6() } else { a.is_ipv4() })
    .or_else(|| addrs.first())
    .copied()
    .ok_or_else(|| anyhow::anyhow!("No address found for {}", remote_addr))?;
  let kcp_stream = KcpStream::connect(&kcp_config, chosen).await?;
  debug!("Connected to {}", chosen);
  Ok(kcp_stream)
}

async fn handle_connection(
  kcp_stream: KcpStream,
  services: &ServiceRegistry,
  config_path: &str,
  shutdown_token: CancellationToken,
) -> anyhow::Result<LoopControl> {
  let smux_session = Session::client(kcp_stream, smux::Config::default()).await?;
  let (mut smux_stream_r, mut smux_stream_w) = split(smux_session.open_stream().await?);

  debug!("Control stream opened");

  register_services(&mut smux_stream_w, services).await?;

  let services_ref = Arc::clone(services);
  let accept_task = tokio::spawn(async move { accept_data_streams(smux_session, services_ref).await });

  let quic_ctrl_task = tokio::spawn({
    async move {
      receive_control_messages(&mut smux_stream_r).await;
      true
    }
  });

  let (reload_tx, reload_rx) = std::sync::mpsc::channel();
  let _watcher = setup_config_watcher(config_path, reload_tx)?;

  let result = event_loop_with_connection_monitor(
    &mut smux_stream_w,
    services,
    config_path,
    reload_rx,
    quic_ctrl_task,
    shutdown_token,
  )
  .await;

  debug!("Closing conn");

  // Best-effort cleanup - batch unregister messages
  for svc in services.iter() {
    let svc = svc.clone();
    let _ = write_frame(&mut smux_stream_w, &ClientControlMessage::DeregisterService(svc)).await;
  }
  debug!("Closing conn");
  let _ = smux_stream_w.shutdown().await;
  accept_task.abort();

  result
}

async fn event_loop_with_connection_monitor(
  smux_stream_w: &mut WriteHalf<Stream>,
  services: &ServiceRegistry,
  config_path: &str,
  reload_rx: std::sync::mpsc::Receiver<()>,
  quic_ctrl_task: JoinHandle<bool>,
  shutdown_token: CancellationToken,
) -> anyhow::Result<LoopControl> {
  let mut conn_dead = std::pin::pin!(quic_ctrl_task);

  loop {
    // Drain all pending reload signals (coalesce rapid changes)
    let mut reload_pending = false;
    while reload_rx.try_recv().is_ok() {
      reload_pending = true;
    }

    if reload_pending {
      info!("Config file changed, reloading...");

      if let Err(e) = handle_config_reload(smux_stream_w, services, config_path).await {
        warn!("Config reload failed: {}", e);
      }
    }

    tokio::select! {
      _ = &mut conn_dead => {
        info!("Connection lost, will reconnect");
        return Ok(LoopControl::Reconnect);
      }
      _ = shutdown_token.cancelled() =>{
        info!("Shutdown requested");
        return Ok(LoopControl::Shutdown);
      }
      _ = tokio::time::sleep(Duration::from_millis(500))=>{}
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
  smux_stream_w: &mut WriteHalf<Stream>,
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
    if let Some(svc) = services.remove(&port) {
      info!("Unregistering removed service: {}", svc.1.name);
      write_frame(smux_stream_w, &ClientControlMessage::DeregisterService(svc.1)).await?;
    }
  }

  // Register new services
  for svc in new_config.services {
    if !current_ports.contains(&svc.remote_port) {
      info!("Registering new service: {}", svc.name);
      write_frame(smux_stream_w, &ClientControlMessage::RegisterService(svc.clone())).await?;
      services.insert(svc.remote_port, svc);
    } else if let Some(mut entry) = services.get_mut(&svc.remote_port) {
      // Update existing service if local_addr changed
      if entry.local_addr != svc.local_addr {
        info!("Updating service {} local_addr: {} -> {}", svc.name, entry.local_addr, svc.local_addr);
        *entry = svc;
      }
    }
  }

  debug!("Updated services list - {:?}", services);
  Ok(())
}

async fn register_services(smux_stream_w: &mut WriteHalf<Stream>, services: &ServiceRegistry) -> anyhow::Result<()> {
  for svc in services.iter() {
    let msg = ClientControlMessage::RegisterService(svc.clone());
    if let Err(e) = write_frame(smux_stream_w, &msg).await {
      warn!("Failed to register {}: {}", svc.name, e);
    } else {
      debug!("Sent register for {}", svc.name);
    }
  }
  Ok(())
}

async fn receive_control_messages(arc_smux_stream: &mut tokio::io::ReadHalf<smux::Stream>) {
  loop {
    match read_frame::<ServerAckMessage, _>(arc_smux_stream).await {
      Ok(msg) => match msg {
        ServerAckMessage::ServiceRegistered { service_name, success, error } => {
          if success {
            info!("Service '{}' registered", service_name);
          } else {
            warn!("Service '{}' registration failed: {:?}", service_name, error);
          }
        }
        ServerAckMessage::ServiceUnregistered { service_name, success, .. } => {
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

async fn accept_data_streams(smux_session: Session, services: ServiceRegistry) {
  loop {
    match smux_session.accept_stream().await {
      Ok(mut smux_stream) => {
        debug!("Accepted data stream from server");
        let services_clone = Arc::clone(&services);

        tokio::spawn(async move {
          match handle_data_stream(&mut smux_stream, &services_clone).await {
            Ok(()) => {}
            Err(e) => {
              debug!("Data stream error: {}", e);
              // Best-effort cleanup
              if smux_stream.close().await.is_ok() {
                trace!("Send stream reset");
              }
            }
          }
        });
      }
      Err(e) => {
        debug!("Accept stream failed: {}", e);
        break;
      }
    }
  }
}

async fn handle_data_stream(smux_stream: &mut Stream, services: &ServiceRegistry) -> anyhow::Result<()> {
  let port = read_port_header(smux_stream).await?;

  // Direct lookup by port instead of iteration
  let service = services.get(&port).ok_or_else(|| anyhow::anyhow!("No service configured for port {}", port))?;

  let local_addr = service.local_addr.clone();
  let service_name = service.name.clone();
  drop(service); // Release lock before async operations

  debug!("Proxying to local service: {} ({})", service_name, local_addr);

  let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
  socket.set_keepalive(true)?;
  socket.set_tcp_nodelay(true)?;
  let keepalive = socket2::TcpKeepalive::new()
    .with_interval(Duration::from_secs(10))
    .with_retries(5)
    .with_time(Duration::from_secs(60));
  socket.set_tcp_keepalive(&keepalive)?;
  let sock_addr = socket2::SockAddr::from(local_addr.to_socket_addrs()?.next().unwrap());
  socket.connect(&sock_addr)?;
  let std_tcp: std::net::TcpStream = socket.into();
  let _ = std_tcp.set_nonblocking(true);
  let local_tcp: tokio::net::TcpStream = tokio::net::TcpStream::from_std(std_tcp)?;
  debug!("Connected to local service: {}", local_addr);

  proxy_quic_to_tcp(local_tcp, smux_stream).await;
  Ok(())
}

async fn proxy_quic_to_tcp(mut tcp: tokio::net::TcpStream, smux_stream: &mut Stream) {
  let (mut tcp_r, mut tcp_w) = tcp.split();
  let (mut smux_stream_r, mut smux_stream_s) = split(smux_stream);
  let upstream = async {
    let result = copy(&mut tcp_r, &mut smux_stream_s).await;
    let _ = smux_stream_s.shutdown().await;
    result
  };

  let downstream = async {
    let res = copy(&mut smux_stream_r, &mut tcp_w).await;
    trace!("Server side closed (external client disconnected)");
    res
  };

  let upstream = std::pin::pin!(upstream);
  let downstream = std::pin::pin!(downstream);

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
