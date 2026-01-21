use std::{
  collections::HashSet,
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
  pin::pin,
  sync::Arc,
  time::Duration,
};

use dashmap::DashMap;
use futures::future::{Either, select};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use quinn::{
  Connection, Endpoint, IdleTimeout, RecvStream, SendStream, TransportConfig, VarInt, congestion,
  crypto::rustls::QuicClientConfig,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{io::copy, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::{
  backoff::ExponentialBackoff,
  config::{Config, ServiceDefinition},
  protocol::{ClientControlMessage, ServerAckMessage, read_frame, read_port_header, write_frame},
  tls::{self, TlsClientCertConfig},
};

type ServiceRegistry = Arc<DashMap<u16, ServiceDefinition>>;

/// Client entry point
pub async fn run_client(config: crate::config::ClientConfig, config_path: &str) -> anyhow::Result<()> {
  info!("client connecting to {}", config.remote_addr);

  let retry_secs = config.retry_interval.unwrap_or(5);
  let mut backoff = ExponentialBackoff::new(Duration::from_secs(retry_secs), Duration::from_secs(30));

  let alpn = tls::alpn(&config.token);
  let (server_addr, local_bind) = resolve_server_addr(&config)?;

  // Pre-allocate with expected capacity
  let services = DashMap::with_capacity(config.services.len());
  for svc in config.services {
    services.insert(svc.remote_port, svc);
  }
  let services = Arc::new(services);
  let tls_config = config.tls;

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
    match connect_to_server(server_addr, local_bind, &alpn, tls_config.clone()).await {
      Ok(conn) => {
        info!("connected to server");
        backoff.reset();

        match handle_connection(conn, &services, config_path, shutdown.clone()).await {
          Ok(LoopControl::Shutdown) => {
            info!("clean shutdown requested");
            break;
          }
          Ok(LoopControl::Reconnect) => {
            info!("reconnecting...");
          }
          Err(e) => {
            warn!("connection error: {}", e);
          }
        }
      }
      Err(e) => {
        let delay = backoff.next_delay();
        tokio::select! {
          _ = tokio::time::sleep(delay) => {
            warn!("connection failed: {}, retrying in {}s", e, delay.as_secs());
          }
          _ = shutdown.cancelled() => {
            info!("shutdown during retry backoff");
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

// =============================================================================
// QUIC Connection Setup
// =============================================================================

#[inline]
fn resolve_server_addr(config: &crate::config::ClientConfig) -> anyhow::Result<(SocketAddr, SocketAddr)> {
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

  debug!("resolved server: {}, local bind: {}", chosen, local_bind);
  Ok((chosen, local_bind))
}

fn create_transport_config() -> anyhow::Result<TransportConfig> {
  let mut transport = TransportConfig::default();

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

  Ok(transport)
}

async fn connect_to_server(
  server_addr: SocketAddr,
  local_bind: SocketAddr,
  alpn: &str,
  tls: TlsClientCertConfig,
) -> anyhow::Result<Connection> {
  let mut client_crypto = tls.into_client_config()?;
  client_crypto.alpn_protocols = vec![alpn.into()];

  let quic_config = QuicClientConfig::try_from(client_crypto)?;
  let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));

  let transport_config = Arc::new(create_transport_config()?);
  client_config.transport_config(transport_config);

  let endpoint = Endpoint::client(local_bind)?;
  debug!("end point created");

  let connection = endpoint.connect_with(client_config, server_addr, "localhost")?.await?;
  Ok(connection)
}

async fn handle_connection(
  conn: Connection,
  services: &ServiceRegistry,
  config_path: &str,
  shutdown_token: CancellationToken,
) -> anyhow::Result<LoopControl> {
  let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?;
  debug!("control stream opened");

  register_services(&mut ctrl_send, services).await?;

  let services_ref = Arc::clone(services);
  let accept_task = tokio::spawn(async move { accept_data_streams(conn, services_ref).await });

  let quic_ctrl_task = tokio::spawn(async move {
    receive_control_messages(&mut ctrl_recv).await;
    true
  });

  let (reload_tx, reload_rx) = std::sync::mpsc::channel();
  let _watcher = setup_config_watcher(config_path, reload_tx)?;

  let result = event_loop_with_connection_monitor(
    &mut ctrl_send,
    services,
    config_path,
    reload_rx,
    quic_ctrl_task,
    shutdown_token,
  )
  .await;

  // Best-effort cleanup - batch unregister messages
  for svc in services.iter() {
    let svc = svc.clone();
    let _ = write_frame(&mut ctrl_send, &ClientControlMessage::DeregisterService(svc)).await;
  }
  let _ = ctrl_send.finish();

  accept_task.abort();

  result
}

async fn event_loop_with_connection_monitor(
  ctrl_send: &mut SendStream,
  services: &ServiceRegistry,
  config_path: &str,
  reload_rx: std::sync::mpsc::Receiver<()>,
  quic_ctrl_task: JoinHandle<bool>,
  shutdown_token: CancellationToken,
) -> anyhow::Result<LoopControl> {
  let mut conn_dead = pin!(quic_ctrl_task);

  loop {
    // Drain all pending reload signals (coalesce rapid changes)
    let mut reload_pending = false;
    while reload_rx.try_recv().is_ok() {
      reload_pending = true;
    }

    if reload_pending {
      info!("config file changed, reloading...");
      if let Err(e) = handle_config_reload(ctrl_send, services, config_path).await {
        warn!("config reload failed: {}", e);
      }
    }

    tokio::select! {
      _ = &mut conn_dead => {
        info!("connection lost, will reconnect");
        return Ok(LoopControl::Reconnect);
      }
      _ = shutdown_token.cancelled() =>{
        info!("shutdown requested");
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
  debug!("watching config file: {}", config_path);

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
    if let Some(svc) = services.remove(&port) {
      info!("unregistering removed service: {}", svc.1.name);
      write_frame(ctrl_send, &ClientControlMessage::DeregisterService(svc.1)).await?;
    }
  }

  // Register new services
  for svc in new_config.services {
    if !current_ports.contains(&svc.remote_port) {
      info!("registering new service: {}", svc.name);
      write_frame(ctrl_send, &ClientControlMessage::RegisterService(svc.clone())).await?;
      services.insert(svc.remote_port, svc);
    } else if let Some(mut entry) = services.get_mut(&svc.remote_port) {
      // Update existing service if local_addr changed
      if entry.local_addr != svc.local_addr {
        info!("updating service {} local_addr: {} -> {}", svc.name, entry.local_addr, svc.local_addr);
        *entry = svc;
      }
    }
  }

  debug!("updated services list - {:?}", services);
  Ok(())
}

async fn register_services(ctrl_send: &mut SendStream, services: &ServiceRegistry) -> anyhow::Result<()> {
  for svc in services.iter() {
    let msg = ClientControlMessage::RegisterService(svc.clone());
    if let Err(e) = write_frame(ctrl_send, &msg).await {
      warn!("failed to register {}: {}", svc.name, e);
    } else {
      debug!("sent register for {}", svc.name);
    }
  }
  Ok(())
}

async fn receive_control_messages(ctrl_recv: &mut RecvStream) {
  loop {
    match read_frame::<ServerAckMessage, _>(ctrl_recv).await {
      Ok(msg) => match msg {
        ServerAckMessage::ServiceRegistered { service_name, success, error } => {
          if success {
            info!("service '{}' registered", service_name);
          } else {
            warn!("service '{}' registration failed: {:?}", service_name, error);
          }
        }
        ServerAckMessage::ServiceUnregistered { service_name, success, .. } => {
          if success {
            info!("service '{}' unregistered", service_name);
          }
        }
      },
      Err(e) => {
        debug!("control receive ended: {}", e);
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
        debug!("accepted data stream from server");
        let services_clone = Arc::clone(&services);

        tokio::spawn(async move {
          match handle_data_stream(&mut quic_send, &mut quic_recv, &services_clone).await {
            Ok(()) => {}
            Err(e) => {
              debug!("data stream error: {}", e);
              // Best-effort cleanup
              let code = VarInt::from_u32(1);
              if quic_send.reset(code).is_ok() {
                trace!("send stream reset");
              }
              if quic_recv.stop(code).is_ok() {
                trace!("receive stream stopped");
              }
            }
          }
        });
      }
      Err(e) => {
        debug!("accept stream failed: {}", e);
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
  let service = services.get(&port).ok_or_else(|| anyhow::anyhow!("no service configured for port {}", port))?;

  let local_addr = service.local_addr.clone();
  let service_name = service.name.clone();
  drop(service); // Release lock before async operations

  debug!("proxying to local service: {} ({})", service_name, local_addr);

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
  debug!("connected to local service: {}", local_addr);

  proxy_quic_to_tcp(local_tcp, quic_send, quic_recv).await;
  Ok(())
}

async fn proxy_quic_to_tcp(mut tcp: tokio::net::TcpStream, quic_send: &mut SendStream, quic_recv: &mut RecvStream) {
  let (mut tcp_r, mut tcp_w) = tcp.split();

  let upstream = async {
    let result = copy(&mut tcp_r, quic_send).await;
    let _ = quic_send.finish();
    result
  };

  let downstream = async {
    let res = copy(quic_recv, &mut tcp_w).await;
    trace!("server side closed (external client disconnected)");
    res
  };

  let upstream = pin!(upstream);
  let downstream = pin!(downstream);

  match select(upstream, downstream).await {
    Either::Left((res, _)) => {
      if let Err(e) = res {
        debug!("upstream (Local->QUIC) error: {}", e);
      } else {
        debug!("upstream completed, local service closed");
      }
    }
    Either::Right((res, _)) => {
      if let Err(e) = res {
        debug!("downstream (QUIC->Local) error: {}", e);
      } else {
        debug!("downstream completed, external client closed");
      }
    }
  }
}
