//! One connected session: send the hello, register services, then run the control
//! loop (acks, registration retries, config reloads) until the connection drops or
//! shutdown is requested.

use std::{
  pin::pin,
  sync::Arc,
  time::{Duration, Instant},
};

use quinn::{Connection, RecvStream, SendStream};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{ServiceRegistry, reload, streams};
use crate::shared::protocol::{ClientControlMessage, ClientHello, ServerAckMessage, read_frame, write_frame};

/// Delay before re-sending a registration the server rejected. Covers ports still held
/// by our own previous connection (e.g. after a restart) until the server times it out.
const REGISTER_RETRY_DELAY: Duration = Duration::from_secs(5);

pub(super) enum LoopControl {
  Shutdown,
  Reconnect,
}

pub(super) async fn handle_connection(
  conn: Connection,
  hello: &ClientHello,
  services: &ServiceRegistry,
  config_path: &str,
  shutdown_token: CancellationToken,
) -> anyhow::Result<LoopControl> {
  let (reload_tx, reload_rx) = std::sync::mpsc::channel();
  let _watcher = reload::setup_config_watcher(config_path, reload_tx)?;

  let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?;
  debug!("control stream opened");

  write_frame(&mut ctrl_send, hello).await?;
  register_services(&mut ctrl_send, services).await?;

  let accept_task = tokio::spawn(streams::accept_data_streams(conn.clone(), Arc::clone(services)));

  let (retry_tx, retry_rx) = mpsc::unbounded_channel();
  let quic_ctrl_task = tokio::spawn(async move {
    receive_control_messages(&mut ctrl_recv, retry_tx).await;
    true
  });

  let result = event_loop_with_connection_monitor(
    &mut ctrl_send,
    services,
    config_path,
    reload_rx,
    retry_rx,
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

  if let Some(reason) = conn.close_reason() {
    warn!("connection closed: {}", reason);
  }

  result
}

async fn event_loop_with_connection_monitor(
  ctrl_send: &mut SendStream,
  services: &ServiceRegistry,
  config_path: &str,
  reload_rx: std::sync::mpsc::Receiver<()>,
  mut retry_rx: mpsc::UnboundedReceiver<u16>,
  quic_ctrl_task: JoinHandle<bool>,
  shutdown_token: CancellationToken,
) -> anyhow::Result<LoopControl> {
  let mut conn_dead = pin!(quic_ctrl_task);
  let mut pending_retries: Vec<(Instant, u16)> = Vec::new();

  loop {
    while let Ok(port) = retry_rx.try_recv() {
      if !pending_retries.iter().any(|&(_, p)| p == port) {
        pending_retries.push((Instant::now() + REGISTER_RETRY_DELAY, port));
      }
    }
    let now = Instant::now();
    let (due, waiting): (Vec<_>, Vec<_>) = pending_retries.into_iter().partition(|&(at, _)| at <= now);
    pending_retries = waiting;
    for (_, port) in due {
      // Skip services removed by a reload since the failure.
      let Some(svc) = services.get(&port).map(|svc| svc.clone()) else { continue };
      debug!("retrying registration of '{}'", svc.name);
      write_frame(ctrl_send, &ClientControlMessage::RegisterService(svc)).await?;
    }

    // Drain all pending reload signals (coalesce rapid changes)
    let mut reload_pending = false;
    while reload_rx.try_recv().is_ok() {
      reload_pending = true;
    }

    if reload_pending {
      info!("config file changed, reloading...");
      if let Err(e) = reload::handle_config_reload(ctrl_send, services, config_path).await {
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

async fn receive_control_messages(ctrl_recv: &mut RecvStream, retry_tx: mpsc::UnboundedSender<u16>) {
  loop {
    match read_frame::<ServerAckMessage, _>(ctrl_recv).await {
      Ok(msg) => match msg {
        ServerAckMessage::ServiceRegistered { service_name, remote_port, success, error } => {
          if success {
            info!("service '{}' registered", service_name);
          } else {
            warn!(
              "service '{}' registration failed, retrying in {}s: {}",
              service_name,
              REGISTER_RETRY_DELAY.as_secs(),
              error.unwrap_or_default()
            );
            let _ = retry_tx.send(remote_port);
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
