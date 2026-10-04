//! Private side of the tunnel: connects out to the server, registers the configured
//! services, and forwards the server's data streams to local addresses.
//!
//! - `transport`: resolve the server and open the QUIC connection
//! - `session`: control stream for one connection (hello, registration, retries)
//! - `reload`: config file watching and live service updates
//! - `streams`: data streams from the server to local services
//! - `tls`: how the server certificate is verified
//! - `backoff`: reconnect delays

mod backoff;
mod reload;
mod session;
mod streams;
mod tls;
mod transport;

use std::{
  sync::Arc,
  time::{Duration, Instant},
};

use dashmap::DashMap;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub use tls::TlsClientCertConfig;

use crate::{
  config::ServiceDefinition,
  shared::protocol::{self, ClientHello},
};
use backoff::ExponentialBackoff;
use session::LoopControl;

/// A session must stay up at least this long before we treat it as "healthy"
/// and reset the reconnect backoff. Prevents tight loops when the server
/// accepts the QUIC handshake but the session dies immediately after.
const HEALTHY_SESSION_THRESHOLD: Duration = Duration::from_secs(30);

/// Configured services by remote port, shared with hot reload and data streams.
type ServiceRegistry = Arc<DashMap<u16, ServiceDefinition>>;

/// Client entry point
pub async fn run_client(config: crate::config::ClientConfig, config_path: &str) -> anyhow::Result<()> {
  info!("client connecting to {}", config.remote_addr);

  let retry_secs = config.retry_interval.unwrap_or(5);
  let mut backoff = ExponentialBackoff::new(Duration::from_secs(retry_secs), Duration::from_secs(30));

  let alpn = protocol::alpn();
  let (server_addr, local_bind) = transport::resolve_server_addr(&config)?;
  let server_name = match &config.server_name {
    Some(name) => name.clone(),
    None => transport::host_from_addr(&config.remote_addr).to_string(),
  };
  debug!("TLS server name: {}", server_name);
  let hello = ClientHello { token: config.token, session_id: uuid::Uuid::new_v4().as_u128() };

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
    match transport::connect_to_server(server_addr, local_bind, &server_name, &alpn, tls_config.clone()).await {
      Ok(conn) => {
        info!("connected to server");
        let session_start = Instant::now();

        let outcome = session::handle_connection(conn, &hello, &services, config_path, shutdown.clone()).await;

        if session_start.elapsed() >= HEALTHY_SESSION_THRESHOLD {
          backoff.reset();
        }

        match outcome {
          Ok(LoopControl::Shutdown) => {
            info!("clean shutdown requested");
            break;
          }
          Ok(LoopControl::Reconnect) => {
            let delay = backoff.next_delay();
            info!("reconnecting in {}s", delay.as_secs());
            tokio::select! {
              _ = tokio::time::sleep(delay) => {}
              _ = shutdown.cancelled() => {
                info!("shutdown during reconnect backoff");
                break;
              }
            }
          }
          Err(e) => {
            let delay = backoff.next_delay();
            warn!("connection error: {}, retrying in {}s", e, delay.as_secs());
            tokio::select! {
              _ = tokio::time::sleep(delay) => {}
              _ = shutdown.cancelled() => {
                info!("shutdown during retry backoff");
                break;
              }
            }
          }
        }
      }
      Err(e) => {
        let delay = backoff.next_delay();
        warn!("connection failed: {}, retrying in {}s", e, delay.as_secs());
        tokio::select! {
          _ = tokio::time::sleep(delay) => {}
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
