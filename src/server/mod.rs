//! Public side of the tunnel: accepts QUIC connections from clients and opens the
//! TCP ports they register.
//!
//! - `connection`: per-client control session (auth, register/unregister)
//! - `registry`: which connection owns which public port
//! - `listener`: public TCP listeners and the QUIC stream opened per TCP connection
//! - `transport`: QUIC transport and UDP socket configuration
//! - `tls`: server certificate

mod connection;
mod listener;
mod registry;
mod tls;
mod transport;

use std::{net::SocketAddr, sync::Arc};

use quinn::{Endpoint, EndpointConfig, ServerConfig, crypto::rustls::QuicServerConfig, default_runtime};
use tracing::{debug, info, warn};

use crate::shared::protocol;
use registry::PortRegistry;
use tls::TlsServerCertConfig;

pub async fn run_server(config: crate::config::ServerConfig) -> anyhow::Result<()> {
  info!("server starting on {}", config.listen_addr);

  let mut server_crypto = match (config.cert, config.key) {
    (Some(cert), Some(key)) => TlsServerCertConfig::from_pem_files(cert, key).into_server_config()?,
    _ => TlsServerCertConfig::self_signed(vec!["localhost"]).into_server_config()?,
  };

  let alpn = protocol::alpn();
  server_crypto.alpn_protocols = vec![alpn.into()];
  let server_crypto = Arc::new(QuicServerConfig::try_from(server_crypto)?);

  let mut server_config = ServerConfig::with_crypto(server_crypto);
  server_config.transport_config(transport::create_transport_config()?);

  let bind_addr: SocketAddr = config.listen_addr.parse()?;
  let socket = transport::create_udp_socket(bind_addr)?;
  let endpoint_config = EndpointConfig::default();
  let runtime = default_runtime().unwrap();
  let endpoint = Endpoint::new(endpoint_config, Some(server_config), socket, runtime)?;

  info!("server listening on {}", endpoint.local_addr()?);

  let registry = PortRegistry::default();
  let token: Arc<Option<String>> = Arc::new(config.token);

  loop {
    let Some(incoming) = endpoint.accept().await else {
      warn!("endpoint closed, shutting down");
      break;
    };

    let registry = registry.clone();
    let token = Arc::clone(&token);
    tokio::spawn(async move {
      let result = connection::handle_connection(incoming, registry, &token).await;
      debug!("result: {:?}", result);
    });
  }

  Ok(())
}
