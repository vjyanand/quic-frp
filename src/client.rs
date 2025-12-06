use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
  sync::Arc,
  time::Duration,
};

use quinn::{
  ClientConfig, Endpoint, IdleTimeout, TransportConfig, VarInt,
  crypto::rustls::QuicClientConfig,
};

use tracing::{debug, info};

use crate::
  config::{ClientConfig as Config, VERSION_MAJOR}
;


/// Client entry point
pub async fn run_client(config: Config, config_path: &str) -> anyhow::Result<()> {
  info!("Client connecting to {}", config.remote_addr);

  let (server_addr, local_bind) = resolve_server_addr(&config)?;

  let transport_config = create_transport_config()?;

  let mut client_crypto = rustls::ClientConfig::builder()
    .with_root_certificates(load_root_certs()?)
    .with_no_client_auth();
  let alpn = if let Some(token) = config.token {
    format!("quic-proxy-{}-{}", VERSION_MAJOR, token).into_bytes()
  } else {
    format!("quic-proxy-{}", VERSION_MAJOR).into_bytes()
  };
  client_crypto.alpn_protocols = vec![alpn];

  let quic_config = QuicClientConfig::try_from(client_crypto)?;

  let mut client_config = ClientConfig::new(Arc::new(quic_config));
  client_config.transport_config(transport_config);
  let endpoint = Endpoint::client(local_bind)?;
  let connection =
    endpoint.connect_with(client_config, server_addr, "localhost")?.await?;

  Ok(())
}

fn load_root_certs() -> anyhow::Result<rustls::RootCertStore> {
  let mut roots = rustls::RootCertStore::empty();
  // Add platform/system roots
  let native_certs = rustls_native_certs::load_native_certs();
  for cert in native_certs.certs {
    roots.add(cert).ok();
  }
  Ok(roots)
}

fn create_transport_config() -> anyhow::Result<Arc<TransportConfig>> {
  let mut config = TransportConfig::default();

  config.keep_alive_interval(Some(Duration::from_secs(5)));
  config.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(20))?));
  config.max_concurrent_bidi_streams(VarInt::from_u64(500)?);

  Ok(Arc::new(config))
}
// =============================================================================
// QUIC Connection Setup
// =============================================================================
fn resolve_server_addr(config: &Config) -> anyhow::Result<(SocketAddr, SocketAddr)> {
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
