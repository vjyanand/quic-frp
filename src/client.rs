use std::{
  fs::File, io::BufReader, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs}, path::PathBuf, pin::pin, sync::Arc, time::Duration
};

use futures::{
  AsyncReadExt,
  future::{Either, select},
  io::copy,
};
use quinn::{
  ClientConfig, Endpoint, IdleTimeout, RecvStream, SendStream, TransportConfig, VarInt,
  crypto::rustls::QuicClientConfig,
};

use rustls::pki_types::CertificateDer;
use smol::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::{ClientConfig as Config, VERSION_MAJOR};

/// Client entry point
pub async fn run_client(config: Config, _config_path: &str) -> anyhow::Result<()> {
  info!("Client connecting to {}", config.remote_addr);

  let (server_addr, local_bind) = resolve_server_addr(&config)?;

  let transport_config = create_transport_config()?;

  let mut client_crypto = rustls::ClientConfig::builder()
    .with_root_certificates(load_root_certs(config.cert.as_ref())?)
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
  debug!("End point created");
  let connection = endpoint.connect_with(client_config, server_addr, "localhost")?.await?;
  debug!("Connected");
  loop {
    debug!("trying BI Stream from server");
    let (mut tx_r, mut tx_s) = connection.accept_bi().await?;
    debug!("BI Stream from server accepted");
    let backend_addr = "127.0.0.1:8080";

    let tcp_stream = match smol::net::TcpStream::connect(backend_addr).await {
      Ok(tcp_stream) => tcp_stream,
      Err(e) => {
        warn!("Failed to connect to backend: {}", e);
        return Err(e.into());
      }
    };
    proxy_quic_to_tcp(tcp_stream, &mut tx_r, &mut tx_s).await?;
  }
}

async fn proxy_quic_to_tcp(
  tcp: TcpStream,
  quic_send: &mut SendStream,
  quic_recv: &mut RecvStream,
) -> anyhow::Result<()> {
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
    copy(quic_recv, &mut tcp_w).await
    // When this returns, server closed their send side (external client disconnected)
    // TCP write half will be dropped, signaling EOF to local service
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

  Ok(())
}

fn load_root_certs(cert_path: Option<&PathBuf>) -> anyhow::Result<rustls::RootCertStore> {
  let mut roots = rustls::RootCertStore::empty();
  // Add platform/system roots
  let native_certs = rustls_native_certs::load_native_certs();
  for cert in native_certs.certs {
    roots.add(cert).ok();
  }
  if let Some(path) = cert_path {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader).filter_map(|r| r.ok()).collect();

    if certs.is_empty() {
      anyhow::bail!("No certificates found in {:?}", path);
    }

    for cert in certs {
      roots.add(cert)?;
    }
  }
  Ok(roots)
}

fn create_transport_config() -> anyhow::Result<Arc<TransportConfig>> {
  let mut config = TransportConfig::default();

  config.keep_alive_interval(Some(Duration::from_secs(45)));
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
    if chosen.is_ipv6() { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) },
    0,
  );

  debug!("Resolved server: {}, local bind: {}", chosen, local_bind);
  Ok((chosen, local_bind))
}
