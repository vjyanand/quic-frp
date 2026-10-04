//! Resolving the server and establishing the QUIC connection.

use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
  sync::Arc,
  time::Duration,
};

use quinn::{Connection, Endpoint, IdleTimeout, TransportConfig, VarInt, congestion, crypto::rustls::QuicClientConfig};
use tracing::debug;

use super::tls::TlsClientCertConfig;

/// Pick the server address (honouring `prefer_ipv6`) and a matching local bind address.
pub(super) fn resolve_server_addr(config: &crate::config::ClientConfig) -> anyhow::Result<(SocketAddr, SocketAddr)> {
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

/// Host part of a `host:port` / `[v6]:port` address, used as the TLS server name.
pub(super) fn host_from_addr(addr: &str) -> &str {
  let host = addr.rsplit_once(':').map_or(addr, |(host, _)| host);
  host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

fn create_transport_config() -> anyhow::Result<TransportConfig> {
  let mut transport = TransportConfig::default();

  transport.keep_alive_interval(Some(Duration::from_secs(5)));
  transport.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(10))?));
  // Limits streams the *server* may open to us: one per proxied TCP connection.
  transport.max_concurrent_bidi_streams(VarInt::from_u32(1024));
  transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));
  // Flow control tuning for better throughput
  transport.send_window(4 * 1024 * 1024); // 4MB send window
  transport.stream_receive_window(VarInt::from_u64(1024 * 1024)?); // 1MB per stream
  transport.receive_window(VarInt::from_u64(8 * 1024 * 1024)?); // 8MB total

  // Initial RTT estimate (can help with initial congestion window)
  transport.initial_rtt(Duration::from_millis(100));

  Ok(transport)
}

pub(super) async fn connect_to_server(
  server_addr: SocketAddr,
  local_bind: SocketAddr,
  server_name: &str,
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

  let connection = endpoint.connect_with(client_config, server_addr, server_name)?.await?;
  Ok(connection)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn host_from_addr_strips_port_and_brackets() {
    assert_eq!(host_from_addr("example.com:4433"), "example.com");
    assert_eq!(host_from_addr("203.0.113.7:4433"), "203.0.113.7");
    assert_eq!(host_from_addr("[2001:db8::1]:4433"), "2001:db8::1");
    assert_eq!(host_from_addr("example.com"), "example.com");
  }
}
