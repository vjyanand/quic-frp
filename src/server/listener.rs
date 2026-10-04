//! Public TCP listeners: bind a registered port, accept connections, and tunnel each
//! one to the client over a new QUIC stream.

use std::{net::SocketAddr, time::Duration};

use quinn::{Connection, VarInt};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{
  config::ServiceDefinition,
  shared::protocol::{StreamHeader, write_stream_header},
  shared::proxy::proxy,
};

/// Bind the service's public port, retrying briefly: on a stale-connection takeover the
/// previous listener is closed asynchronously by its accept task.
pub(super) async fn bind_with_retry(service: &ServiceDefinition, max_retries: u32) -> anyhow::Result<TcpListener> {
  let retry_delay = Duration::from_millis(100);
  let (domain, bind_addr) = match service.prefer_ipv6.unwrap_or_default() {
    true => (Domain::IPV6, SocketAddr::from(([0u16; 8], service.remote_port))),
    false => (Domain::IPV4, SocketAddr::from(([0u8; 4], service.remote_port))),
  };

  let mut attempt = 0;
  loop {
    match bind(domain, bind_addr) {
      Ok(listener) => {
        debug!("bound TCP listener {} (attempt {})", bind_addr, attempt + 1);
        return Ok(listener);
      }
      Err(e) if attempt < max_retries => {
        debug!("failed to bind {} (attempt {}), retrying: {}", bind_addr, attempt + 1, e);
        attempt += 1;
        tokio::time::sleep(retry_delay).await;
      }
      Err(e) => {
        return Err(anyhow::anyhow!("failed to bind {} after {} attempts: {}", bind_addr, attempt + 1, e));
      }
    }
  }
}

fn bind(domain: Domain, bind_addr: SocketAddr) -> std::io::Result<TcpListener> {
  let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
  socket.set_tcp_nodelay(true)?;
  socket.set_nonblocking(true)?;
  socket.set_reuse_address(true)?;
  socket.bind(&bind_addr.into())?;
  socket.listen(128)?;
  let std_listener: std::net::TcpListener = socket.into();
  TcpListener::from_std(std_listener)
}

/// Accept TCP connections until `cancel` fires; each is tunnelled on its own QUIC stream.
pub(super) async fn accept_loop(
  conn: Connection,
  listener: TcpListener,
  service: ServiceDefinition,
  cancel: CancellationToken,
) {
  let port = service.remote_port;
  let compression = service.compression.unwrap_or_default();
  info!("accepting TCP connections on port {} for service '{}'", port, service.name);

  loop {
    tokio::select! {
      biased;
      _ = cancel.cancelled() => {
        debug!("listener for port {} cancelled, releasing", port);
        break;
      }
      accept_result = listener.accept() => {
        match accept_result {
          Ok((tcp_stream, peer_addr)) => {
            debug!("accepted TCP connection on port {} from {}", port, peer_addr);
            let conn = conn.clone();
            let conn_cancel = cancel.child_token();
            tokio::spawn(async move {
              if let Err(e) = tunnel(conn, tcp_stream, port, peer_addr, compression, conn_cancel).await {
                warn!("TCP connection handler error for {}: {}", peer_addr, e);
              }
            });
          }
          Err(e) => {
            warn!("TCP accept error on port {}: {}", port, e);
            tokio::time::sleep(Duration::from_millis(100)).await;
          }
        }
      }
    }
  }
}

async fn tunnel(
  conn: Connection,
  tcp_stream: TcpStream,
  port: u16,
  peer_addr: SocketAddr,
  compression: bool,
  cancel: CancellationToken,
) -> anyhow::Result<()> {
  debug!("opening QUIC stream for TCP peer {}", peer_addr);
  let (mut quic_send, mut quic_recv) = tokio::select! {
    biased;
    _ = cancel.cancelled() => return Ok(()),
    res = conn.open_bi() => res.map_err(|e| anyhow::anyhow!("failed to open QUIC stream: {}", e))?,
  };

  write_stream_header(&mut quic_send, &StreamHeader { port, compression })
    .await
    .map_err(|e| anyhow::anyhow!("failed to write stream header: {}", e))?;

  tokio::select! {
    biased;
    _ = cancel.cancelled() => {
      debug!("TCP connection {} cancelled mid-proxy", peer_addr);
      let _ = quic_send.reset(VarInt::from_u32(0));
      let _ = quic_recv.stop(VarInt::from_u32(0));
    }
    _ = proxy(tcp_stream, &mut quic_send, &mut quic_recv, compression) => {}
  }
  debug!("TCP connection {} closed", peer_addr);
  Ok(())
}
