//! Data streams opened by the server, one per public TCP connection: connect to the
//! matching local service and forward both ways.

use std::{net::ToSocketAddrs, sync::Arc, time::Duration};

use quinn::{Connection, RecvStream, SendStream, VarInt};
use tracing::{debug, trace};

use super::ServiceRegistry;
use crate::shared::{protocol::read_stream_header, proxy::proxy};

pub(super) async fn accept_data_streams(conn: Connection, services: ServiceRegistry) {
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
  let header = read_stream_header(quic_recv).await?;
  let port = header.port;
  // Compression comes from the stream header, not local config, so a reload that is
  // still propagating to the server cannot desync the two ends.
  let compression = header.compression;

  let service = services.get(&port).ok_or_else(|| anyhow::anyhow!("no service configured for port {}", port))?;

  let local_addr = service.local_addr.clone();
  let service_name = service.name.clone();

  drop(service); // Release lock before async operations

  debug!("proxying to local service: {} ({})", service_name, local_addr);

  let resolved = local_addr
    .to_socket_addrs()?
    .next()
    .ok_or_else(|| anyhow::anyhow!("no address resolved for local service {}", local_addr))?;
  let local_tcp = tokio::net::TcpStream::connect(resolved).await?;
  let sock_ref = socket2::SockRef::from(&local_tcp);
  sock_ref.set_tcp_nodelay(true)?;
  let keepalive = socket2::TcpKeepalive::new()
    .with_interval(Duration::from_secs(10))
    .with_retries(5)
    .with_time(Duration::from_secs(60));
  sock_ref.set_tcp_keepalive(&keepalive)?;
  debug!("connected to local service: {}", local_addr);

  proxy(local_tcp, quic_send, quic_recv, compression).await;
  Ok(())
}
