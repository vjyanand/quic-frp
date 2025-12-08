use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures::future::{Either, select};
use quinn::{
  Endpoint, EndpointConfig, IdleTimeout, RecvStream, SendStream, ServerConfig, TransportConfig, VarInt,
  crypto::rustls::QuicServerConfig, default_runtime,
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::copy;
use tracing::{debug, info, warn};

use crate::{
  config::{ServerConfig as Config, VERSION_MAJOR},
  tls::TlsCertConfig,
};

/// Server entry point
pub async fn run_server(config: Config) -> anyhow::Result<()> {
  info!("Server starting on {}", config.listen_addr);
  let (cert_der, key_der) = if config.cert.is_some() && config.key.is_some() {
    TlsCertConfig::from_pem_files(config.cert.unwrap(), config.key.unwrap()).load()?
  } else {
    TlsCertConfig::self_signed(vec!["localhost".to_owned()]).load()?
  };

  let mut server_crypto = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(cert_der, key_der)?;

  let alpn = if let Some(token) = config.token {
    format!("quic-proxy-{}-{}", VERSION_MAJOR, token).into_bytes()
  } else {
    format!("quic-proxy-{}", VERSION_MAJOR).into_bytes()
  };
  server_crypto.alpn_protocols = vec![alpn];
  let server_crypto = QuicServerConfig::try_from(server_crypto)?;
  let server_crypto = Arc::new(server_crypto);
  let mut server_config = ServerConfig::with_crypto(server_crypto);
  server_config.transport_config(create_transport_config()?);

  let bind_addr: SocketAddr = config.listen_addr.parse()?;
  let socket = create_udp_socket(bind_addr)?;
  let endpoinf_config = EndpointConfig::default();
  let runtime = default_runtime().unwrap();
  let endpoint = Endpoint::new(endpoinf_config, Some(server_config), socket, runtime)?;
  info!("Server listening on {}", endpoint.local_addr()?);
  loop {
    let incoming = endpoint.accept().await.unwrap();
    debug!("New incoming connection {}", incoming.remote_address());
    tokio::spawn(async move {
      let result = handle_connection(incoming).await;
      debug!("result: {:?}", result);
    });
  }
}

async fn handle_connection(incoming: quinn::Incoming) -> anyhow::Result<()> {
  let connection = incoming.await?;
  let remote_addr = connection.remote_address();
  debug!("Incoming connection from {}", remote_addr);

  let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
  socket.set_tcp_nodelay(true)?;
  socket.set_nonblocking(true)?;
  socket.set_reuse_address(true)?;
  socket.set_write_timeout(Some(Duration::from_secs(2)))?;
  let bind_address = format!("0.0.0.0:{}", "7071");
  let bin = bind_address.parse::<std::net::SocketAddr>()?.into();
  socket.bind(&bin)?;
  socket.listen(128)?;

  let std_listener: std::net::TcpListener = socket.into();
  std_listener.set_nonblocking(true)?;
  let tcp_listener = tokio::net::TcpListener::try_from(std_listener)?;
  debug!("TCP Listening on: {:?}", tcp_listener.local_addr());
  loop {
    debug!("Awaiting on new TCP connection: {:?}", tcp_listener.local_addr());
    let (stream, peer_addr) = tcp_listener.accept().await?;
    debug!("New TCP connection from: {}", peer_addr);
    let l_connection = connection.clone();
    tokio::spawn(async move {
      let result = handle_client(&l_connection, stream).await;
      debug!("result2: {:?}", result);
    });
    debug!("Ends");
  }
}

async fn handle_client(connection: &quinn::Connection, stream: tokio::net::TcpStream) -> anyhow::Result<()> {
  debug!("OPening bi-stream");
  let (mut tx_stream, mut tr_stream) = match connection.open_bi().await {
    Ok(stream) => stream,
    Err(e) => {
      warn!("Stream error {}", e);
      return Ok(());
    }
  };
  proxy_tcp_to_quic(stream, &mut tx_stream, &mut tr_stream).await;
  Ok(())
}

async fn proxy_tcp_to_quic(mut tcp: tokio::net::TcpStream, quic_send: &mut SendStream, quic_recv: &mut RecvStream) {
  let (mut tcp_r, mut tcp_w) = tcp.split();

  let upstream = async {
    let result = copy(&mut tcp_r, quic_send).await;
    let _ = quic_send.finish();
    result
  };

  let downstream = async { copy(quic_recv, &mut tcp_w).await };

  let upstream = std::pin::pin!(upstream);
  let downstream = std::pin::pin!(downstream);

  match select(upstream, downstream).await {
    Either::Left((res, _)) => {
      if let Err(e) = res {
        debug!("Upstream (TCP->QUIC)   {}", e);
      }
    }
    Either::Right((res, _)) => {
      if let Err(e) = res {
        debug!("Downstream (QUIC->TCP) error: {}", e);
      }
    }
  }
}

/// Create and configure UDP socket with optimal settings for QUIC.
fn create_udp_socket(bind_addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
  let socket = Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(Protocol::UDP))?;

  socket.set_nonblocking(true)?;
  socket.set_keepalive(true)?;
  socket.bind(&bind_addr.into())?;
  Ok(socket.into())
}

fn create_transport_config() -> anyhow::Result<Arc<TransportConfig>> {
  let mut transport = TransportConfig::default();

  // Keep-alive to detect dead connections
  transport.keep_alive_interval(Some(Duration::from_secs(5)));

  // Longer idle timeout for server (handles multiple clients)
  transport.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(40))?));

  // High stream limit for busy proxies
  transport.max_concurrent_bidi_streams(VarInt::from_u64(500)?);

  transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

  Ok(Arc::new(transport))
}
