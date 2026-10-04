//! End-to-end tests: real server and client over loopback QUIC, proxying to a local echo service.

use std::{
  net::SocketAddr,
  path::{Path, PathBuf},
  time::{Duration, Instant},
};

use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream},
  task::JoinHandle,
};

use crate::{
  client::run_client,
  config::{Config, ServerConfig},
  server::run_server,
};

async fn spawn_echo() -> SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  tokio::spawn(async move {
    while let Ok((mut stream, _)) = listener.accept().await {
      tokio::spawn(async move {
        let (mut r, mut w) = stream.split();
        let _ = tokio::io::copy(&mut r, &mut w).await;
        let _ = w.shutdown().await;
      });
    }
  });
  addr
}

fn free_udp_port() -> u16 {
  std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn free_tcp_port() -> u16 {
  std::net::TcpListener::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port()
}

struct Service {
  name: &'static str,
  local_addr: SocketAddr,
  remote_port: u16,
  compression: bool,
}

fn client_config_toml(server_port: u16, token: Option<&str>, services: &[Service]) -> String {
  let mut toml = format!("[client]\nremote_addr = \"127.0.0.1:{server_port}\"\nretry_interval = 1\n");
  if let Some(token) = token {
    toml += &format!("token = \"{token}\"\n");
  }
  toml += "\n[client.tls]\nmode = \"skip_verification\"\n";
  for svc in services {
    toml += &format!(
      "\n[[client.services]]\nname = \"{}\"\nlocal_addr = \"{}\"\nremote_port = {}\ncompression = {}\n",
      svc.name, svc.local_addr, svc.remote_port, svc.compression
    );
  }
  toml
}

fn temp_config_path() -> PathBuf {
  std::env::temp_dir().join(format!("quic-frp-e2e-{}.toml", uuid::Uuid::new_v4()))
}

fn start_server(port: u16, token: Option<&str>) -> JoinHandle<anyhow::Result<()>> {
  let config =
    ServerConfig { cert: None, key: None, listen_addr: format!("127.0.0.1:{port}"), token: token.map(Into::into) };
  tokio::spawn(run_server(config))
}

fn start_client(path: &Path) -> JoinHandle<anyhow::Result<()>> {
  let path = path.to_str().unwrap().to_string();
  tokio::spawn(async move {
    let Config::Client(config) = Config::load(&path)? else { anyhow::bail!("expected client config") };
    run_client(config, &path).await
  })
}

async fn roundtrip(port: u16, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
  let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
  let (mut r, mut w) = stream.split();
  let write = async {
    w.write_all(payload).await?;
    w.shutdown().await
  };
  let mut out = Vec::with_capacity(payload.len());
  let (written, read) = tokio::join!(write, r.read_to_end(&mut out));
  written?;
  read?;
  Ok(out)
}

/// Retry until the tunnel is up (the server binds `port` only after registration).
async fn roundtrip_eventually(port: u16, payload: &[u8]) -> Vec<u8> {
  let deadline = Instant::now() + Duration::from_secs(15);
  loop {
    match roundtrip(port, payload).await {
      Ok(out) if !out.is_empty() => return out,
      result if Instant::now() > deadline => panic!("tunnel on port {port} never came up: {result:?}"),
      _ => tokio::time::sleep(Duration::from_millis(100)).await,
    }
  }
}

/// ~1 MiB: compressible text plus a non-repeating tail, to exercise multi-chunk snappy framing.
fn payload() -> Vec<u8> {
  let mut data = b"quic-frp end-to-end ".repeat(40_000);
  data.extend((0..200_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8));
  data
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxies_with_and_without_compression() {
  let echo = spawn_echo().await;
  let server_port = free_udp_port();
  let (plain_port, snappy_port) = (free_tcp_port(), free_tcp_port());
  let services = [
    Service { name: "plain", local_addr: echo, remote_port: plain_port, compression: false },
    Service { name: "snappy", local_addr: echo, remote_port: snappy_port, compression: true },
  ];
  let path = temp_config_path();
  std::fs::write(&path, client_config_toml(server_port, Some("s3cret"), &services)).unwrap();

  let server = start_server(server_port, Some("s3cret"));
  let client = start_client(&path);

  let data = payload();
  assert!(roundtrip_eventually(plain_port, &data).await == data, "plain tunnel corrupted data");
  assert!(roundtrip_eventually(snappy_port, &data).await == data, "compressed tunnel corrupted data");

  // Concurrent streams over the same connection.
  let concurrent = (0..32).map(|i| {
    let port = if i % 2 == 0 { plain_port } else { snappy_port };
    let data = data[..64 * 1024].to_vec();
    tokio::spawn(async move { roundtrip(port, &data).await.map(|out| out == data) })
  });
  for task in concurrent {
    assert!(task.await.unwrap().unwrap(), "concurrent roundtrip corrupted data");
  }

  client.abort();
  server.abort();
  let _ = std::fs::remove_file(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compression_change_on_reload_keeps_data_intact() {
  let echo = spawn_echo().await;
  let server_port = free_udp_port();
  let remote_port = free_tcp_port();
  let path = temp_config_path();
  let config = |compression| {
    client_config_toml(server_port, None, &[Service { name: "svc", local_addr: echo, remote_port, compression }])
  };
  std::fs::write(&path, config(false)).unwrap();

  let server = start_server(server_port, None);
  let client = start_client(&path);

  let data = payload();
  assert!(roundtrip_eventually(remote_port, &data).await == data);

  // Flip compression on and keep traffic flowing through the reload.
  std::fs::write(&path, config(true)).unwrap();
  let deadline = Instant::now() + Duration::from_secs(5);
  while Instant::now() < deadline {
    if let Ok(out) = roundtrip(remote_port, &data).await {
      // Re-registration closes the old listener and its in-flight connections, so a
      // roundtrip racing the reload may be cut short. It must never contain wrong bytes.
      assert!(data.starts_with(&out), "data corrupted across compression reload (got {} bytes)", out.len());
      if out.len() != data.len() {
        eprintln!("truncated roundtrip during reload: {} of {} bytes", out.len(), data.len());
      }
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
  assert!(roundtrip_eventually(remote_port, &data).await == data);

  client.abort();
  server.abort();
  let _ = std::fs::remove_file(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_token_is_rejected() {
  let echo = spawn_echo().await;
  let server_port = free_udp_port();
  let remote_port = free_tcp_port();
  let path = temp_config_path();
  let services = [Service { name: "svc", local_addr: echo, remote_port, compression: false }];
  std::fs::write(&path, client_config_toml(server_port, Some("wrong"), &services)).unwrap();

  let server = start_server(server_port, Some("right"));
  let client = start_client(&path);

  tokio::time::sleep(Duration::from_secs(3)).await;
  assert!(TcpStream::connect(("127.0.0.1", remote_port)).await.is_err(), "unauthorized client got a port");

  client.abort();
  server.abort();
  let _ = std::fs::remove_file(&path);
}

/// Local service that answers every connection with `tag`, so tests can tell backends apart.
async fn spawn_tagged(tag: &'static [u8]) -> SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  tokio::spawn(async move {
    while let Ok((mut stream, _)) = listener.accept().await {
      tokio::spawn(async move {
        let _ = stream.write_all(tag).await;
        let _ = stream.shutdown().await;
        let _ = tokio::io::copy(&mut stream, &mut tokio::io::sink()).await;
      });
    }
  });
  addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarted_client_reclaims_port_via_retry() {
  let (backend_a, backend_b) = (spawn_tagged(b"A").await, spawn_tagged(b"B").await);
  let server_port = free_udp_port();
  let remote_port = free_tcp_port();
  let config = |local_addr| {
    client_config_toml(server_port, None, &[Service { name: "svc", local_addr, remote_port, compression: false }])
  };
  let (path_a, path_b) = (temp_config_path(), temp_config_path());
  std::fs::write(&path_a, config(backend_a)).unwrap();
  std::fs::write(&path_b, config(backend_b)).unwrap();

  let server = start_server(server_port, None);
  let client_a = start_client(&path_a);
  assert_eq!(roundtrip_eventually(remote_port, b"").await, b"A");

  // A second process (new session, same IP) must not take the port while the first is alive.
  let client_b = start_client(&path_b);
  tokio::time::sleep(Duration::from_secs(2)).await;
  assert_eq!(roundtrip(remote_port, b"").await.unwrap(), b"A");

  // Crash the first process. Once the server drops its connection, the second client's
  // registration retries must win the port.
  client_a.abort();
  let deadline = Instant::now() + Duration::from_secs(30);
  loop {
    if let Ok(out) = roundtrip(remote_port, b"").await
      && out == b"B"
    {
      break;
    }
    assert!(Instant::now() < deadline, "second client never took over the port");
    tokio::time::sleep(Duration::from_millis(250)).await;
  }

  client_b.abort();
  server.abort();
  let _ = std::fs::remove_file(&path_a);
  let _ = std::fs::remove_file(&path_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn bench_throughput() {
  let echo = spawn_echo().await;
  let server_port = free_udp_port();
  let (plain_port, snappy_port) = (free_tcp_port(), free_tcp_port());
  let services = [
    Service { name: "plain", local_addr: echo, remote_port: plain_port, compression: false },
    Service { name: "snappy", local_addr: echo, remote_port: snappy_port, compression: true },
  ];
  let path = temp_config_path();
  std::fs::write(&path, client_config_toml(server_port, None, &services)).unwrap();
  let _server = start_server(server_port, None);
  let _client = start_client(&path);
  roundtrip_eventually(plain_port, b"x").await;
  roundtrip_eventually(snappy_port, b"x").await;
  // 128 MiB, mildly compressible (like typical mixed traffic)
  let chunk = payload();
  let data: Vec<u8> = chunk.iter().cycle().take(128 << 20).copied().collect();
  for (name, port) in [("plain", plain_port), ("snappy", snappy_port)] {
    let mut best = f64::MAX;
    for _ in 0..3 {
      let t = Instant::now();
      let out = roundtrip(port, &data).await.unwrap();
      assert_eq!(out.len(), data.len());
      best = best.min(t.elapsed().as_secs_f64());
    }
    // echo => bytes cross the tunnel twice
    eprintln!("BENCH {name}: {:.0} MiB/s", 2.0 * 128.0 / best);
  }
}
