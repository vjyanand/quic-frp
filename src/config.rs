#![allow(dead_code)]

use bincode::{Decode, Encode, encode_to_vec};
use compio_quic::{RecvStream, SendStream};
use log::trace;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Encode, Decode, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct ServiceDefinition {
  pub service_name: String,
  pub local_addr: String,
  pub remote_port: u16,
}

#[derive(Debug, Clone, Encode, Deserialize)]
pub struct ClientConfig {
  pub remote_addr: String,
  pub prefer_ipv6: Option<bool>,
  pub retry_interval: Option<u64>,
  pub services: Vec<ServiceDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
  pub listen_addr: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerRootConfig {
  pub server: ServerConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientRootConfig {
  pub client: ClientConfig,
}

#[derive(Debug, Deserialize)]
pub enum Config {
  Server(ServerConfig),
  Client(ClientConfig),
}

impl Config {
  pub fn load(path: &str) -> anyhow::Result<Self> {
    let content = std::fs::read_to_string(path)?;
    if let Ok(server_root_config) = toml::from_str::<ServerRootConfig>(&content) {
      return Ok(Config::Server(server_root_config.server));
    }

    if let Ok(client_root_config) = toml::from_str::<ClientRootConfig>(&content) {
      return Ok(Config::Client(client_root_config.client));
    }
    toml::from_str::<ClientRootConfig>(&content)?;
    Err(anyhow::anyhow!("Invalid config: must have [server] or [client] section"))
  }
  pub fn load_client(path: &str) -> anyhow::Result<ClientConfig> {
    let content = std::fs::read_to_string(path)?;
    let root: ClientRootConfig = toml::from_str(&content)?;
    Ok(root.client)
  }
}

/// Writes a framed control message to a *unidirectional* or *bidi* SendStream.
pub async fn control_write_frame<T: Encode>(
  stream: &mut SendStream,
  frame: &T,
) -> anyhow::Result<()> {
  let serialized = encode_to_vec(frame, bincode::config::standard())?;
  let len = (serialized.len() as u32).to_be_bytes();
  trace!("Writing frame of length {:?}", len);
  // Write 4-byte length
  stream.write_all(&len).await?;
  // Write payload
  stream.write_all(&serialized).await?;
  Ok(())
}

/// Reads exactly one framed control message.
pub async fn control_read_frame<T: bincode::Decode<()>>(
  stream: &mut RecvStream,
) -> anyhow::Result<T> {
  let mut len_buf = [0u8; 4];
  stream.read_exact(&mut len_buf[..]).await?;
  let frame_len = u32::from_be_bytes(len_buf) as usize;
  trace!("Reading frame of length {}", frame_len);
  let mut buf = vec![0u8; frame_len];
  stream.read_exact(&mut buf[..]).await?;
  let (frame, _) = bincode::decode_from_slice::<T, _>(&buf, bincode::config::standard())?;
  Ok(frame)
}
