use std::path::PathBuf;

use bitcode::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::tls::TlsClientCertConfig;

pub const VERSION_MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");

#[derive(Debug, Clone, Encode, Decode, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct ServiceDefinition {
  pub local_addr: String,
  pub name: String,
  pub remote_port: u16,
  pub prefer_ipv6: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
  pub prefer_ipv6: Option<bool>,
  pub remote_addr: String,
  pub retry_interval: Option<u64>,
  pub services: Vec<ServiceDefinition>,
  pub token: Option<String>,
  #[serde(default)]
  pub tls: TlsClientCertConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
  pub cert: Option<PathBuf>,
  pub key: Option<PathBuf>,
  pub listen_addr: String,
  pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ServerRootConfig {
  pub server: ServerConfig,
}

#[derive(Debug, Deserialize)]
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
