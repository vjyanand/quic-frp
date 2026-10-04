//! Server certificate: loaded from PEM files, or a self-signed one generated at startup.

use anyhow::{Context, anyhow};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
  fs::File,
  io::BufReader,
  path::{Path, PathBuf},
};
use tracing::debug;

use crate::shared::tls::load_certs;

#[derive(Debug)]
pub(super) enum TlsServerCertConfig {
  SelfSigned {
    san: Vec<String>,
  },
  PemFiles {
    /// Path to the certificate chain PEM file (fullchain.pem)
    cert_path: PathBuf,
    /// Path to the private key PEM file (private.key)
    key_path: PathBuf,
  },
}

impl TlsServerCertConfig {
  pub(super) fn self_signed(san: impl IntoIterator<Item = impl Into<String>>) -> Self {
    Self::SelfSigned { san: san.into_iter().map(Into::into).collect() }
  }

  pub(super) fn from_pem_files(cert_path: PathBuf, key_path: PathBuf) -> Self {
    Self::PemFiles { cert_path, key_path }
  }

  pub(super) fn into_server_config(self) -> anyhow::Result<rustls::ServerConfig> {
    let (certs, key) = match self {
      Self::SelfSigned { san } => generate_self_signed(&san)?,
      Self::PemFiles { cert_path, key_path } => load_pem_files(&cert_path, &key_path)?,
    };
    let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    Ok(config)
  }
}

fn load_pem_files(
  cert_path: &Path,
  key_path: &Path,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
  let certs = load_certs(cert_path)?;

  let key_file = File::open(key_path).with_context(|| format!("failed to open key file {}", key_path.display()))?;
  let mut key_reader = BufReader::new(key_file);
  let key = rustls_pemfile::private_key(&mut key_reader)
    .with_context(|| format!("failed to parse private key PEM: {}", key_path.display()))?
    .ok_or_else(|| anyhow!("No private key found in {}", key_path.display()))?;

  debug!("loaded certificate from file");
  Ok((certs, key))
}

fn generate_self_signed(san: &[String]) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
  let rcgen::CertifiedKey { cert, signing_key } =
    rcgen::generate_simple_self_signed(san.to_vec()).map_err(|e| anyhow!("failed to generate certificate: {}", e))?;

  let cert_der = cert.der().clone();
  let key_der = signing_key
    .serialize_der()
    .try_into() // Convert Vec<u8> to PrivateKeyDer via TryInto
    .map_err(|_| anyhow!("failed to serialize private key"))?;

  debug!("generated self signed certificate");
  Ok((vec![cert_der], key_der))
}
