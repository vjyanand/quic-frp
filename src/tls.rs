use std::path::PathBuf;

use log::debug;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub enum TlsCertConfig {
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

impl Default for TlsCertConfig {
  fn default() -> Self {
    Self::SelfSigned { san: vec!["localhost".to_string()] }
  }
}

impl TlsCertConfig {
  /// Create a self-signed certificate config with the given SANs
  pub fn self_signed(san: impl IntoIterator<Item = impl Into<String>>) -> Self {
    Self::SelfSigned { san: san.into_iter().map(Into::into).collect() }
  }
  pub fn from_pem_files(
    cert_path: impl Into<PathBuf>,
    key_path: impl Into<PathBuf>,
  ) -> Self {
    Self::PemFiles { cert_path: cert_path.into(), key_path: key_path.into() }
  }

  pub fn load(
    &self,
  ) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    match self {
      TlsCertConfig::SelfSigned { san } => Self::generate_self_signed(san),
      TlsCertConfig::PemFiles { cert_path, key_path } => {
        Self::load_pem_files(cert_path, key_path)
      }
    }
  }

  fn load_pem_files(
    cert_path: &PathBuf,
    key_path: &PathBuf,
  ) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let key_pem = std::fs::read(key_path).map_err(|e| {
      anyhow::anyhow!("Failed to read key file {}: {}", key_path.display(), e)
    })?;

    // Read certificate chain
    let cert_pem = std::fs::read(cert_path).map_err(|e| {
      anyhow::anyhow!("Failed to read certificate file {}: {}", cert_path.display(), e)
    })?;

    let certs: Vec<CertificateDer<'static>> =
      rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate PEM: {}", e))?;

    if certs.is_empty() {
      return Err(anyhow::anyhow!("No certificates found in {}", cert_path.display()));
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
      .map_err(|e| anyhow::anyhow!("Failed to parse private key PEM: {}", e))?
      .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path.display()))?;
    debug!("loaded certificate from file");
    Ok((certs, key))
  }

  fn generate_self_signed(
    san: &[String],
  ) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let rcgen::CertifiedKey { cert, signing_key } =
      rcgen::generate_simple_self_signed(san.to_vec())
        .map_err(|e| anyhow::anyhow!("Failed to generate certificate: {}", e))?;

    let cert_der = cert.der().clone();
    let key_der = signing_key
      .serialize_der()
      .try_into()
      .map_err(|_| anyhow::anyhow!("Failed to serialize private key"))?;
    debug!("generated self signed certificate");
    Ok((vec![cert_der], key_der))
  }
}
