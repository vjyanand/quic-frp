use anyhow::{Context, anyhow};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::debug;

use crate::config::VERSION_MAJOR;

#[derive(Debug)]
pub enum TlsServerCertConfig {
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

impl Default for TlsServerCertConfig {
  fn default() -> Self {
    Self::SelfSigned { san: vec!["localhost".to_string()] }
  }
}

impl TlsServerCertConfig {
  pub fn self_signed(san: impl IntoIterator<Item = impl Into<String>>) -> Self {
    Self::SelfSigned { san: san.into_iter().map(Into::into).collect() }
  }
  pub fn from_pem_files(cert_path: PathBuf, key_path: PathBuf) -> Self {
    Self::PemFiles { cert_path, key_path }
  }

  pub fn load(&self) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    match self {
      TlsServerCertConfig::SelfSigned { san } => generate_self_signed(san),
      TlsServerCertConfig::PemFiles { cert_path, key_path } => Self::load_pem_files(cert_path, key_path),
    }
  }

  fn load_pem_files(
    cert_path: &PathBuf,
    key_path: &PathBuf,
  ) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = load_certs(cert_path)?;

    if certs.is_empty() {
      return Err(anyhow!("no certificates found in {}", cert_path.display()));
    }

    // Read private key
    let key_file = File::open(key_path).with_context(|| format!("failed to open key file {}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);

    let key = rustls_pemfile::private_key(&mut key_reader)
      .with_context(|| format!("failed to parse private key PEM: {}", key_path.display()))?
      .ok_or_else(|| anyhow!("No private key found in {}", key_path.display()))?;

    debug!("loaded certificate from file");
    Ok((certs, key))
  }

  pub fn into_server_config(self) -> anyhow::Result<rustls::ServerConfig> {
    let (certs, key) = self.load()?;
    let config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    Ok(config)
  }
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

pub fn alpn(token: &Option<String>) -> String {
  match token {
    Some(token) => format!("quic-proxy-{}-{}", VERSION_MAJOR, token.clone()),
    None => format!("quic-proxy-{}", VERSION_MAJOR),
  }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TlsClientCertConfig {
  /// Trust system root certificates
  #[default]
  SystemRoot,
  /// Trust a specific certificate file (for self-signed servers)
  TrustCert {
    /// Path to the server's certificate PEM file
    cert_path: PathBuf,
  },
  /// Skip certificate verification (DANGEROUS - testing only)
  SkipVerification,
}

impl TlsClientCertConfig {
  pub fn into_client_config(self) -> anyhow::Result<rustls::ClientConfig> {
    debug!("{:?}", self);
    match self {
      TlsClientCertConfig::SystemRoot => Self::build_with_system_root(),
      TlsClientCertConfig::TrustCert { cert_path } => Self::build_with_cert(cert_path),
      TlsClientCertConfig::SkipVerification => Self::build_with_skip_verification(),
    }
  }

  fn build_with_cert(cert_path: PathBuf) -> anyhow::Result<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();

    let certs = load_certs(&cert_path)?;

    if certs.is_empty() {
      return Err(anyhow!("no certificates found in {}", cert_path.display()));
    }

    // Add all certificates to root store
    for cert in certs {
      root_store.add(cert)?;
    }

    let config = rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();

    debug!("built client config trusting certificate from {}", cert_path.display());
    Ok(config)
  }

  fn build_with_system_root() -> anyhow::Result<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();

    // Load native OS certificates
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
      root_store.add(cert)?;
    }

    let config = rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();

    debug!("built client config with system root certificates");
    Ok(config)
  }

  fn build_with_skip_verification() -> anyhow::Result<rustls::ClientConfig> {
    let config = rustls::ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(verifier::SkipServerVerification::new()))
      .with_no_client_auth();

    debug!("built client config with certificate verification DISABLED");
    Ok(config)
  }
}

/// Helper to just load certs for Root Store population
fn load_certs(path: &PathBuf) -> anyhow::Result<Vec<CertificateDer<'static>>> {
  let file = File::open(path).with_context(|| format!("failed to open cert file {}", path.display()))?;
  let mut reader = BufReader::new(file);
  rustls_pemfile::certs(&mut reader)
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("failed to parse certificates from {}", path.display()))
}

//Borrowed from https://github.com/compio-rs/compio/blob/ce3c0455027b055e6a8a4b5e9b8ee947f1b71746/compio-quic/src/builder.rs#L225
mod verifier {
  use rustls::{
    client::danger::{ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, ring::default_provider},
  };
  #[derive(Debug)]
  pub struct SkipServerVerification(WebPkiSupportedAlgorithms);
  impl SkipServerVerification {
    pub fn new() -> Self {
      Self(
        rustls::crypto::CryptoProvider::get_default()
          .map(|provider| provider.signature_verification_algorithms)
          .unwrap_or_else(|| default_provider().signature_verification_algorithms),
      )
    }
  }

  impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
      &self,
      _end_entity: &rustls::pki_types::CertificateDer<'_>,
      _intermediates: &[rustls::pki_types::CertificateDer<'_>],
      _server_name: &rustls::pki_types::ServerName<'_>,
      _ocsp_response: &[u8],
      _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
      Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
      &self,
      message: &[u8],
      cert: &rustls::pki_types::CertificateDer<'_>,
      dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
      &self,
      message: &[u8],
      cert: &rustls::pki_types::CertificateDer<'_>,
      dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
      self.0.supported_schemes()
    }
  }
}
