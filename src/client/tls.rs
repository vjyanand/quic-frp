//! How the client verifies the server certificate (`[client.tls]` in the config).

use rustls::RootCertStore;
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc};
use tracing::debug;

use crate::shared::tls::load_certs;

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
  pub(super) fn into_client_config(self) -> anyhow::Result<rustls::ClientConfig> {
    debug!("{:?}", self);
    match self {
      Self::SystemRoot => {
        let mut root_store = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
          root_store.add(cert)?;
        }
        debug!("built client config with system root certificates");
        Ok(with_roots(root_store))
      }
      Self::TrustCert { cert_path } => {
        let mut root_store = RootCertStore::empty();
        for cert in load_certs(&cert_path)? {
          root_store.add(cert)?;
        }
        debug!("built client config trusting certificate from {}", cert_path.display());
        Ok(with_roots(root_store))
      }
      Self::SkipVerification => {
        let config = rustls::ClientConfig::builder()
          .dangerous()
          .with_custom_certificate_verifier(Arc::new(verifier::SkipServerVerification::new()))
          .with_no_client_auth();
        debug!("built client config with certificate verification DISABLED");
        Ok(config)
      }
    }
  }
}

fn with_roots(root_store: RootCertStore) -> rustls::ClientConfig {
  rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth()
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
