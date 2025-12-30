use anyhow::{Context, anyhow};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use tracing::debug;

#[derive(Debug, Clone)]
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
  pub fn from_pem_files(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
    Self::PemFiles { cert_path: cert_path.into(), key_path: key_path.into() }
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
    // Read certificate chain
    let cert_file =
      File::open(cert_path).with_context(|| format!("Failed to open certificate file {}", cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
      .collect::<Result<Vec<_>, _>>()
      .with_context(|| format!("Failed to parse certificate PEM: {}", cert_path.display()))?;

    if certs.is_empty() {
      return Err(anyhow!("No certificates found in {}", cert_path.display()));
    }

    // Read private key
    let key_file = File::open(key_path).with_context(|| format!("Failed to open key file {}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);

    let key = rustls_pemfile::private_key(&mut key_reader)
      .with_context(|| format!("Failed to parse private key PEM: {}", key_path.display()))?
      .ok_or_else(|| anyhow!("No private key found in {}", key_path.display()))?;

    debug!("loaded certificate from file");
    Ok((certs, key))
  }
}

fn generate_self_signed(san: &[String]) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
  let rcgen::CertifiedKey { cert, signing_key } =
    rcgen::generate_simple_self_signed(san.to_vec()).map_err(|e| anyhow!("Failed to generate certificate: {}", e))?;

  let cert_der = cert.der().clone();
  let key_der = signing_key
    .serialize_der()
    .try_into() // Convert Vec<u8> to PrivateKeyDer via TryInto
    .map_err(|_| anyhow!("Failed to serialize private key"))?;

  debug!("generated self signed certificate");
  Ok((vec![cert_der], key_der))
}

#[derive(Debug, Clone)]
pub enum TlsClientCertConfig {
  SelfSigned {
    san: Vec<String>,
  },
  SystemRoot {
    extra_ca: Option<PathBuf>,
  },
  Custom {
    /// Path to PEM file containing trusted CA(s) and optionally client cert/key
    bundle_path: PathBuf,
  },
}

impl Default for TlsClientCertConfig {
  fn default() -> Self {
    Self::SystemRoot { extra_ca: None }
  }
}

impl TlsClientCertConfig {
  pub fn system_root() -> Self {
    Self::SystemRoot { extra_ca: None }
  }

  pub fn system_root_with_extra_ca(path: impl Into<PathBuf>) -> Self {
    Self::SystemRoot { extra_ca: Some(path.into()) }
  }

  pub fn self_signed(san: impl IntoIterator<Item = impl Into<String>>) -> Self {
    Self::SelfSigned { san: san.into_iter().map(Into::into).collect() }
  }

  pub fn custom(bundle_path: impl Into<PathBuf>) -> Self {
    Self::Custom { bundle_path: bundle_path.into() }
  }

  pub fn into_client_config(self) -> anyhow::Result<rustls::ClientConfig> {
    // 1. Prepare the Root Store (Trusted CAs)
    let mut root_store = rustls::RootCertStore::empty();

    match &self {
      TlsClientCertConfig::SystemRoot { extra_ca } => {
        // Load native OS certs
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
          root_store.add(cert)?;
        }

        // If an extra CA is provided, add it
        if let Some(path) = extra_ca {
          let certs = load_certs(path)?;
          for cert in certs {
            root_store.add(cert)?;
          }
        }
      }
      TlsClientCertConfig::SelfSigned { san } => {
        // For SelfSigned config, we likely trust the cert we just generated (for dev/test loopback)
        // Note: This regenerates the cert. If client and server must match,
        // they must share the same certs logic or files.
        let (certs, _) = generate_self_signed(san)?;
        for cert in certs {
          root_store.add(cert)?;
        }
      }
      TlsClientCertConfig::Custom { bundle_path } => {
        // Load all certs in the bundle as trusted roots
        let certs = load_certs(bundle_path)?;
        for cert in certs {
          root_store.add(cert)?;
        }
      }
    };

    // 2. Prepare Client Authentication (mTLS)
    let (client_certs, client_key) = self.load_client_auth()?;

    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

    let config = if !client_certs.is_empty()
      && let Some(key) = client_key
    {
      builder.with_client_auth_cert(client_certs, key)?
    } else {
      builder.with_no_client_auth()
    };

    Ok(config)
  }

  pub fn load_client_auth(&self) -> anyhow::Result<(Vec<CertificateDer<'static>>, Option<PrivateKeyDer<'static>>)> {
    match self {
      TlsClientCertConfig::SystemRoot { .. } => Ok((vec![], None)),
      TlsClientCertConfig::SelfSigned { san } => {
        let (certs, key) = generate_self_signed(san)?;
        Ok((certs, Some(key)))
      }
      TlsClientCertConfig::Custom { bundle_path } => Self::load_bundle(bundle_path),
    }
  }

  // Load certs and optional key from a bundle file (CA + client cert/key)
  fn load_bundle(path: &PathBuf) -> anyhow::Result<(Vec<CertificateDer<'static>>, Option<PrivateKeyDer<'static>>)> {
    // Load certificates
    // Note: certs() consumes the reader until it finds non-cert data or EOF,
    // so we need to be careful if key and certs are mixed.
    // Rustls-pemfile's `read_all` is safer for mixed content, but we can try specialized cursors.
    // A safer approach for a "bundle" is to read the whole file into memory.
    let pem_data = std::fs::read(path).with_context(|| format!("Failed to read bundle file {}", path.display()))?;

    let mut cursor = std::io::Cursor::new(&pem_data);

    // Parse all certs found
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
      .collect::<Result<Vec<_>, _>>()
      .context("Failed to parse certificates from bundle")?;

    // Reset cursor to try finding a key (if it was skipped or placed before certs)
    cursor.set_position(0);
    let key = rustls_pemfile::private_key(&mut cursor)
      .with_context(|| format!("Failed to parse private key from {}", path.display()))?;

    Ok((certs, key))
  }
}

/// Helper to just load certs for Root Store population
fn load_certs(path: &PathBuf) -> anyhow::Result<Vec<CertificateDer<'static>>> {
  let file = File::open(path).with_context(|| format!("Failed to open cert file {}", path.display()))?;
  let mut reader = BufReader::new(file);
  rustls_pemfile::certs(&mut reader)
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("Failed to parse certificates from {}", path.display()))
}
