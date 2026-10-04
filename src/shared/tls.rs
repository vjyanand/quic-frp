//! PEM helpers used by both the server (its certificate chain) and the client
//! (certificates it pins).

use anyhow::Context;
use rustls::pki_types::CertificateDer;
use std::{fs::File, io::BufReader, path::Path};

pub fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
  let file = File::open(path).with_context(|| format!("failed to open cert file {}", path.display()))?;
  let mut reader = BufReader::new(file);
  let certs = rustls_pemfile::certs(&mut reader)
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("failed to parse certificates from {}", path.display()))?;
  if certs.is_empty() {
    anyhow::bail!("no certificates found in {}", path.display());
  }
  Ok(certs)
}
