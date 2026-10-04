//! Ownership of public ports: which client connection serves which port.
//!
//! All DashMap access lives here. Never hold a `get` guard while mutating the map:
//! a `remove` on the same shard while a guard is alive deadlocks the thread.

use std::{
  net::{IpAddr, SocketAddr},
  sync::Arc,
};

use dashmap::DashMap;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Identity of one client connection.
#[derive(Clone, Debug)]
pub(super) struct ClientIdentity {
  /// For logging only; ownership is decided by `session_id` and `connection_id`.
  remote_ip: IpAddr,
  /// Client-chosen, stable across reconnects of one client process.
  session_id: u128,
  /// Unique per QUIC connection.
  connection_id: uuid::Uuid,
}

impl ClientIdentity {
  pub(super) fn new(addr: SocketAddr, session_id: u128) -> Self {
    let remote_ip = match addr.ip() {
      IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
      ip => ip,
    };
    Self { remote_ip, session_id, connection_id: uuid::Uuid::new_v4() }
  }

  /// Same client process on a different connection (a reconnect), regardless of source IP.
  fn is_same_client(&self, other: &Self) -> bool {
    self.session_id == other.session_id
  }
}

impl PartialEq for ClientIdentity {
  fn eq(&self, other: &Self) -> bool {
    self.session_id == other.session_id && self.connection_id == other.connection_id
  }
}

impl std::fmt::Display for ClientIdentity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let session = format!("{:032x}", self.session_id);
    let connection = self.connection_id.as_hyphenated().to_string();
    write!(f, "{}({:.8}/{:.8})", self.remote_ip, session, connection)
  }
}

/// A registered port. Cancelling `cancel` stops its listener and in-flight connections.
pub(super) struct PortBinding {
  pub(super) client_identity: ClientIdentity,
  pub(super) service_name: Box<str>,
  pub(super) cancel: CancellationToken,
}

/// Outcome of asking to bind a port.
pub(super) enum Claim {
  /// Nobody holds the port (any stale binding of the same session was evicted).
  Free,
  /// This very connection already holds it.
  AlreadyOwned,
  /// Another client holds it.
  Taken { owner: String },
}

#[derive(Clone, Default)]
pub(super) struct PortRegistry(Arc<DashMap<u16, PortBinding>>);

impl PortRegistry {
  /// Check whether `client` may bind `port`, evicting a binding left by a stale
  /// connection of the same client session.
  pub(super) fn claim(&self, port: u16, client: &ClientIdentity) -> Claim {
    enum Owner {
      Same,
      Stale,
      Other(String),
    }
    let owner = self.0.get(&port).map(|existing| {
      if client == &existing.client_identity {
        Owner::Same
      } else if client.is_same_client(&existing.client_identity) {
        Owner::Stale
      } else {
        Owner::Other(format!("{} (service: {})", existing.client_identity, existing.service_name))
      }
    }); // guard dropped here, before any mutation

    match owner {
      None => Claim::Free,
      Some(Owner::Same) => Claim::AlreadyOwned,
      Some(Owner::Stale) => {
        info!("port {} owned by stale connection, taking over for {}", port, client);
        if let Some((_, old)) = self.0.remove(&port) {
          debug!(
            "cancelling listener for port {} (client={}, service={})",
            port, old.client_identity, old.service_name
          );
          old.cancel.cancel();
        }
        Claim::Free
      }
      Some(Owner::Other(owner)) => Claim::Taken { owner },
    }
  }

  pub(super) fn insert(&self, port: u16, binding: PortBinding) {
    self.0.insert(port, binding);
  }

  /// Release `port` if `client` owns it. Returns whether it did.
  pub(super) fn release(&self, port: u16, client: &ClientIdentity) -> bool {
    match self.0.remove_if(&port, |_, binding| &binding.client_identity == client) {
      Some((_, binding)) => {
        binding.cancel.cancel();
        debug!("released port {} (service: {})", port, binding.service_name);
        true
      }
      None => {
        if self.0.contains_key(&port) {
          debug!("port {} was taken over, skipping release", port);
        }
        false
      }
    }
  }

  /// Release every port owned by `client` (connection closed).
  pub(super) fn release_all(&self, client: &ClientIdentity) {
    let ports: Vec<u16> =
      self.0.iter().filter_map(|entry| (&entry.client_identity == client).then_some(*entry.key())).collect();
    let released = ports.into_iter().filter(|&port| self.release(port, client)).count();
    if released > 0 {
      info!("cleaned up {} ports for {}", released, client);
    }
  }

  #[cfg(test)]
  pub(super) fn contains(&self, port: u16) -> bool {
    self.0.contains_key(&port)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn identity(addr: &str, session_id: u128) -> ClientIdentity {
    ClientIdentity::new(addr.parse().unwrap(), session_id)
  }

  fn bind(registry: &PortRegistry, port: u16, owner: &ClientIdentity) -> CancellationToken {
    let cancel = CancellationToken::new();
    let binding = PortBinding { client_identity: owner.clone(), service_name: "svc".into(), cancel: cancel.clone() };
    registry.insert(port, binding);
    cancel
  }

  #[test]
  fn claim_classifies_owners() {
    let registry = PortRegistry::default();
    let owner = identity("203.0.113.7:5000", 1);
    assert!(matches!(registry.claim(80, &owner), Claim::Free));
    let cancel = bind(&registry, 80, &owner);

    assert!(matches!(registry.claim(80, &owner), Claim::AlreadyOwned));
    // Same NAT IP, different session: refused.
    assert!(matches!(registry.claim(80, &identity("203.0.113.7:5000", 2)), Claim::Taken { .. }));
    assert!(registry.contains(80) && !cancel.is_cancelled());

    // Same session, new connection (even from another IP): stale binding evicted.
    assert!(matches!(registry.claim(80, &identity("198.51.100.9:6000", 1)), Claim::Free));
    assert!(!registry.contains(80) && cancel.is_cancelled());
  }

  #[test]
  fn release_only_by_owner() {
    let registry = PortRegistry::default();
    let owner = identity("203.0.113.7:5000", 1);
    let cancel = bind(&registry, 80, &owner);
    bind(&registry, 81, &owner);

    assert!(!registry.release(80, &identity("203.0.113.7:5000", 2)));
    assert!(registry.contains(80) && !cancel.is_cancelled());

    registry.release_all(&owner);
    assert!(!registry.contains(80) && !registry.contains(81) && cancel.is_cancelled());
  }
}
