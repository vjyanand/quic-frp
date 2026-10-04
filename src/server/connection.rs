//! One client connection: authenticate, then serve register/unregister requests on the
//! control stream until it closes, and release the client's ports afterwards.

use std::time::Duration;

use quinn::{Connection, SendStream, VarInt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::{
  listener,
  registry::{Claim, ClientIdentity, PortBinding, PortRegistry},
};
use crate::{
  config::ServiceDefinition,
  shared::protocol::{ClientControlMessage, ClientHello, ServerAckMessage, constant_time_eq, read_frame, write_frame},
};

/// How long a new connection has to send its `ClientHello`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// QUIC application close code sent when the client fails authentication.
const CLOSE_UNAUTHORIZED: u32 = 0x401;
/// Bind attempts beyond the first when registering a port.
const BIND_RETRIES: u32 = 3;

pub(super) async fn handle_connection(
  incoming: quinn::Incoming,
  registry: PortRegistry,
  token: &Option<String>,
) -> anyhow::Result<()> {
  let connection = incoming.await?;
  let remote_address = connection.remote_address();
  debug!("new incoming connection from {} with id {}", remote_address, connection.stable_id());

  let (mut control_send, mut control_recv) = connection.accept_bi().await?; // Control Stream from client
  debug!("control stream established for {}", remote_address);

  let hello = tokio::time::timeout(HELLO_TIMEOUT, read_frame::<ClientHello, _>(&mut control_recv))
    .await
    .map_err(|_| anyhow::anyhow!("client {} did not send hello within {:?}", remote_address, HELLO_TIMEOUT))??;
  if !is_authorized(token, &hello.token) {
    warn!("rejecting {}: invalid token", remote_address);
    connection.close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"unauthorized");
    return Err(anyhow::anyhow!("client {} failed authentication", remote_address));
  }

  let client = ClientIdentity::new(remote_address, hello.session_id);
  debug!("authenticated client {}", client);

  let loop_result: anyhow::Result<()> = async {
    loop {
      match read_frame::<ClientControlMessage, _>(&mut control_recv).await {
        Ok(ClientControlMessage::RegisterService(def)) => {
          if let Err(e) = handle_register(def, &connection, &mut control_send, &client, &registry).await {
            warn!("handle_register error: {:?}", e);
            return Err(e);
          }
        }
        Ok(ClientControlMessage::DeregisterService(def)) => {
          if let Err(e) = handle_unregister(def, &mut control_send, &client, &registry).await {
            warn!("handle_unregister error: {:?}", e);
          }
        }
        Err(e) => {
          debug!("control stream ended for {}: {:#}  (chain: {:?})", client, e, e);
          break;
        }
      }
    }
    Ok(())
  }
  .await;

  registry.release_all(&client);
  loop_result
}

fn is_authorized(expected: &Option<String>, presented: &Option<String>) -> bool {
  match (expected, presented) {
    (None, _) => true,
    (Some(expected), Some(presented)) => constant_time_eq(expected.as_bytes(), presented.as_bytes()),
    (Some(_), None) => false,
  }
}

async fn handle_register(
  def: ServiceDefinition,
  conn: &Connection,
  control_send: &mut SendStream,
  client: &ClientIdentity,
  registry: &PortRegistry,
) -> anyhow::Result<()> {
  let outcome = register(&def, client, registry).await;
  let (success, error) = match &outcome {
    Registration::Bound(_) | Registration::AlreadyBound => (true, None),
    Registration::Rejected(msg) => (false, Some(msg.clone())),
  };
  let ack = ServerAckMessage::ServiceRegistered {
    service_name: def.name.clone(),
    remote_port: def.remote_port,
    success,
    error,
  };
  write_frame(control_send, &ack).await?;

  if let Registration::Bound(tcp_listener) = outcome {
    let cancel = CancellationToken::new();
    let binding =
      PortBinding { client_identity: client.clone(), service_name: def.name.clone().into(), cancel: cancel.clone() };
    registry.insert(def.remote_port, binding);
    tokio::spawn(listener::accept_loop(conn.clone(), tcp_listener, def, cancel));
  }
  Ok(())
}

enum Registration {
  Bound(TcpListener),
  /// Idempotent re-register from the connection that already holds the port.
  AlreadyBound,
  Rejected(String),
}

async fn register(def: &ServiceDefinition, client: &ClientIdentity, registry: &PortRegistry) -> Registration {
  debug!("register: {:?} from {}", def, client);
  let port = def.remote_port;

  match registry.claim(port, client) {
    Claim::Free => {}
    Claim::AlreadyOwned => {
      debug!("port {} already registered by this connection {}", port, client);
      return Registration::AlreadyBound;
    }
    Claim::Taken { owner } => {
      return Registration::Rejected(format!("port {} conflict: requested by {} but owned by {}", port, client, owner));
    }
  }

  match listener::bind_with_retry(def, BIND_RETRIES).await {
    Ok(tcp_listener) => {
      info!("created listener for service '{}' on port {} for {}", def.name, port, client);
      Registration::Bound(tcp_listener)
    }
    Err(e) => {
      let msg = format!("failed to create listener for port {} ({}): {}", port, client, e);
      warn!("{}", msg);
      Registration::Rejected(msg)
    }
  }
}

async fn handle_unregister(
  def: ServiceDefinition,
  control_send: &mut SendStream,
  client: &ClientIdentity,
  registry: &PortRegistry,
) -> anyhow::Result<()> {
  debug!("unregister: {:?} from {}", def, client);

  let success = registry.release(def.remote_port, client);

  let ack = ServerAckMessage::ServiceUnregistered {
    service_name: def.name,
    success,
    error: (!success).then(|| "port not owned by this connection".to_string()),
  };
  write_frame(control_send, &ack).await?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::net::SocketAddr;

  use super::*;

  fn service(port: u16) -> ServiceDefinition {
    ServiceDefinition {
      local_addr: "127.0.0.1:1".into(),
      name: "svc".into(),
      remote_port: port,
      prefer_ipv6: None,
      compression: None,
    }
  }

  fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port()
  }

  /// Register `def` for `owner` and hold the listener until the binding is cancelled,
  /// like `listener::accept_loop` does.
  async fn bind_for(def: &ServiceDefinition, owner: &ClientIdentity, registry: &PortRegistry) {
    let Registration::Bound(tcp_listener) = register(def, owner, registry).await else {
      panic!("initial registration failed");
    };
    let cancel = CancellationToken::new();
    let held = cancel.clone();
    tokio::spawn(async move {
      held.cancelled().await;
      drop(tcp_listener);
    });
    registry.insert(
      def.remote_port,
      PortBinding { client_identity: owner.clone(), service_name: def.name.clone().into(), cancel },
    );
  }

  /// A DashMap deadlock blocks the thread outright, so `tokio::time::timeout` cannot catch it.
  /// Run on a separate OS thread and bound the wait from outside.
  fn run_with_deadline<F: std::future::Future<Output = ()> + Send + 'static>(fut: F) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
      tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(fut);
      let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(10)).expect("test hung (deadlock?)");
  }

  #[test]
  fn stale_connection_takeover_rebinds_port() {
    run_with_deadline(async {
      let registry = PortRegistry::default();
      let def = service(free_tcp_port());
      let stale = ClientIdentity::new("203.0.113.7:5000".parse().unwrap(), 42);
      bind_for(&def, &stale, &registry).await;

      // Reconnect of the same session (from a new IP) while the old listener is still open:
      // must not deadlock, and must retry the bind until the old listener is released.
      let fresh = ClientIdentity::new("198.51.100.9:6000".parse().unwrap(), 42);
      let result = register(&def, &fresh, &registry).await;
      assert!(matches!(result, Registration::Bound(_)));
      assert!(!registry.contains(def.remote_port), "stale binding should have been removed");
    });
  }

  #[test]
  fn conflicting_registrations_rejected() {
    run_with_deadline(async {
      let registry = PortRegistry::default();
      let def = service(free_tcp_port());
      let addr: SocketAddr = "203.0.113.7:5000".parse().unwrap();
      let owner = ClientIdentity::new(addr, 1);
      bind_for(&def, &owner, &registry).await;

      let result = register(&def, &owner, &registry).await;
      assert!(matches!(result, Registration::AlreadyBound));

      // Another client behind the same NAT IP must not be able to take the port.
      let other = ClientIdentity::new(addr, 2);
      let result = register(&def, &other, &registry).await;
      assert!(matches!(result, Registration::Rejected(_)));
      assert!(registry.contains(def.remote_port), "owner's binding must survive a conflicting request");
    });
  }

  #[test]
  fn token_authorization() {
    let expected = Some("secret".to_string());
    assert!(is_authorized(&None, &None));
    assert!(is_authorized(&None, &Some("anything".into())));
    assert!(is_authorized(&expected, &Some("secret".into())));
    assert!(!is_authorized(&expected, &Some("wrong".into())));
    assert!(!is_authorized(&expected, &None));
  }
}
