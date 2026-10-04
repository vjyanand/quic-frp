//! Hot reload: watch the config file and apply service changes to a live session.

use std::{collections::HashSet, time::Duration};

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use quinn::SendStream;
use tracing::{debug, info};

use super::ServiceRegistry;
use crate::{
  config::{Config, ServiceDefinition},
  shared::protocol::{ClientControlMessage, write_frame},
};

pub(super) fn setup_config_watcher(
  config_path: &str,
  tx: std::sync::mpsc::Sender<()>,
) -> anyhow::Result<RecommendedWatcher> {
  let config = notify::Config::default().with_poll_interval(Duration::from_secs(10)).with_compare_contents(true);

  let mut watcher = RecommendedWatcher::new(
    move |res: Result<Event, _>| {
      if let Ok(event) = res
        && event.kind.is_modify()
      {
        let _ = tx.send(());
      }
    },
    config,
  )?;

  watcher.watch(std::path::Path::new(config_path), RecursiveMode::NonRecursive)?;
  debug!("watching config file: {}", config_path);

  Ok(watcher)
}

pub(super) async fn handle_config_reload(
  ctrl_send: &mut SendStream,
  services: &ServiceRegistry,
  config_path: &str,
) -> anyhow::Result<()> {
  let new_config = Config::load_client(config_path)?;

  let new_ports: HashSet<u16> = new_config.services.iter().map(|s| s.remote_port).collect();

  let to_remove: Vec<u16> = services
    .iter()
    .filter_map(|entry| {
      let port = *entry.key();
      if !new_ports.contains(&port) { Some(port) } else { None }
    })
    .collect();

  // Unregister removed services
  for port in to_remove {
    if let Some(svc) = services.remove(&port) {
      info!("unregistering removed service: {}", svc.1.name);
      write_frame(ctrl_send, &ClientControlMessage::DeregisterService(svc.1)).await?;
    }
  }

  // Register or update services. Clone the current entry out so no DashMap guard
  // is held across the awaits below.
  for svc in new_config.services {
    let current = services.get(&svc.remote_port).map(|entry| entry.clone());
    match current {
      Some(current) if current == svc => {}
      Some(current) if needs_reregister(&current, &svc) => {
        // Server-side settings changed: the server must rebind with the new definition.
        info!("re-registering changed service: {}", svc.name);
        write_frame(ctrl_send, &ClientControlMessage::DeregisterService(current)).await?;
        write_frame(ctrl_send, &ClientControlMessage::RegisterService(svc.clone())).await?;
        services.insert(svc.remote_port, svc);
      }
      Some(current) => {
        info!("updating service {} local_addr: {} -> {}", svc.name, current.local_addr, svc.local_addr);
        services.insert(svc.remote_port, svc);
      }
      None => {
        info!("Registering new service: {}", svc.name);
        write_frame(ctrl_send, &ClientControlMessage::RegisterService(svc.clone())).await?;
        services.insert(svc.remote_port, svc);
      }
    }
  }

  debug!("updated services list - {:?}", services);
  Ok(())
}

/// Whether a change touches fields the server acts on (as opposed to `local_addr`,
/// which only the client uses).
fn needs_reregister(current: &ServiceDefinition, new: &ServiceDefinition) -> bool {
  current.name != new.name || current.compression != new.compression || current.prefer_ipv6 != new.prefer_ipv6
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reregister_only_for_server_side_changes() {
    let base = ServiceDefinition {
      local_addr: "127.0.0.1:80".into(),
      name: "web".into(),
      remote_port: 8080,
      prefer_ipv6: None,
      compression: None,
    };
    let local_only = ServiceDefinition { local_addr: "127.0.0.1:81".into(), ..base.clone() };
    let compression = ServiceDefinition { compression: Some(true), ..base.clone() };
    let ipv6 = ServiceDefinition { prefer_ipv6: Some(true), ..base.clone() };
    assert!(!needs_reregister(&base, &local_only));
    assert!(needs_reregister(&base, &compression));
    assert!(needs_reregister(&base, &ipv6));
  }
}
