use clap::Parser;
use tracing::debug;
use tracing_subscriber::{EnvFilter, FmtSubscriber, fmt::format::FmtSpan};

use crate::{cli::Cli, client::run_client, config::Config, server::run_server};

//mod backoff;
mod cli;
mod client;
mod config;
//mod protocol;
mod server;
mod tls;

fn main() -> anyhow::Result<()> {
  FmtSubscriber::builder()
    .with_env_filter(EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("info")))
    .with_span_events(FmtSpan::CLOSE)
    .init();

  let cli = Cli::try_parse()?;
  debug!("Using config file {}", cli.config);
  let config = Config::load(&cli.config)?;
  smol::block_on(async {
    match config {
      Config::Server(server_config) => run_server(server_config).await,
      Config::Client(client_config) => run_client(client_config, &cli.config).await,
    }
  })
}
