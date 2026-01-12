mod backoff;
mod cli;
mod client;
mod config;
mod protocol;
mod server;

use clap::Parser;
use tracing::debug;
use tracing_subscriber::{EnvFilter, FmtSubscriber, fmt::format::FmtSpan};

use crate::{cli::Cli, client::run_client, config::Config, server::run_server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  FmtSubscriber::builder()
    .with_env_filter(
      EnvFilter::try_from_default_env()
        .unwrap_or(EnvFilter::new("debug"))
        .add_directive("quinn::connection=warn".parse().unwrap()),
    )
    .with_thread_names(true)
    .with_span_events(FmtSpan::CLOSE)
    .init();

  let cli = Cli::try_parse()?;
  debug!("Using config file {}", cli.config);
  let config = Config::load(&cli.config)?;
  match config {
    Config::Server(server_config) => run_server(server_config).await,
    Config::Client(client_config) => run_client(client_config, &cli.config).await,
  }
}
