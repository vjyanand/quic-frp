use clap::Parser;
use tracing::{Level, debug};
use tracing_subscriber::FmtSubscriber;

use crate::{cli::Cli, client::run_client, config::Config, server::run_server};

mod backoff;
mod cli;
mod client;
mod config;
mod protocol;
mod server;
mod tls;

#[compio::main]
async fn main() -> anyhow::Result<()> {
  let subscriber = FmtSubscriber::builder().with_max_level(Level::WARN).finish();
  tracing::subscriber::set_global_default(subscriber)
    .expect("setting default subscriber failed");

  let cli = Cli::try_parse()?;
  debug!("Using config file {}", cli.config);
  let config = Config::load(&cli.config)?;
  match config {
    Config::Server(server_config) => run_server(server_config).await,
    Config::Client(client_config) => run_client(client_config, &cli.config).await,
  }
}
