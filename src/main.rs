use clap::Parser;

use crate::{cli::Cli, client::run_client, config::Config, server::run_server};

mod backoff;
mod cli;
mod client;
mod config;
mod protocol;
mod server;

#[compio::main]
async fn main() -> anyhow::Result<()> {
  env_logger::init();
  let cli = Cli::try_parse()?;
  let config = Config::load(&cli.config)?;
  match config {
    Config::Server(server_config) => run_server(server_config).await,
    Config::Client(client_config) => run_client(client_config, &cli.config).await,
  }
}
