use clap::Parser;

#[derive(Parser)]
pub struct Cli {
  /// Path to configuration file
  pub config: String,
}
