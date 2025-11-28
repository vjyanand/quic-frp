use clap::Parser;

#[derive(Parser)]
pub struct Cli {
  /// Path to configuration file
  #[arg(short, long)]
  pub config: String,
}
