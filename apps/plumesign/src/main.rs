mod commands;

use clap::Parser;
use commands::{Cli, Commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    _ = rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    let cli = Cli::parse();

    match cli.command {
        Commands::Sign(args) => commands::sign::execute(args).await?,
        Commands::MachO(args) => commands::macho::execute(args).await?,
        Commands::Account(args) => commands::account::execute(args).await?,
        Commands::Device(args) => commands::device::execute(args).await?,
        Commands::DeviceId(args) => commands::device_id::execute(args).await?,
        Commands::Pair(args) => commands::pair::execute(args).await?,
        Commands::Certificate(args) => commands::certificate::execute(args).await?,
        Commands::Check(args) => commands::check::execute(args).await?,
    }

    Ok(())
}
