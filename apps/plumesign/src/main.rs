mod commands;

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use chrono::Local;
use clap::Parser;
use commands::{Cli, Commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            writeln!(
                buf,
                "[{} {:<5} {}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.module_path().unwrap_or("<unknown>"),
                record.args()
            )
        })
        .init();
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

pub fn get_data_path() -> PathBuf {
    let base = if cfg!(windows) {
        env::var("APPDATA").unwrap()
    } else {
        env::var("HOME").unwrap() + "/.config"
    };

    let dir = Path::new(&base).join("PlumeImpactor");

    fs::create_dir_all(&dir).ok();

    dir
}
