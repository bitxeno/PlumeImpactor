use std::io;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::get_data_path;

#[derive(Debug, Args)]
#[command(arg_required_else_help = true, about = "Manage local anisette data")]
pub struct AnisetteArgs {
    #[command(subcommand)]
    pub command: AnisetteCommands,
}

#[derive(Debug, Subcommand)]
pub enum AnisetteCommands {
    /// Delete local anisette data so it is generated again on next use
    Reset,
}

pub async fn execute(args: AnisetteArgs) -> Result<()> {
    match args.command {
        AnisetteCommands::Reset => reset(),
    }
}

fn reset() -> Result<()> {
    let data_path = get_data_path();
    let removed = reset_data(&data_path)?;

    if removed.is_empty() {
        log::info!("No anisette data found in {}.", data_path.display());
    } else {
        for path in &removed {
            log::info!("Removed {}.", path.display());
        }
    }

    log::info!("Anisette data will be regenerated on next use. You may need to log in again.");
    Ok(())
}

fn reset_data(data_path: &Path) -> Result<Vec<PathBuf>> {
    let mut removed = Vec::new();

    for name in ["state.plist", "identifier", "adi.pb"] {
        let path = data_path.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }

    let anisette_dir = data_path.join("anisette");
    match std::fs::remove_dir_all(&anisette_dir) {
        Ok(()) => removed.push(anisette_dir),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_removes_anisette_data_and_keeps_configuration() {
        let data_path =
            std::env::temp_dir().join(format!("plumesign-anisette-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(data_path.join("anisette").join("account")).unwrap();

        for path in [
            data_path.join("state.plist"),
            data_path.join("identifier"),
            data_path.join("adi.pb"),
            data_path
                .join("anisette")
                .join("account")
                .join("state.plist"),
            data_path.join("accounts.json"),
            data_path.join("anisette.json"),
        ] {
            std::fs::write(path, b"test").unwrap();
        }

        let removed = reset_data(&data_path).unwrap();

        assert_eq!(removed.len(), 4);
        assert!(!data_path.join("state.plist").exists());
        assert!(!data_path.join("identifier").exists());
        assert!(!data_path.join("adi.pb").exists());
        assert!(!data_path.join("anisette").exists());
        assert!(data_path.join("accounts.json").exists());
        assert!(data_path.join("anisette.json").exists());

        std::fs::remove_dir_all(data_path).unwrap();
    }
}
