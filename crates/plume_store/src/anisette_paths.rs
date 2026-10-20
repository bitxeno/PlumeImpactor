//! Per-account anisette state layout.
//!
//! One state per Apple ID, under `<data>/anisette/<hash>/state.plist`, where
//! `<hash>` is derived from the account email (see
//! [`omnisette::account_dir_name`]).  Hashing keeps the user's email out of
//! the filesystem while still mapping one account to exactly one directory.
//!
//! The email is known before login, so no temporary directory is needed.
//!
//! Legacy files (`<data>/state.plist`, `<data>/identifier` + `<data>/adi.pb`)
//! are never moved or deleted.  They stay as read-only fallbacks so accounts
//! that have not logged in again keep refreshing, and downgrading still works.

use std::path::{Path, PathBuf};

/// Subdirectory of the data root holding per-account state.
pub const ANISETTE_DIR: &str = "anisette";

/// Path of an account's state directory: `<data>/anisette/<hash>`.
pub fn account_dir(data_root: &Path, email: &str) -> PathBuf {
    data_root
        .join(ANISETTE_DIR)
        .join(plume_core::account_dir_name(email))
}

/// Path of an account's state file.
pub fn account_state_file(data_root: &Path, email: &str) -> PathBuf {
    account_dir(data_root, email).join("state.plist")
}

/// Reset an account's anisette data: generate a brand-new device identity and
/// drop the existing `adi_pb`.
///
/// The file is overwritten rather than removed so the loader cannot fall back
/// to the legacy shared state and resurrect the old identity.
pub fn reset_account_state(data_root: &Path, email: &str) -> std::io::Result<()> {
    let path = account_state_file(data_root, email);
    plume_core::reset_state_file(&path).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_name_does_not_contain_email() {
        let dir = account_dir(Path::new("/data"), "user@example.com");
        let name = dir.file_name().unwrap().to_string_lossy();
        assert!(!name.contains("user"));
        assert!(!name.contains("example"));
        assert!(!name.contains('@'));
        assert_eq!(name.len(), 32);
    }

    #[test]
    fn same_account_maps_to_same_dir() {
        let a = account_dir(Path::new("/data"), "User@Example.com");
        let b = account_dir(Path::new("/data"), "  user@example.com ");
        assert_eq!(a, b);
    }

    #[test]
    fn different_accounts_differ() {
        let a = account_dir(Path::new("/data"), "a@example.com");
        let b = account_dir(Path::new("/data"), "b@example.com");
        assert_ne!(a, b);
    }
}

/// Remote anisette server setting, stored next to `accounts.json`.
pub mod server {
    use std::path::{Path, PathBuf};

    use serde::{Deserialize, Serialize};

    /// Server used when the user has not chosen one.
    pub const DEFAULT_URL: &str = "https://new.ani.sidestore.io";

    const SETTINGS_FILE: &str = "anisette.json";

    #[derive(Debug, Default, Serialize, Deserialize)]
    struct Settings {
        /// `None` means the default server.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    }

    fn settings_path(data_root: &Path) -> PathBuf {
        data_root.join(SETTINGS_FILE)
    }

    fn load(data_root: &Path) -> Settings {
        std::fs::read_to_string(settings_path(data_root))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Remote anisette server in effect, falling back to the default.
    pub fn url(data_root: &Path) -> String {
        load(data_root)
            .url
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_URL.to_string())
    }

    /// Whether the value comes from the settings file rather than the default.
    pub fn is_custom(data_root: &Path) -> bool {
        load(data_root).url.is_some()
    }

    /// Set a custom server; `None` restores the default.
    pub fn set_url(data_root: &Path, url: Option<&str>) -> std::io::Result<()> {
        let settings = Settings {
            url: url.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()),
        };
        let path = settings_path(data_root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&settings)?)?;
        Ok(())
    }
}
