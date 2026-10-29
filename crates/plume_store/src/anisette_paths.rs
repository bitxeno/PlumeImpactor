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
    plume_core::reset_state_file_for_account(&path, email).map_err(std::io::Error::other)
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
    pub const DEFAULT_URL: &str = plume_core::DEFAULT_ANISETTE_URL_V3;

    /// Overrides the stored setting for a single run, mainly for debugging.
    pub const ENV_OVERRIDE: &str = "PLUME_ANISETTE_URL";

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

    /// Trim whitespace and trailing slashes so that callers can safely append
    /// `/v3/...` without producing a double slash.
    ///
    /// Returns `None` for anything that is not an absolute `http(s)` URL: a
    /// relative or scheme-less value would only fail much later, at login.
    pub fn normalize_url(raw: &str) -> Option<String> {
        let url = raw.trim().trim_end_matches('/');
        if url.is_empty() {
            return None;
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return None;
        }
        if url.len() <= "https://".len() {
            return None;
        }
        Some(url.to_string())
    }

    /// Where the effective URL came from, for diagnostics.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Source {
        Env,
        Custom,
        Default,
    }

    impl std::fmt::Display for Source {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let text = match self {
                Source::Env => ENV_OVERRIDE,
                Source::Custom => SETTINGS_FILE,
                Source::Default => "default",
            };
            f.write_str(text)
        }
    }

    /// Remote anisette server in effect, falling back to the default.
    ///
    /// Precedence: [`ENV_OVERRIDE`], then the stored setting, then the default.
    pub fn url(data_root: &Path) -> String {
        url_with_source(data_root).0
    }

    /// Same as [`url`], also reporting where the value came from.
    pub fn url_with_source(data_root: &Path) -> (String, Source) {
        if let Some(from_env) = std::env::var(ENV_OVERRIDE)
            .ok()
            .and_then(|value| normalize_url(&value))
        {
            return (from_env, Source::Env);
        }

        if let Some(stored) = load(data_root).url.as_deref().and_then(normalize_url) {
            return (stored, Source::Custom);
        }

        (DEFAULT_URL.to_string(), Source::Default)
    }

    fn load(data_root: &Path) -> Settings {
        std::fs::read_to_string(settings_path(data_root))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Set a custom server; `None` restores the default.
    ///
    /// The URL is normalized and validated up front so a typo fails here
    /// instead of surfacing as a confusing login error later.
    pub fn set_url(data_root: &Path, url: Option<&str>) -> Result<(), SetUrlError> {
        let url = match url {
            Some(raw) => Some(normalize_url(raw).ok_or(SetUrlError::InvalidUrl(raw.trim().to_string()))?),
            None => None,
        };

        let settings = Settings { url };
        let path = settings_path(data_root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&settings)?)?;
        Ok(())
    }

    #[derive(Debug)]
    pub enum SetUrlError {
        /// The value is not an absolute `http(s)` URL.
        InvalidUrl(String),
        Io(std::io::Error),
        Json(serde_json::Error),
    }

    impl std::fmt::Display for SetUrlError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                SetUrlError::InvalidUrl(url) => write!(
                    f,
                    "'{url}' is not a valid server URL; expected an absolute http:// or https:// URL"
                ),
                SetUrlError::Io(err) => write!(f, "{err}"),
                SetUrlError::Json(err) => write!(f, "{err}"),
            }
        }
    }

    impl std::error::Error for SetUrlError {}

    impl From<std::io::Error> for SetUrlError {
        fn from(err: std::io::Error) -> Self {
            SetUrlError::Io(err)
        }
    }

    impl From<serde_json::Error> for SetUrlError {
        fn from(err: serde_json::Error) -> Self {
            SetUrlError::Json(err)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn temp_root() -> PathBuf {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "plume-anisette-server-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        #[test]
        fn default_is_used_without_a_stored_value() {
            let root = temp_root();
            let (url, source) = url_with_source(&root);
            assert_eq!(url, DEFAULT_URL);
            assert_eq!(source, Source::Default);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn stored_value_wins_over_default() {
            let root = temp_root();
            set_url(&root, Some("https://example.test/")).unwrap();

            let (url, source) = url_with_source(&root);
            assert_eq!(url, "https://example.test");
            assert_eq!(source, Source::Custom);

            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn reset_restores_the_default() {
            let root = temp_root();
            set_url(&root, Some("https://example.test")).unwrap();
            set_url(&root, None).unwrap();

            assert_eq!(url_with_source(&root), (DEFAULT_URL.to_string(), Source::Default));
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn invalid_urls_are_rejected() {
            let root = temp_root();
            assert!(matches!(
                set_url(&root, Some("example.test")),
                Err(SetUrlError::InvalidUrl(_))
            ));
            assert!(matches!(
                set_url(&root, Some("ftp://example.test")),
                Err(SetUrlError::InvalidUrl(_))
            ));
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
