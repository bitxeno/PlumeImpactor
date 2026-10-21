use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use omnisette::AnisetteConfiguration;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

pub(crate) const CANDIDATES_VERSION: u32 = 1;

const STORE_VERSION: u32 = 1;
const FILE_NAME: &str = "client_identity.json";

static STORE_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum AccountIdentity {
    Resolved { client_info: String },
    Checked,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientIdentityStore {
    #[serde(default = "store_version")]
    version: u32,
    #[serde(default = "candidates_version")]
    candidates_version: u32,
    #[serde(default)]
    accounts: HashMap<String, AccountIdentity>,
}

impl Default for ClientIdentityStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            candidates_version: CANDIDATES_VERSION,
            accounts: HashMap::new(),
        }
    }
}

impl ClientIdentityStore {
    fn normalize(&mut self) {
        if self.version == 0 {
            self.version = STORE_VERSION;
        }

        if self.candidates_version != CANDIDATES_VERSION {
            self.accounts
                .retain(|_, identity| !matches!(identity, AccountIdentity::Checked));
            self.candidates_version = CANDIDATES_VERSION;
        }
    }
}

fn store_version() -> u32 {
    STORE_VERSION
}

fn candidates_version() -> u32 {
    CANDIDATES_VERSION
}

pub(crate) fn path(config: &AnisetteConfiguration) -> Option<PathBuf> {
    let base = config.configuration_path();
    if base.as_os_str().is_empty() {
        None
    } else {
        Some(base.join(FILE_NAME))
    }
}

pub(crate) async fn lookup(path: &Path, email: &str) -> Option<AccountIdentity> {
    let _guard = STORE_LOCK.lock().await;
    let mut store = read(path).await;
    store.normalize();
    store.accounts.get(email).cloned()
}

pub(crate) async fn record(path: &Path, email: &str, identity: AccountIdentity) {
    let _guard = STORE_LOCK.lock().await;
    let mut store = read(path).await;
    store.normalize();

    if store.accounts.get(email) == Some(&identity) {
        return;
    }

    store.accounts.insert(email.to_owned(), identity);

    if let Err(err) = write(path, &store).await {
        log::warn!(
            "Failed to save client identity sidecar {}: {}",
            path.display(),
            err
        );
    }
}

async fn read(path: &Path) -> ClientIdentityStore {
    match tokio::fs::read_to_string(path).await {
        Ok(contents) => match serde_json::from_str(&contents) {
            Ok(store) => store,
            Err(err) => {
                log::warn!(
                    "Failed to parse client identity sidecar {}: {}",
                    path.display(),
                    err
                );
                ClientIdentityStore::default()
            }
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => ClientIdentityStore::default(),
        Err(err) => {
            log::warn!(
                "Failed to read client identity sidecar {}: {}",
                path.display(),
                err
            );
            ClientIdentityStore::default()
        }
    }
}

async fn write(path: &Path, store: &ClientIdentityStore) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let temp_path = path.with_file_name(format!(".{}.{}.tmp", FILE_NAME, uuid::Uuid::new_v4()));
    let contents = serde_json::to_vec_pretty(store).map_err(io::Error::other)?;

    tokio::fs::write(&temp_path, contents).await?;

    if let Err(err) = tokio::fs::rename(&temp_path, path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(err);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_states_have_the_expected_json_shape() {
        let resolved = serde_json::to_value(AccountIdentity::Resolved {
            client_info: "client-info".to_string(),
        })
        .unwrap();
        assert_eq!(
            resolved,
            serde_json::json!({ "state": "resolved", "client_info": "client-info" })
        );

        let checked = serde_json::to_value(AccountIdentity::Checked).unwrap();
        assert_eq!(checked, serde_json::json!({ "state": "checked" }));
    }

    #[test]
    fn checked_entries_are_dropped_when_candidate_version_changes() {
        let mut store = ClientIdentityStore {
            version: STORE_VERSION,
            candidates_version: CANDIDATES_VERSION - 1,
            accounts: HashMap::from([
                ("old@example.com".to_string(), AccountIdentity::Checked),
                (
                    "resolved@example.com".to_string(),
                    AccountIdentity::Resolved {
                        client_info: "client-info".to_string(),
                    },
                ),
            ]),
        };

        store.normalize();

        assert!(!store.accounts.contains_key("old@example.com"));
        assert!(store.accounts.contains_key("resolved@example.com"));
        assert_eq!(store.candidates_version, CANDIDATES_VERSION);
    }

    #[test]
    fn records_and_preserves_other_accounts() {
        let dir =
            std::env::temp_dir().join(format!("plume-client-identity-{}", uuid::Uuid::new_v4()));
        let path = dir.join(FILE_NAME);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            record(
                &path,
                "a@example.com",
                AccountIdentity::Resolved {
                    client_info: "macos".to_string(),
                },
            )
            .await;
            record(&path, "b@example.com", AccountIdentity::Checked).await;

            assert_eq!(
                lookup(&path, "a@example.com").await,
                Some(AccountIdentity::Resolved {
                    client_info: "macos".to_string()
                })
            );
            assert_eq!(
                lookup(&path, "b@example.com").await,
                Some(AccountIdentity::Checked)
            );
            assert_eq!(lookup(&path, "c@example.com").await, None);
        });

        std::fs::remove_dir_all(dir).unwrap();
    }
}
