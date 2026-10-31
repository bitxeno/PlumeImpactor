//! Anisette server selection and per-account state management.
//!
//! The remote anisette server is a user-level setting stored next to
//! `accounts.json` (see [`plume_store::anisette_paths::server`]), so it
//! survives independent of any single account.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use plume_store::AccountStore;

use crate::get_data_path;
use plume_utils::mask_email;

#[derive(Debug, Args)]
#[command(arg_required_else_help = true, about = "Anisette server and state")]
pub struct AnisetteArgs {
    #[command(subcommand)]
    pub command: AnisetteCommands,
}

#[derive(Debug, Subcommand)]
pub enum AnisetteCommands {
    /// Show or change the remote anisette server
    Server(ServerArgs),
    /// Reset an account's anisette data (new device identity, requires re-login)
    Reset(ResetArgs),
    /// Remove an account's anisette data directory
    Remove(RemoveArgs),
    /// List accounts with stored anisette data
    List,
}

#[derive(Debug, Args)]
pub struct ServerArgs {
    /// Set the remote anisette server URL
    #[arg(long = "set", value_name = "URL")]
    pub set: Option<String>,

    /// Restore the default server
    #[arg(long = "reset", conflicts_with = "set")]
    pub reset: bool,
}

#[derive(Debug, Args)]
pub struct ResetArgs {
    /// Email of the account to reset (required)
    #[arg(short = 'u', long = "username", value_name = "EMAIL", required = true)]
    pub username: String,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Account email, or the directory name shown by `anisette list` when
    /// the state has no recoverable email
    #[arg(short = 'u', long = "username", value_name = "EMAIL|DIR", required = true)]
    pub username: String,
}

/// Build the anisette configuration used by every command.
///
/// `login` marks the flow as a login, which lets a legacy state adopt the
/// server identity once.  Existing per-account state is always reused.
pub fn build(email: &str, login: bool) -> plume_core::AnisetteConfiguration {
    plume_core::AnisetteConfiguration::default()
        .set_configuration_path(get_data_path())
        .set_account_id(email.to_string())
        .set_anisette_url_v3(plume_store::anisette_paths::server::url(&get_data_path()))
        .set_login_mode(login)
}

pub async fn execute(args: AnisetteArgs) -> Result<()> {
    match args.command {
        AnisetteCommands::Server(server_args) => server(server_args).await,
        AnisetteCommands::Reset(reset_args) => reset(reset_args).await,
        AnisetteCommands::Remove(remove_args) => remove(remove_args).await,
        AnisetteCommands::List => list().await,
    }
}

async fn server(args: ServerArgs) -> Result<()> {
    let data_root = get_data_path();

    if args.reset {
        plume_store::anisette_paths::server::set_url(&data_root, None)?;
        log::info!(
            "Anisette server reset to default: {}",
            plume_store::anisette_paths::server::DEFAULT_URL
        );
    } else if let Some(url) = args.set {
        plume_store::anisette_paths::server::set_url(&data_root, Some(&url))?;
        log::info!(
            "Anisette server set to: {}",
            plume_store::anisette_paths::server::url(&data_root)
        );
        log::info!(
            "Existing anisette data was provisioned against the previous server. \
             If requests start failing, reset the account with \
             `plumesign anisette reset -u <EMAIL>`."
        );
    }

    // Always report the effective endpoint and where it came from, so a
    // mismatch (for example an env override masking the stored value) is
    // visible instead of silently changing which server is contacted.
    let (effective, effective_source) =
        plume_store::anisette_paths::server::url_with_source(&data_root);
    log::info!("Anisette server: {effective} (source: {effective_source})");

    if matches!(
        effective_source,
        plume_store::anisette_paths::server::Source::Env
    ) {
        log::info!(
            "{} is set, so it takes precedence over the stored setting.",
            plume_store::anisette_paths::server::ENV_OVERRIDE
        );
    }

    Ok(())
}

async fn account_email(username: &str) -> Result<String> {
    let settings_path = crate::commands::account::get_settings_path();
    let settings = plume_store::AccountStore::load(&Some(settings_path)).await?;

    Ok(settings
        .get_account(username)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Account '{}' not found. Use 'plumesign account list' to see available accounts.",
                username
            )
        })?
        .email()
        .clone())
}

async fn reset(args: ResetArgs) -> Result<()> {
    let email = account_email(&args.username).await?;
    plume_store::anisette_paths::reset_account_state(&get_data_path(), &email)?;

    log::info!(
        "Anisette data reset for {}. A new device identity will be generated on next use; \
         you need to log in again.",
        mask_email(&email)
    );

    Ok(())
}

/// Resolve the `-u` value to the directory name of the anisette state to
/// delete.
///
/// Accepts the account email, or the hashed directory name as displayed by
/// `anisette list` for states whose email is unrecoverable.  A hash that
/// matches no known account is kept as-is so orphaned directories created by
/// failed logins can still be removed.
fn removal_key(
    data_root: &Path,
    username: &str,
    accounts: &AccountStore,
) -> Result<String> {
    let key = username.trim();
    if key.is_empty() {
        anyhow::bail!("Provide the account email used to create its Anisette data.");
    }

    if key.contains('@') {
        // Use the canonical email from accounts.json when available. Anisette
        // data can also belong to an account that has never been saved/logged
        // in, so the supplied email itself is a valid directory key fallback.
        let email = accounts
            .accounts()
            .values()
            .find(|account| account.email().trim().eq_ignore_ascii_case(key))
            .map(|account| account.email().clone())
            .unwrap_or_else(|| key.to_owned());
        return Ok(plume_core::account_dir_name(&email));
    }

    // Not an email: treat it as the directory name shown by `anisette list`.
    // Verify the caller passed a real directory so a typo cannot silently
    // report success after deleting nothing.
    let directory = data_root
        .join(plume_store::anisette_paths::ANISETTE_DIR)
        .join(key);
    if !directory.join("state.plist").is_file() {
        anyhow::bail!(
            "No Anisette data found for '{}'. Use 'plumesign anisette list' to see the exact directory names.",
            key
        );
    }
    Ok(key.to_string())
}

async fn remove(args: RemoveArgs) -> Result<()> {
    let data_root = get_data_path();
    let settings_path = crate::commands::account::get_settings_path();
    let settings = AccountStore::load(&Some(settings_path)).await?;
    let key = removal_key(&data_root, &args.username, &settings)?;
    plume_store::anisette_paths::remove_account_dir(&data_root, &key)?;

    log::info!("Anisette data removed for {}.", mask_email(&key));
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct AnisetteAccountEntry {
    directory: String,
    email: Option<String>,
    first_name: Option<String>,
    team_id: Option<String>,
}

fn anisette_accounts(
    data_root: &Path,
    accounts: &AccountStore,
) -> Result<Vec<AnisetteAccountEntry>> {
    let anisette_root = data_root.join(plume_store::anisette_paths::ANISETTE_DIR);
    if !anisette_root.exists() {
        return Ok(Vec::new());
    }

    let mut account_by_directory = HashMap::new();
    let mut account_by_email = HashMap::new();
    for account in accounts.accounts().values() {
        account_by_directory.insert(plume_core::account_dir_name(account.email()), account);
        account_by_email.insert(account.email().trim().to_lowercase(), account);
    }

    let mut directories = fs::read_dir(&anisette_root)
        .with_context(|| format!("failed to read {}", anisette_root.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    directories.sort_by_key(|entry| entry.file_name());

    let mut result = Vec::new();
    for directory in directories {
        if !directory.file_type()?.is_dir() {
            continue;
        }
        let directory_name = directory.file_name().to_string_lossy().into_owned();
        let state_path = directory.path().join("state.plist");
        if !state_path.is_file() {
            continue;
        }

        let state: plist::Value = plist::from_file(&state_path)
            .with_context(|| format!("failed to read {}", state_path.display()))?;
        let state_email = state
            .as_dictionary()
            .and_then(|dict| dict.get("email"))
            .and_then(plist::Value::as_string)
            .map(str::to_owned);

        // Older state files have no email. Recover it for display by matching
        // the hashed directory name against accounts.json; do not rewrite the
        // existing plist as a side effect of listing.
        let account = match state_email.as_deref() {
            Some(email) => account_by_email.get(&email.trim().to_lowercase()).copied(),
            None => account_by_directory.get(&directory_name).copied(),
        };
        let email = state_email.or_else(|| account.map(|account| account.email().clone()));

        result.push(AnisetteAccountEntry {
            directory: directory_name,
            email,
            first_name: account.map(|account| account.first_name().clone()),
            team_id: account.map(|account| account.team_id().clone()),
        });
    }
    Ok(result)
}

async fn list() -> Result<()> {
    let data_root = get_data_path();
    let accounts = AccountStore::load(&Some(crate::commands::account::get_settings_path())).await?;
    let entries = anisette_accounts(&data_root, &accounts)?;

    if entries.is_empty() {
        println!("No accounts with Anisette data found.");
        return Ok(());
    }

    println!("Accounts with Anisette data:");
    println!("{:<32}  {:<20}  TEAM ID", "ACCOUNT", "NAME");
    for entry in entries {
        println!(
            "{:<32}  {:<20}  {}",
            entry.email.as_deref().unwrap_or(&entry.directory),
            entry.first_name.as_deref().unwrap_or("-"),
            entry
                .team_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .unwrap_or("-")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("plumesign-anisette-list-{}", uuid::Uuid::new_v4()))
    }

    fn account_store(root: &Path) -> AccountStore {
        fs::create_dir_all(root).unwrap();
        let path = root.join("accounts.json");
        fs::write(
            &path,
            r#"{
                "accounts": {
                    "old@example.com": {
                        "email": "old@example.com",
                        "first_name": "Old User",
                        "adsid": "adsid-old",
                        "xcode_gs_token": "token-old",
                        "team_id": "TEAMOLD123"
                    },
                    "new@example.com": {
                        "email": "new@example.com",
                        "first_name": "New User",
                        "adsid": "adsid-new",
                        "xcode_gs_token": "token-new",
                        "team_id": "TEAMNEW456"
                    }
                }
            }"#,
        )
        .unwrap();
        AccountStore::load_sync(&Some(path)).unwrap()
    }

    fn write_state(path: &Path, email: Option<&str>) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut dict = plist::Dictionary::new();
        if let Some(email) = email {
            dict.insert("email".into(), plist::Value::String(email.into()));
        }
        plist::to_file_xml(path, &plist::Value::Dictionary(dict)).unwrap();
    }

    #[test]
    fn list_recovers_missing_email_and_team_from_accounts_json() {
        let root = temp_dir();
        let store = account_store(&root);
        let dir = root
            .join(plume_store::anisette_paths::ANISETTE_DIR)
            .join(plume_core::account_dir_name("old@example.com"));
        let state_path = dir.join("state.plist");
        write_state(&state_path, None);

        let entries = anisette_accounts(&root, &store).unwrap();
        assert_eq!(
            entries,
            vec![AnisetteAccountEntry {
                directory: plume_core::account_dir_name("old@example.com"),
                email: Some("old@example.com".into()),
                first_name: Some("Old User".into()),
                team_id: Some("TEAMOLD123".into()),
            }]
        );

        let state: plist::Value = plist::from_file(&state_path).unwrap();
        assert!(state.as_dictionary().unwrap().get("email").is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn list_prefers_email_stored_in_state() {
        let root = temp_dir();
        let store = account_store(&root);
        let dir = root
            .join(plume_store::anisette_paths::ANISETTE_DIR)
            .join("state-directory");
        write_state(&dir.join("state.plist"), Some("new@example.com"));

        let entries = anisette_accounts(&root, &store).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].email.as_deref(), Some("new@example.com"));
        assert_eq!(entries[0].first_name.as_deref(), Some("New User"));
        assert_eq!(entries[0].team_id.as_deref(), Some("TEAMNEW456"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn list_ignores_directories_without_state_data() {
        let root = temp_dir();
        let store = account_store(&root);
        let empty_dir = root
            .join(plume_store::anisette_paths::ANISETTE_DIR)
            .join(plume_core::account_dir_name("old@example.com"));
        fs::create_dir_all(empty_dir).unwrap();

        assert!(anisette_accounts(&root, &store).unwrap().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remove_accepts_email_of_account_not_saved_in_accounts_json() {
        let root = temp_dir();
        let store = account_store(&root);
        let email = "never-logged-in@example.com";
        let account_state = root
            .join(plume_store::anisette_paths::ANISETTE_DIR)
            .join(plume_core::account_dir_name(email));
        fs::create_dir_all(&account_state).unwrap();
        fs::write(account_state.join("state.plist"), b"anisette data").unwrap();

        let key = removal_key(&root, email, &store).unwrap();
        assert_eq!(key, plume_core::account_dir_name(email));
        plume_store::anisette_paths::remove_account_dir(&root, &key).unwrap();
        assert!(!account_state.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remove_accepts_directory_name_of_orphaned_state() {
        let root = temp_dir();
        let store = account_store(&root);
        // A failed login can leave state behind for an account that never
        // made it into accounts.json, so only the hashed directory is known.
        let directory = "deadbeefdeadbeefdeadbeefdeadbeef";
        let account_state = root
            .join(plume_store::anisette_paths::ANISETTE_DIR)
            .join(directory);
        fs::create_dir_all(&account_state).unwrap();
        fs::write(account_state.join("state.plist"), b"orphan state").unwrap();

        let key = removal_key(&root, directory, &store).unwrap();
        assert_eq!(key, directory);
        plume_store::anisette_paths::remove_account_dir(&root, &key).unwrap();
        assert!(!account_state.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remove_rejects_unknown_non_email_key() {
        let root = temp_dir();
        let store = account_store(&root);

        assert!(removal_key(&root, "no-such-directory", &store).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remove_maps_known_email_to_its_directory() {
        let root = temp_dir();
        let store = account_store(&root);

        let key = removal_key(&root, "Old@Example.com", &store).unwrap();
        assert_eq!(key, plume_core::account_dir_name("old@example.com"));
        fs::remove_dir_all(root).unwrap();
    }
}
