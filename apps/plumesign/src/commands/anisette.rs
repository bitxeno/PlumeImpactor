//! Anisette server selection and per-account state management.
//!
//! The remote anisette server is a user-level setting stored next to
//! `accounts.json` (see [`plume_store::anisette_paths::server`]), so it
//! survives independent of any single account.

use anyhow::Result;
use clap::{Args, Subcommand};

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
    /// Email of the account whose anisette data should be removed
    #[arg(short = 'u', long = "username", value_name = "EMAIL", required = true)]
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

async fn remove(args: RemoveArgs) -> Result<()> {
    let email = account_email(&args.username).await?;
    plume_store::anisette_paths::remove_account_state(&get_data_path(), &email)?;

    log::info!("Anisette data removed for {}.", mask_email(&email));
    Ok(())
}
