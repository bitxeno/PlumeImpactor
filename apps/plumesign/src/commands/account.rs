use std::io::Write;
use std::path::PathBuf;

use anyhow::{Ok, Result};
use clap::{Args, Subcommand};
use dialoguer::Select;

use plume_core::{
    auth::Account,
    developer::{DeveloperSession, qh::devices::DeviceType},
};
use plume_store::AccountStore;
use plume_utils::mask_email;

use crate::get_data_path;

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct AccountArgs {
    #[command(subcommand)]
    pub command: AccountCommands,
}

#[derive(Debug, Subcommand)]
#[command(arg_required_else_help = true)]
pub enum AccountCommands {
    /// Login to Apple Developer account
    Login(LoginArgs),
    /// Logout from Apple Developer account
    Logout(LogoutArgs),
    /// List all saved accounts
    List,
    /// Switch to a different account
    Switch(SwitchArgs),
    /// List certificates for a team
    Certificates(CertificatesArgs),
    /// List devices registered to the account
    Devices(DevicesArgs),
    /// Register a new device
    RegisterDevice(RegisterDeviceArgs),
    /// Delete a device from the account
    DeleteDevice(DeleteDeviceArgs),
    /// List all app IDs for a team
    AppIds(AppIdsArgs),
    /// List teams for the authenticated account
    Teams(TeamsArgs),
}

#[derive(Debug, Args)]
pub struct TeamsArgs {
    /// Email of the account to use
    #[arg(short = 'u', long = "username", value_name = "EMAIL")]
    pub username: Option<String>,
}

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct LoginArgs {
    /// Apple ID email
    #[arg(short = 'u', long = "username", value_name = "EMAIL")]
    pub username: Option<String>,
    /// Password (will prompt if not provided)
    #[arg(short = 'p', long = "password", value_name = "PASSWORD")]
    pub password: Option<String>,
}

#[derive(Debug, Args)]
pub struct LogoutArgs {
    /// Email of the account to logout
    #[arg(short = 'u', long = "username", value_name = "EMAIL")]
    pub username: Option<String>,
}

#[derive(Debug, Args)]
pub struct CertificatesArgs {
    /// Email of the account to use
    #[arg(short = 'u', long = "username", value_name = "EMAIL")]
    pub username: Option<String>,
    /// Team ID to list certificates for
    #[arg(short = 't', long = "team", value_name = "TEAM_ID")]
    pub team_id: Option<String>,
    /// Filter by certificate type (development, distribution)
    #[arg(long = "type", value_name = "TYPE")]
    pub cert_type: Option<String>,
}

#[derive(Debug, Args)]
pub struct DevicesArgs {
    /// Email of the account to use
    #[arg(short = 'u', long = "username", value_name = "EMAIL")]
    pub username: Option<String>,
    /// Team ID to list devices for
    #[arg(short = 't', long = "team", value_name = "TEAM_ID")]
    pub team_id: Option<String>,
    /// Filter by device platform (ios, tvos, watchos)
    #[arg(long = "platform", value_name = "PLATFORM")]
    pub platform: Option<String>,
}

#[derive(Debug, Args)]
pub struct RegisterDeviceArgs {
    /// Email of the account to use
    #[arg(short = 'u', long = "username", value_name = "EMAIL")]
    pub username: Option<String>,
    /// Team ID to list devices for
    #[arg(short = 't', long = "team", value_name = "TEAM_ID")]
    pub team_id: Option<String>,
    /// Device UDID
    #[arg(long = "udid", value_name = "UDID", required = true)]
    pub udid: String,
    /// Device name
    #[arg(short = 'n', long = "name", value_name = "NAME", required = true)]
    pub name: String,
    #[arg(long = "platform", value_name = "PLATFORM")]
    pub platform: Option<String>,
}

#[derive(Debug, Args)]
pub struct DeleteDeviceArgs {
    /// Apple ID email
    #[arg(short = 'u', long = "username", value_name = "EMAIL")]
    pub username: Option<String>,
    /// Team ID to delete device from
    #[arg(short = 't', long = "team", value_name = "TEAM_ID")]
    pub team_id: Option<String>,
    /// Device Identifier
    #[arg(
        short = 'i',
        long = "device-id",
        value_name = "DEVICE_ID",
        required = true
    )]
    pub device_id: String,
}

#[derive(Debug, Args)]
pub struct AppIdsArgs {
    /// Team ID to list app IDs for
    #[arg(short = 't', long = "team", value_name = "TEAM_ID")]
    pub team_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct SwitchArgs {
    /// Email of the account to switch to
    #[arg(value_name = "EMAIL", required = true)]
    pub email: String,
}

pub async fn execute(args: AccountArgs) -> Result<()> {
    match args.command {
        AccountCommands::Login(login_args) => login(login_args).await,
        AccountCommands::Logout(logout_args) => logout(logout_args).await,
        AccountCommands::List => list_accounts().await,
        AccountCommands::Switch(switch_args) => switch_account(switch_args).await,
        AccountCommands::Certificates(cert_args) => certificates(cert_args).await,
        AccountCommands::Devices(device_args) => devices(device_args).await,
        AccountCommands::RegisterDevice(register_args) => register_device(register_args).await,
        AccountCommands::DeleteDevice(delete_args) => delete_device(delete_args).await,
        AccountCommands::AppIds(app_id_args) => app_ids(app_id_args).await,
        AccountCommands::Teams(teams_args) => list_teams_command(teams_args).await,
    }
}

pub fn get_settings_path() -> PathBuf {
    get_data_path().join("accounts.json")
}

pub async fn get_authenticated_account(username: Option<String>) -> Result<DeveloperSession> {
    let settings_path = get_settings_path();
    let settings = AccountStore::load(&Some(settings_path.clone())).await?;

    let gsa_account = if let Some(user) = username {
        settings.get_account(&user).ok_or_else(|| {
            anyhow::anyhow!(
                "Account '{}' not found. Use 'plumesign account list' to see available accounts.",
                user
            )
        })?
        .clone()
    } else {
        settings
            .selected_account()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No account selected. Please login first using 'plumesign account login'"
                )
            })?
            .clone()
    };

    let anisette_config = crate::commands::anisette::build(gsa_account.email(), false);

    log::info!(
        "Restoring session for {}...",
        mask_email(gsa_account.email())
    );

    let session = DeveloperSession::new(
        gsa_account.adsid().clone(),
        gsa_account.xcode_gs_token().clone(),
        anisette_config,
    )
    .await?;

    Ok(session)
}

async fn login(args: LoginArgs) -> Result<()> {
    let tfa_closure = |req: plume_core::auth::TwoFactorRequest| -> std::result::Result<
        plume_core::auth::TwoFactorAction,
        String,
    > {
        use plume_core::auth::{TwoFactorAction, TwoFactorMethod};

        let can_use_sms = !req.trusted_phone_numbers.is_empty();
        match req.method {
            TwoFactorMethod::Sms => log::info!("Enter the code sent via SMS: "),
            TwoFactorMethod::Device if can_use_sms => {
                log::info!("Enter the code sent to your device, or type 'sms' to receive it by text message: ")
            }
            TwoFactorMethod::Device => log::info!("Enter 2FA code: "),
        }

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        let input = input.trim();

        if input.eq_ignore_ascii_case("sms") && can_use_sms {
            let id = if req.trusted_phone_numbers.len() == 1 {
                req.trusted_phone_numbers[0].id
            } else {
                let labels: Vec<String> = req
                    .trusted_phone_numbers
                    .iter()
                    .map(|p| format!("Phone ending in {}", p.last_two_digits))
                    .collect();
                let choice = Select::new()
                    .with_prompt("Send SMS to which number?")
                    .items(&labels)
                    .default(0)
                    .interact()
                    .map_err(|e| e.to_string())?;
                req.trusted_phone_numbers[choice].id
            };
            return std::result::Result::Ok(TwoFactorAction::SendSms(id));
        }

        std::result::Result::Ok(TwoFactorAction::SubmitCode(input.to_string()))
    };

    let username = if let Some(user) = args.username {
        user
    } else {
        log::info!("Enter Apple ID email: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    // The email is the account key in `accounts.json` and is known before
    // login, so the state can go straight into its final directory.
    let anisette_config = crate::commands::anisette::build(&username, true);

    let password = if let Some(pass) = args.password {
        pass
    } else {
        print!("Enter password: ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    let login_closure = || -> std::result::Result<(String, String), String> {
        std::result::Result::Ok((username.clone(), password.clone()))
    };

    println!("Logging in...");
    let logged_in = Account::login(login_closure, tfa_closure, anisette_config).await?;

    let settings_path = get_settings_path();
    let mut settings = AccountStore::load(&Some(settings_path.clone())).await?;
    settings
        .accounts_add_from_session(username, logged_in)
        .await?;

    log::info!("Successfully logged in and account saved.");

    Ok(())
}

async fn logout(args: LogoutArgs) -> Result<()> {
    let settings_path = get_settings_path();
    let mut settings = AccountStore::load(&Some(settings_path.clone())).await?;

    let email = if let Some(user) = args.username {
        if settings.get_account(&user).is_none() {
            return Err(anyhow::anyhow!(
                "Account '{}' not found. Use 'plumesign account list' to see available accounts.",
                user
            ));
        }
        user
    } else {
        settings
            .selected_account()
            .ok_or_else(|| anyhow::anyhow!("No account currently logged in"))?
            .email()
            .clone()
    };

    // Anisette state is intentionally kept: logging out is not a request to
    // discard the device identity or the provisioned adi, so logging back in
    // reuses both.  Only `reset-anisette` discards them.
    settings.accounts_remove(&email).await?;

    log::info!("Successfully logged out and removed account.");

    Ok(())
}

async fn certificates(args: CertificatesArgs) -> Result<()> {
    let session = get_authenticated_account(args.username).await?;

    let team_id = if args.team_id.is_none() {
        teams(&session).await?
    } else {
        args.team_id.unwrap()
    };

    let certificates = session.qh_list_certs(&team_id).await?.certificates;

    log::info!("You have {} certificates registered.", certificates.len());
    log::info!("Currently registered certificates:");
    for cert in certificates.iter() {
        log::info!(
            " - `{}` with the serial number `{}`, from the machine named `{}`.",
            cert.name,
            cert.serial_number,
            cert.machine_name.as_deref().unwrap_or("")
        );
    }

    Ok(())
}

async fn devices(args: DevicesArgs) -> Result<()> {
    let session = get_authenticated_account(args.username).await?;

    let team_id = if args.team_id.is_none() {
        teams(&session).await?
    } else {
        args.team_id.unwrap()
    };

    let p = session.qh_list_devices(&team_id).await?.devices;

    log::info!("{:#?}", p);

    Ok(())
}

async fn register_device(args: RegisterDeviceArgs) -> Result<()> {
    let session = get_authenticated_account(args.username).await?;

    let team_id = if args.team_id.is_none() {
        teams(&session).await?
    } else {
        args.team_id.unwrap()
    };

    let device_type = args
        .platform
        .as_ref()
        .map(|p| DeviceType::from_string(p))
        .unwrap_or(DeviceType::Any);
    let p = session
        .qh_add_device(&team_id, &args.name, &args.udid, Some(device_type))
        .await?
        .device;

    log::info!("{:#?}", p);

    Ok(())
}

async fn delete_device(args: DeleteDeviceArgs) -> Result<()> {
    let session = get_authenticated_account(args.username).await?;

    let team_id = if args.team_id.is_none() {
        teams(&session).await?
    } else {
        args.team_id.unwrap()
    };

    session.qh_delete_device(&team_id, &args.device_id).await?;

    log::info!(
        "Successfully deleted device with Device ID: {}",
        args.device_id
    );

    Ok(())
}

pub async fn teams(session: &DeveloperSession) -> Result<String> {
    let teams = session.qh_list_teams().await?.teams;

    if teams.is_empty() {
        return Err(anyhow::anyhow!("No teams found for account."));
    }

    // interact() will trigger `not a terminal` error in docker non-interactive environments
    // so if there's only one team, just return it without prompting
    if teams.len() > 0 {
        return Ok(teams[0].team_id.clone());
    }

    let team_names: Vec<String> = teams
        .iter()
        .map(|t| format!("{} ({})", t.name, t.team_id))
        .collect();

    let selection = Select::new().items(&team_names).default(0).interact()?;

    Ok(teams[selection].team_id.clone())
}

pub async fn app_ids(args: AppIdsArgs) -> Result<()> {
    let session = get_authenticated_account(None).await?;

    let team_id = if args.team_id.is_none() {
        teams(&session).await?
    } else {
        args.team_id.unwrap()
    };

    let p = session.v1_list_app_ids(&team_id, None).await?.data;

    log::info!("{:#?}", p);

    Ok(())
}

async fn list_teams_command(args: TeamsArgs) -> Result<()> {
    let session = get_authenticated_account(args.username).await?;

    let teams = session.qh_list_teams().await?.teams;

    if teams.is_empty() {
        log::info!("No teams found for account.");
        return Ok(());
    }

    log::info!("Teams:");
    for t in teams.iter() {
        log::info!(" - `{}`, with ID `{}`.", t.name, t.team_id);
    }

    Ok(())
}

async fn list_accounts() -> Result<()> {
    let settings_path = get_settings_path();
    let settings = AccountStore::load(&Some(settings_path)).await?;

    let accounts = settings.accounts();

    if accounts.is_empty() {
        log::info!("No accounts found. Use 'account login' to add an account.");
        return Ok(());
    }

    let selected_email = settings.selected_account().map(|a| a.email().clone());

    log::info!("Saved accounts:");
    for (email, account) in accounts {
        let selected = if Some(email) == selected_email.as_ref() {
            "(selected)"
        } else {
            ""
        };

        log::info!(" [{}] {} {}", account.first_name(), email, selected);
    }

    Ok(())
}

async fn switch_account(args: SwitchArgs) -> Result<()> {
    let settings_path = get_settings_path();
    let mut settings = AccountStore::load(&Some(settings_path)).await?;

    if settings.get_account(&args.email).is_none() {
        return Err(anyhow::anyhow!(
            "Account '{}' not found. Use 'account list' to see available accounts.",
            args.email
        ));
    }

    settings.account_select(&args.email).await?;

    log::info!("Switched to account: {}", args.email);

    Ok(())
}
