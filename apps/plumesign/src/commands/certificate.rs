use anyhow::Result;
use clap::{Args, Subcommand};

use crate::commands::account::{get_authenticated_account, teams};

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct CertificateArgs {
    #[command(subcommand)]
    pub command: CertificateCommands,
}

#[derive(Debug, Subcommand)]
#[command(arg_required_else_help = true)]
pub enum CertificateCommands {
    /// List certificates for a team
    List(ListArgs),
    /// Revoke a certificate by serial number
    Revoke(RevokeArgs),
}

#[derive(Debug, Args)]
pub struct ListArgs {
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
pub struct RevokeArgs {
    /// Email of the account to use
    #[arg(short = 'u', long = "username", value_name = "EMAIL")]
    pub username: Option<String>,
    /// Team ID containing the certificate (will prompt if not provided)
    #[arg(short = 't', long = "team", value_name = "TEAM_ID")]
    pub team_id: Option<String>,
    /// Serial number of the certificate to revoke
    #[arg(
        short = 's',
        long = "serial-number",
        value_name = "SERIAL",
        required = true
    )]
    pub serial_number: String,
}

pub async fn execute(args: CertificateArgs) -> Result<()> {
    match args.command {
        CertificateCommands::List(list_args) => list(list_args).await,
        CertificateCommands::Revoke(revoke_args) => revoke(revoke_args).await,
    }
}

async fn list(args: ListArgs) -> Result<()> {
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
            " - `{}` with the serial number `{}`, expires `{:?}`, from the machine named `{}`.",
            cert.name,
            cert.serial_number,
            cert.expiration_date,
            cert.machine_name.as_deref().unwrap_or("")
        );
    }

    Ok(())
}

async fn revoke(args: RevokeArgs) -> Result<()> {
    let session = get_authenticated_account(args.username).await?;

    let team_id = if args.team_id.is_none() {
        teams(&session).await?
    } else {
        args.team_id.unwrap()
    };

    // Ensure certificate with given serial number exists
    let certificates = session.qh_list_certs(&team_id).await?.certificates;

    let found = certificates
        .iter()
        .any(|c| c.serial_number == args.serial_number);

    if !found {
        return Err(anyhow::anyhow!("No matching certificate found"));
    }

    log::info!(
        "Revoking certificate with serial number: {}",
        args.serial_number
    );

    let resp = session
        .qh_revoke_cert(&team_id, &args.serial_number)
        .await?;

    if let Some(s) = resp.result_string {
        log::info!("Revoke response: {}", s);
    } else if let Some(u) = resp.user_string {
        log::info!("Revoke response: {}", u);
    } else {
        log::info!("Certificate revoke request completed (no message).");
    }

    Ok(())
}
