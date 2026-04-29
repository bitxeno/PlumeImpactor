use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};
use plume_core::{CertificateIdentity, MobileProvision, developer::qh::devices::DeviceType};
use plume_utils::{Bundle, Package, Signer, SignerMode, SignerOptions};
use std::fs;
use std::{net::IpAddr, str::FromStr};

use crate::{
    commands::account::{get_authenticated_account, teams},
    get_data_path,
};

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct SignArgs {
    /// Path to the app bundle or package to sign (.app or .ipa)
    #[arg(long, short, value_name = "PACKAGE")]
    pub package: PathBuf,
    /// PEM files for certificate and private key
    #[arg(long = "pem", value_name = "PEM", num_args = 1..)]
    pub pem_files: Option<Vec<PathBuf>>,
    /// Use Apple ID credentials for signing
    #[arg(long = "apple-id")]
    pub apple_id: bool,
    /// Specify account email to use
    #[arg(short = 'u', long = "username", value_name = "EMAIL")]
    pub username: Option<String>,
    /// Provisioning profile files to embed
    #[arg(long = "provision", value_name = "PROVISION")]
    pub provisioning_files: Option<PathBuf>,
    /// Custom bundle identifier to set
    #[arg(long = "custom-identifier", value_name = "BUNDLE_ID")]
    pub bundle_identifier: Option<String>,
    /// Custom bundle name to set
    #[arg(long = "custom-name", value_name = "NAME")]
    pub name: Option<String>,
    /// Custom bundle version to set
    #[arg(long = "custom-version", value_name = "VERSION")]
    pub version: Option<String>,
    /// Perform ad-hoc signing (no certificate required)
    #[arg(long, short, num_args = 1..)]
    pub tweaks: Option<Vec<PathBuf>>,
    /// shallow mode means not to recurse into sign nested bundles.
    #[arg(long)]
    pub shallow: bool,
    /// Register device and install after signing
    #[arg(long)]
    pub register_and_install: bool,
    /// Device UDID to register and install to (will prompt if not provided)
    #[arg(long, value_name = "UDID")]
    pub udid: Option<String>,
    /// Device IP address
    #[arg(long = "ip", value_name = "IP")]
    pub ip: String,
    /// Device pairing service port
    #[arg(long = "port", value_name = "PORT")]
    pub port: u16,
    #[arg(long)]
    pub pairing_file: Option<String>,
    /// Output path for signed .ipa (only for .ipa input)
    #[arg(long, short, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,
    /// Output path for provisioning profile (exports the first embedded profile)
    #[arg(long, value_name = "PROVISION_OUTPUT")]
    pub output_provision: Option<PathBuf>,
    /// Remove app extensions before signing
    #[arg(long)]
    pub remove_extensions: bool,
    /// Refresh the app on the device
    #[arg(long)]
    pub refresh: bool,
}

pub async fn execute(args: SignArgs) -> Result<()> {
    if !args.package.is_dir() && !args.apple_id && args.output.is_none() {
        return Err(anyhow::anyhow!(
            "-o/--output is required when signing an .ipa without --apple-id (ad-hoc mode)."
        ));
    }
    let pairing_file = if let Some(pairing_file) = args.pairing_file.as_deref() {
        std::path::PathBuf::from(pairing_file)
    } else if let Some(udid) = args.udid.as_deref() {
        get_data_path()
            .join("pairing_files")
            .join(format!("{}.plist", udid))
    } else {
        return Err(anyhow::anyhow!(
            "pairing file is required when ip and port are provided"
        ));
    };
    let ip = IpAddr::from_str(&args.ip)
        .map_err(|e| anyhow::anyhow!("Invalid IP '{}': {}", args.ip, e))?;
    let host_name = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "plumesign".to_string());

    let mut rpf = RpPairingFile::read_from_file(&pairing_file).await?;
    let conn = tokio::net::TcpStream::connect((ip, args.port)).await?;
    let conn = RpPairingSocket::new(conn);
    let mut rpc = RemotePairingClient::new(conn, &host_name, &mut rpf);

    let (mut handle, mut handshake) = rpc.start_tunnel(&args.ip).await?;

    use plume_utils::Device;
    let device = if args.register_and_install {
        Some(Device {
            name: handshake
                .properties
                .get("DeviceClass")
                .and_then(|v| v.as_string())
                .unwrap_or_default()
                .to_string(),
            udid: handshake
                .properties
                .get("UniqueDeviceID")
                .and_then(|v| v.as_string())
                .unwrap_or_default()
                .to_string(),
            device_id: 0,
            usbmuxd_device: None,
            is_mac: false,
        })
    } else {
        None
    };

    let mut options = SignerOptions {
        custom_identifier: args.bundle_identifier,
        custom_name: args.name,
        custom_version: args.version,
        tweaks: args.tweaks,
        shallow: args.shallow,
        ..Default::default()
    };
    options.embedding.remove_extensions = args.remove_extensions;

    let (bundle, package) = if args.package.is_dir() {
        log::warn!("⚠️  Signing bundle in place: {}", args.package.display());
        if args.output.is_some() {
            log::warn!(
                "Note: -o/--output flag is ignored for .app bundles (in-place signing only)"
            );
        }
        (Bundle::new(&args.package)?, None)
    } else {
        let pkg = Package::new(args.package.clone())?;
        let bundle = pkg.get_package_bundle()?;
        (bundle, Some(pkg))
    };

    if let Ok(app) = bundle.detect_app() {
        log::info!("Detected app type: {:?}", app);
        options.app = app;
    }

    let (mut signer, team_id_opt) = if let Some(ref pem_files) = args.pem_files {
        let cert_identity = CertificateIdentity::new_with_paths(Some(pem_files.clone())).await?;

        options.mode = SignerMode::Pem;
        (Signer::new(Some(cert_identity), options), None)
    } else if args.apple_id {
        let session = get_authenticated_account(args.username.clone()).await?;
        let team_id = teams(&session).await?;
        let cert_identity = CertificateIdentity::new_with_session(
            &session,
            get_data_path(),
            None,
            &team_id,
            false,
            None,
        )
        .await?;

        options.mode = SignerMode::Pem;
        (
            Signer::new(Some(cert_identity), options),
            Some((session, team_id)),
        )
    } else {
        options.mode = SignerMode::Adhoc;
        (Signer::new(None, options), None)
    };

    if let Some(provision_path) = args.provisioning_files {
        let prov = MobileProvision::load_with_path(&provision_path)?;
        signer.provisioning_files.push(prov.clone());
    }

    if let Some((session, team_id)) = team_id_opt {
        signer
            .modify_bundle(&bundle, &Some(team_id.clone()))
            .await?;

        if let Some(ref dev) = device {
            log::info!("Registering device: {} ({})", dev.name, dev.udid);
            let device_type = DeviceType::from_string(&dev.name);
            session
                .qh_ensure_device(&team_id, &dev.name, &dev.udid, Some(device_type))
                .await?;
        }

        if args.refresh {
            signer
                .register_bundle(&bundle, &session, &team_id, false)
                .await?;

            log::info!("Skip signing while in refresh mode");
            if let Some(ref dev) = device {
                log::info!("Installing to device: {}", dev.name);
                for provision in &signer.provisioning_files {
                    dev.install_profile_rsd(&mut handle, &mut handshake, provision)
                        .await?
                }
                log::info!("Installation complete!");
            }
        } else {
            signer
                .register_bundle(&bundle, &session, &team_id, false)
                .await?;
            signer.sign_bundle(&bundle).await?;

            if let Some(dev) = device {
                log::info!("Installing to device: {}", dev.name);
                log::info!("Prepare to archive bundle for installation...");
                let archived_path = Package::archive_bundle_dir(&bundle.bundle_dir())?;
                log::info!("Archiving complete. Starting upload to device...");
                dev.install_app_rsd(
                    &mut handle,
                    &mut handshake,
                    &archived_path,
                    |progress| async move {
                        log::info!("Installation progress: {}%", progress);
                    },
                )
                .await?;

                fs::remove_dir_all(&archived_path).ok();
                log::info!("Installation complete!");
            }
        }
    } else {
        signer.modify_bundle(&bundle, &None).await?;
        signer.sign_bundle(&bundle).await?;

        if let Some(dev) = device {
            log::info!("Installing to device: {}", dev.name);
            let archived_path = Package::archive_bundle_dir(&bundle.bundle_dir())?;
            dev.install_app_rsd(
                &mut handle,
                &mut handshake,
                &archived_path,
                |progress| async move {
                    log::info!("Installation progress: {}%", progress);
                },
            )
            .await?;

            fs::remove_dir_all(&archived_path).ok();
            log::info!("Installation complete!");
        }
    }

    if let Some(pkg) = package {
        if let Some(output_path) = args.output {
            let archived_path = pkg.get_archive_based_on_path(&bundle.bundle_dir())?;
            tokio::fs::copy(&archived_path, &output_path).await?;
            log::info!("Saved signed package to: {}", output_path.display());
            pkg.remove_package_stage();
        } else {
            pkg.remove_package_stage();
        }
    }

    // Export provisioning profile if requested
    if let Some(output_provision_path) = args.output_provision {
        if let Some(first_provision) = signer.provisioning_files.first() {
            tokio::fs::write(&output_provision_path, &first_provision.data).await?;
        } else {
            log::warn!("No provisioning profile available to export");
        }
    }

    Ok(())
}
