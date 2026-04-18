use std::path::Path;

use anyhow::Result;
use clap::{Args, Subcommand};
use idevice::lockdown::LockdownClient;
use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};
use serde_json::json;
use std::fs;

use crate::get_data_path;
use base64::Engine;
use idevice::afc::AfcClient;
use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
use idevice::{IdeviceService, RsdService};
use plume_core::AnisetteConfiguration;
use plume_core::auth::anisette_data::AnisetteData;

use crate::commands::device::select_device;
use plume_utils::Device;

#[derive(Debug, Args)]
#[command(
    arg_required_else_help = true,
    about = "Check PublicStaging via AFC and list files"
)]
pub struct CheckArgs {
    #[command(subcommand)]
    pub command: CheckCommands,
}

#[derive(Debug, Subcommand)]
#[command(arg_required_else_help = true)]
pub enum CheckCommands {
    /// Show configuration path
    Config,
    /// Run AFC check and show result
    Afc(AfcArgs),
    /// Validate a pairing file against a device (use ip to select device)
    Pairing(PairingArgs),
    /// Find a pairing file or folder to validate
    FindPairing(FindPairingArgs),
}

#[derive(Debug, Args)]
pub struct ConfigArgs {}

#[derive(Debug, Args)]
pub struct AfcArgs {
    /// Device UDID to target (optional, will prompt if not provided)
    #[arg(short = 'u', long = "udid", value_name = "UDID")]
    pub udid: Option<String>,

    /// Device IP address
    #[arg(long = "ip", value_name = "IP", requires_all = ["port", "pairing_file"])]
    pub ip: Option<String>,

    /// Device pairing service port
    #[arg(long = "port", value_name = "PORT", requires_all = ["ip", "pairing_file"])]
    pub port: Option<u16>,

    /// Path to pairing file
    #[arg(
        short = 'f',
        long = "file",
        visible_alias = "pairing-file",
        value_name = "PAIRING_FILE",
        requires_all = ["ip", "port"]
    )]
    pub pairing_file: Option<String>,
}

#[derive(Debug, Args)]
pub struct PairingArgs {
    /// Device UDID to target (optional, will prompt if not provided)
    #[arg(short = 'u', long = "udid", value_name = "UDID")]
    pub udid: Option<String>,

    /// Device IP address
    #[arg(long = "ip", value_name = "IP")]
    pub ip: String,

    /// Device pairing service port
    #[arg(long = "port", value_name = "PORT")]
    pub port: u16,

    /// Path to pairing file to validate
    #[arg(short = 'f', long = "file", value_name = "PAIRING_FILE")]
    pub pairing_file: Option<String>,
}

#[derive(Debug, Args)]
pub struct FindPairingArgs {
    /// Device IP address
    #[arg(long)]
    pub identifier: String,

    /// Device pairing service port
    #[arg(long)]
    pub auth_tag: String,
}

pub async fn execute(args: CheckArgs) -> Result<()> {
    match args.command {
        CheckCommands::Config => config().await,
        CheckCommands::Afc(afc_args) => afc(afc_args).await,
        CheckCommands::Pairing(pair_args) => pairing(pair_args).await,
        CheckCommands::FindPairing(find_pairing_args) => find_pairing(find_pairing_args).await,
    }
}

async fn find_pairing(args: FindPairingArgs) -> Result<()> {
    let identifier = args.identifier;
    let auto_tag = args.auth_tag;
    let pairing_file_dir = get_data_path().join("pairing_files");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(auto_tag)
        .expect("Invalid auth tag");

    let entries =
        std::fs::read_dir(pairing_file_dir.clone()).expect("Failed to read pairing file directory");

    let mut plist_files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| anyhow::anyhow!("Failed to read folder entry: {}", e))?;
        let path = entry.path();
        let is_plist = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("plist"));

        if is_plist {
            plist_files.push(path);
        }
    }

    if plist_files.is_empty() {
        return Err(anyhow::anyhow!(
            "No .plist pairing files found in '{}'",
            pairing_file_dir.display()
        ));
    }

    for pairing_file in plist_files {
        let rpf = RpPairingFile::read_from_file(pairing_file.clone()).await?;

        if rpf.alt_irk.is_empty() {
            continue; // skip invalid pairing files
        }

        if rpf.validate_auth_tag(&identifier, bytes.as_slice()) {
            println!(
                "UDID: `{}`",
                pairing_file
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown")
            );
            return Ok(());
        }
    }

    Err(anyhow::anyhow!(
        "Failed to validate pairing for {}",
        identifier
    ))
}

async fn pairing(args: PairingArgs) -> Result<()> {
    let ip = args.ip;
    let host = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "plumesign".to_string());

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

    let path = Path::new(&pairing_file);
    validate_pairing_file(path, &ip, args.port, &host).await?;
    Ok(())
}

async fn validate_pairing_file(pairing_file: &Path, ip: &str, port: u16, host: &str) -> Result<()> {
    let mut rpf = RpPairingFile::read_from_file(pairing_file)
        .await
        .map_err(|e| anyhow::anyhow!("invalid pairing file '{}': {}", pairing_file.display(), e))?;
    if rpf.alt_irk.is_empty() {
        return Err(anyhow::anyhow!(
            "invalid pairing file '{}': alt_irk is empty",
            pairing_file.display()
        ));
    }
    let conn = tokio::net::TcpStream::connect((ip, port)).await?;
    let conn = RpPairingSocket::new(conn);
    let mut rpc = RemotePairingClient::new(conn, host, &mut rpf);

    let (mut provider, mut handshake) = rpc.start_tunnel(ip).await?;
    let mut lockdown = LockdownClient::connect_rsd(&mut provider, &mut handshake).await?;
    let value = lockdown.get_value(None, None).await?;

    let peer_identifier = rpc
        .peer_identifier()
        .expect("Failed to get peer identifier");
    let udid = value
        .as_dictionary()
        .and_then(|dict| dict.get("UniqueDeviceID"))
        .and_then(|v| v.as_string())
        .expect("Failed to get UniqueDeviceID from lockdown value");
    let name = value
        .as_dictionary()
        .and_then(|dict| dict.get("DeviceName"))
        .and_then(|v| v.as_string())
        .expect("Failed to get DeviceName from lockdown value");
    let model = value
        .as_dictionary()
        .and_then(|dict| dict.get("ProductType"))
        .and_then(|v| v.as_string())
        .expect("Failed to get ProductType from lockdown value");
    let peer_info_json = json!({
        "account_id": peer_identifier,
        "alt_irk": rpf.alt_irk,
        "model": model,
        "name": name,
        "remotepairing_udid": udid,
    });

    let pairing_file_dir = get_data_path().join("pairing_files");
    fs::create_dir_all(&pairing_file_dir)?;

    // save pairing file
    let output = pairing_file_dir.join(format!("{}.plist", udid));
    rpf.write_to_file(output).await?;

    // save peer device info for reference
    let peer_info_output = pairing_file_dir.join(format!("{}.json", udid));
    fs::write(
        peer_info_output,
        serde_json::to_string_pretty(&peer_info_json)?,
    )?;

    Ok(())
}

async fn config() -> Result<()> {
    let config_path = get_data_path();
    log::info!("configurationPath={}", config_path.display());

    // anisette data auto save to ~/.config/PlumeImpactor/adb.pb or ~/.config/PlumeImpactor/state.plist
    let anisette_config = AnisetteConfiguration::default().set_configuration_path(get_data_path());
    let anisette = AnisetteData::new(anisette_config).await?;
    log::info!("anisette={:#?}", anisette);

    Ok(())
}

async fn afc(args: AfcArgs) -> Result<()> {
    if let (Some(ip), Some(port)) = (args.ip.as_deref(), args.port) {
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
        let host = hostname::get()
            .ok()
            .and_then(|name| name.into_string().ok())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "plumesign".to_string());

        let mut rpf = RpPairingFile::read_from_file(&pairing_file)
            .await
            .map_err(|e| {
                anyhow::anyhow!("invalid pairing file '{}': {}", pairing_file.display(), e)
            })?;

        let conn = tokio::net::TcpStream::connect((ip, port)).await?;
        let conn = RpPairingSocket::new(conn);
        let mut rpc = RemotePairingClient::new(conn, &host, &mut rpf);

        rpc.attempt_pair_verify().await?;
        rpc.validate_pairing().await?;

        println!("SUCCESS: AFC access OK (RSD)");
        return Ok(());
    }

    let device: Device = if let Some(udid) = args.udid {
        select_device(Some(udid)).await?
    } else {
        // No UDID provided: pick the first connected device automatically.
        let mut muxer = UsbmuxdConnection::default().await?;
        let usb_devices = muxer.get_devices().await?;

        if usb_devices.is_empty() {
            return Err(anyhow::anyhow!(
                "No devices connected. Please connect a device or specify a UDID with -u"
            ));
        }

        let device_futures: Vec<_> = usb_devices.into_iter().map(|d| Device::new(d)).collect();
        let devices = futures::future::join_all(device_futures).await;
        devices[0].clone()
    };

    let provider = device
        .usbmuxd_device
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Device has no usbmuxd provider"))?
        .to_provider(UsbmuxdAddr::default(), "plume_check_afc");

    let mut afc = AfcClient::connect(&provider).await?;
    let _ = afc.list_dir("/").await?;

    println!("SUCCESS: AFC access OK");
    Ok(())
}
