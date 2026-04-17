use std::path::Path;

use anyhow::Result;
use clap::{ArgGroup, Args, Subcommand};
use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};
use log::debug;

use crate::get_data_path;
use idevice::IdeviceService;
use idevice::RsdService;
use idevice::afc::AfcClient;
use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
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
#[command(
    group(
        ArgGroup::new("pairing_source")
            .args(["pairing_file_folder", "pairing_file"])
            .required(true)
            .multiple(false)
    )
)]
pub struct PairingArgs {
    /// Device IP address
    #[arg(long = "ip", value_name = "IP")]
    pub ip: String,

    /// Device pairing service port
    #[arg(long = "port", value_name = "PORT")]
    pub port: u16,

    /// Path to pairing file folder to validate
    #[arg(long = "folder", value_name = "PAIRING_FILE_FOLDER")]
    pub pairing_file_folder: Option<String>,

    /// Path to pairing file to validate
    #[arg(short = 'f', long = "file", value_name = "PAIRING_FILE")]
    pub pairing_file: Option<String>,
}

pub async fn execute(args: CheckArgs) -> Result<()> {
    match args.command {
        CheckCommands::Config => config().await,
        CheckCommands::Afc(afc_args) => afc(afc_args).await,
        CheckCommands::Pairing(pair_args) => pairing(pair_args).await,
    }
}

async fn pairing(args: PairingArgs) -> Result<()> {
    let ip = args.ip;
    let host = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "plumesign".to_string());

    if let Some(folder) = args.pairing_file_folder.as_deref() {
        return validate_pairing_folder(Path::new(folder), &ip, args.port, &host).await;
    }

    let pairing_file = args
        .pairing_file
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("pairing file or pairing file folder is required"))?;

    let path = Path::new(pairing_file);
    validate_pairing_file(path, &ip, args.port, &host).await?;
    println!("SUCCESS: Pair verify succeeded");
    Ok(())
}

async fn validate_pairing_folder(folder: &Path, ip: &str, port: u16, host: &str) -> Result<()> {
    let entries = std::fs::read_dir(folder)
        .map_err(|e| anyhow::anyhow!("Failed to read folder '{}': {}", folder.display(), e))?;

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
            folder.display()
        ));
    }

    for pairing_file in plist_files {
        match validate_pairing_file(&pairing_file, ip, port, host).await {
            Ok(()) => {
                println!("SUCCESS: Pair verify succeeded");
                return Ok(());
            }
            Err(error) => {
                debug!(
                    "Failed to validate pairing file '{}': {}",
                    pairing_file.display(),
                    error
                );
            }
        }
    }

    Err(anyhow::anyhow!(
        "Failed to validate pairing for {} ({}:{})",
        host,
        ip,
        port
    ))
}

async fn validate_pairing_file(pairing_file: &Path, ip: &str, port: u16, host: &str) -> Result<()> {
    let mut rpf = RpPairingFile::read_from_file(pairing_file)
        .await
        .map_err(|e| anyhow::anyhow!("invalid pairing file '{}': {}", pairing_file.display(), e))?;
    let conn = tokio::net::TcpStream::connect((ip, port)).await?;
    let conn = RpPairingSocket::new(conn);
    let mut rpc = RemotePairingClient::new(conn, host, &mut rpf);

    let (_, handshake) = rpc.start_tunnel(ip).await?;
    println!(
        "pairing file: `{}`, uuid: `{}`, DeviceClass: `{}`, UniqueDeviceID: `{}`",
        pairing_file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown"),
        handshake.uuid,
        handshake
            .properties
            .get("DeviceClass")
            .and_then(|v| v.as_string())
            .unwrap_or("unknown"),
        handshake
            .properties
            .get("UniqueDeviceID")
            .and_then(|v| v.as_string())
            .unwrap_or("unknown")
    );
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
    if let (Some(ip), Some(port), Some(pairing_file)) =
        (args.ip.as_deref(), args.port, args.pairing_file.as_deref())
    {
        let host = hostname::get()
            .ok()
            .and_then(|name| name.into_string().ok())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "plumesign".to_string());

        let mut rpf = RpPairingFile::read_from_file(pairing_file)
            .await
            .map_err(|e| anyhow::anyhow!("invalid pairing file '{}': {}", pairing_file, e))?;

        let conn = tokio::net::TcpStream::connect((ip, port)).await?;
        let conn = RpPairingSocket::new(conn);
        let mut rpc = RemotePairingClient::new(conn, &host, &mut rpf);

        let (mut provider, mut handshake) = rpc.start_tunnel(ip).await?;
        let mut afc = AfcClient::connect_rsd(&mut provider, &mut handshake).await?;
        let _ = afc.list_dir("/").await?;

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
