use anyhow::Result;
use clap::{Args, Subcommand};

use crate::get_data_path;
use idevice::IdeviceService;
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
}

#[derive(Debug, Args)]
pub struct PairingArgs {
    /// Device IP to target (can also be UDID or device id as fallback)
    #[arg(short = 'i', long = "ip", value_name = "IP")]
    pub ip: String,

    /// Path to pairing file to validate
    #[arg(short = 'f', long = "file", value_name = "PAIRING_FILE")]
    pub pairing: String,

    #[arg(short = 's', long = "save", value_name = "SAVE")]
    pub save: bool,
}

pub async fn execute(args: CheckArgs) -> Result<()> {
    match args.command {
        CheckCommands::Config => config().await,
        CheckCommands::Afc(afc_args) => afc(afc_args).await,
        CheckCommands::Pairing(pair_args) => pairing(pair_args).await,
    }
}

async fn pairing(args: PairingArgs) -> Result<()> {
    use idevice::lockdown::LockdownClient;
    use idevice::pairing_file::PairingFile;
    use idevice::provider::TcpProvider;
    use std::net::IpAddr;

    // Build a TCP provider using the provided IP and port 62078
    let ip: IpAddr = args
        .ip
        .parse()
        .map_err(|e| anyhow::anyhow!(format!("Invalid IP: {}", e)))?;

    // Read pairing file directly into a `PairingFile` structure
    let mut pairing_file = PairingFile::read_from_file(&args.pairing)
        .map_err(|e| anyhow::anyhow!(format!("Failed to read pairing file: {}", e)))?;

    // Construct TcpProvider with port 62078 and the retrieved pairing file
    let provider = TcpProvider {
        addr: ip,
        pairing_file: pairing_file.clone(),
        label: "plume_check_pairing".to_string(),
    };

    let mut lc = LockdownClient::connect(&provider).await?;
    lc.start_session(&pairing_file).await?;

    let serial_val = lc.get_value(Some("UniqueDeviceID"), None).await?;
    let s_udid = serial_val.as_string().unwrap_or_default().to_string();
    if args.save {
        if pairing_file.udid.is_none() {
            pairing_file.udid = Some(s_udid.clone());
        }

        log::info!("Saving pairing file for device UDID: {}", s_udid);
        let mut usbmuxd: UsbmuxdConnection = UsbmuxdConnection::default().await?;
        let pairing_file = pairing_file.serialize().expect("failed to serialize");

        usbmuxd.save_pair_record(&s_udid, pairing_file).await?;
    }

    println!("SUCCESS: UDID `{}`", s_udid);
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
