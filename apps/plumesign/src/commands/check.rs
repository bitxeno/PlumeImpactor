use anyhow::Result;
use clap::{Args, Subcommand};

use idevice::IdeviceService;
use idevice::afc::AfcClient;
use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
use plume_core::AnisetteConfiguration;
use plume_core::auth::anisette_data::AnisetteData;
use plume_shared::get_data_path;

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
}

#[derive(Debug, Args)]
pub struct ConfigArgs {}

#[derive(Debug, Args)]
pub struct AfcArgs {
    /// Device UDID to target (optional, will prompt if not provided)
    #[arg(short = 'u', long = "udid", value_name = "UDID")]
    pub udid: Option<String>,
}

pub async fn execute(args: CheckArgs) -> Result<()> {
    match args.command {
        CheckCommands::Config => config().await,
        CheckCommands::Afc(afc_args) => afc(afc_args).await,
    }
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

    let dir = "PublicStaging";
    let _ = afc.get_file_info(dir).await?;

    println!("SUCCESS: AFC access OK");
    Ok(())
}
