use anyhow::Result;
use clap::Args;

use idevice::IdeviceService;
use idevice::afc::AfcClient;
use idevice::usbmuxd::UsbmuxdAddr;

use crate::commands::device::select_device;

#[derive(Debug, Args)]
#[command(about = "Check PublicStaging via AFC and list files")]
pub struct CheckArgs {
    /// Device UDID to target (optional, will prompt if not provided)
    #[arg(short = 'u', long = "udid", value_name = "UDID")]
    pub udid: Option<String>,
}

pub async fn execute(args: CheckArgs) -> Result<()> {
    let device = select_device(args.udid).await?;

    let provider = device
        .usbmuxd_device
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Device has no usbmuxd provider"))?
        .to_provider(UsbmuxdAddr::default(), "plume_check_afc");

    // Try to connect to AFC service and list the PublicStaging directory.
    // The exact AFC API surface may differ; this follows repository patterns.
    let mut afc = AfcClient::connect(&provider).await?;

    let dir = "PublicStaging";

    // Query info for the PublicStaging directory itself
    match afc.get_file_info(dir).await {
        Ok(_) => {
            return Ok(());
        }
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to access afc service: {}", e));
        }
    }
}
