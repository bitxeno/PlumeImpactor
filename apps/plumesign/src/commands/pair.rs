use anyhow::Result;
use clap::Args;
use dialoguer::Password;

use idevice::IdeviceService;
use idevice::lockdown::LockdownClient;
use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};

use crate::commands::device::select_device;

#[derive(Debug, Args)]
#[command(
    arg_required_else_help = true,
    about = "Pair a device (wired or wireless)"
)]
pub struct PairArgs {
    /// Device UDID to target (optional, will prompt if not provided)
    #[arg(short = 'u', long = "udid", value_name = "UDID")]
    pub udid: Option<String>,

    /// Perform wireless pairing (otherwise wired pairing)
    #[arg(short = 'w', long = "wireless")]
    pub wireless: bool,
}

pub async fn execute(args: PairArgs) -> Result<()> {
    let device = select_device(args.udid).await?;

    if !args.wireless {
        log::info!("Performing wired pairing for device {}", device.name);
        device.pair().await?;
        log::info!("Paired device {} successfully", device.name);
        return Ok(());
    }

    log::info!(
        "Starting wireless pairing for device {}({})",
        device.name,
        device.udid
    );

    // Connect to usbmuxd
    let mut usbmuxd = UsbmuxdConnection::default().await?;

    // provider for lockdown operations over the device connection
    let provider = device
        .usbmuxd_device
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Device has no usbmuxd provider"))?
        .to_provider(UsbmuxdAddr::default(), "pair-jkcoxson");

    let mut lockdown_client = LockdownClient::connect(&provider).await?;

    // Identifier used for pairing operations
    let id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let buid = usbmuxd.get_buid().await.unwrap();

    // Prompt for PIN
    let pin_cb = || async move {
        Password::new()
            .with_prompt("Enter PIN:")
            .interact()
            .expect("Failed to read PIN")
    };

    lockdown_client
        .cu_pairing_create(buid.clone(), pin_cb, None)
        .await
        .expect("Failed to perform wireless pairing handshake");

    let mut pairing_file = lockdown_client
        .pair_cu(id, buid)
        .await
        .expect("Failed to create pairing record");

    // After CU pairing, try to obtain a normal pairing record via `pair`
    // pairing_file.udid = Some(s_udid.clone());
    // let serialized = pairing_file.serialize()?;

    // Add the UDID (jitterbug spec)
    if pairing_file.udid.is_none() {
        pairing_file.udid = Some(device.udid.clone());
    }
    let s_udid = pairing_file.udid.as_ref().unwrap().clone();
    let pairing_file = pairing_file.serialize().expect("failed to serialize");

    // Save with usbmuxd
    usbmuxd
        .save_pair_record(&s_udid, pairing_file)
        .await
        .expect("no save");

    log::info!("SUCCESS: Paired with device {}({})", device.name, s_udid);

    Ok(())
}
