use anyhow::Result;
use clap::Args;
use idevice::usbmuxd::{Connection, UsbmuxdConnection};
use plume_utils::Device;

#[derive(Debug, Args)]
#[command(arg_required_else_help = false)]
pub struct DeviceIdArgs {}

pub async fn execute(_args: DeviceIdArgs) -> Result<()> {
    let mut muxer = UsbmuxdConnection::default().await?;
    let devices = muxer.get_devices().await?;

    if devices.is_empty() {
        println!("No devices connected");
        return Ok(());
    }

    let device_futures: Vec<_> = devices.into_iter().map(|d| Device::new(d)).collect();
    let devices = futures::future::join_all(device_futures).await;

    for d in devices.iter() {
        let conn = match &d.usbmuxd_device {
            Some(dev) => match &dev.connection_type {
                Connection::Usb => "(USB)",
                Connection::Network(_) => "(Network)",
                Connection::Unknown(_) => "",
            },
            None => "",
        };

        println!("{} {}", d.udid, conn);
    }

    Ok(())
}
