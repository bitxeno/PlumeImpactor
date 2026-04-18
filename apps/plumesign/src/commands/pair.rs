use crate::get_data_path;
use anyhow::Result;
use clap::Args;
use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};
use log::debug;
use serde_json::json;
use std::{fs, io::Write, net::IpAddr, str::FromStr};

#[derive(Debug, Args)]
#[command(
    arg_required_else_help = true,
    about = "Pair a device over network (IP/port, no usbmuxd)"
)]
pub struct PairArgs {
    /// Device IP address
    #[arg(short = 'i', long = "ip", value_name = "IP")]
    pub ip: String,

    /// Device pairing service port
    #[arg(short = 'p', long = "port", value_name = "PORT")]
    pub port: u16,
}

pub async fn execute(args: PairArgs) -> Result<()> {
    let ip = IpAddr::from_str(&args.ip)
        .map_err(|e| anyhow::anyhow!("Invalid IP '{}': {}", args.ip, e))?;

    log::info!("Starting remote pairing with {}:{}", ip, args.port);
    debug!("Received pairing arguments: {:?}", args);

    let host = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "plumesign".to_string());
    let mut pairing_file = RpPairingFile::generate(&host);

    let (udid, peer_info_json) = {
        let conn = tokio::net::TcpStream::connect((ip, args.port)).await?;
        let conn = RpPairingSocket::new(conn);
        let mut rpc = RemotePairingClient::new(conn, &host, &mut pairing_file);

        // try pairing, will fail with invalid pin
        rpc.connect(
            async |_| {
                let mut buf = String::new();
                print!("Enter PIN:");
                std::io::stdout().flush().unwrap();
                std::io::stdin()
                    .read_line(&mut buf)
                    .expect("Failed to read line");
                buf.trim_end().to_string()
            },
            0u8,
        )
        .await
        .expect("Invalid PIN");

        let peer_device: &idevice::remote_pairing::PeerDevice =
            rpc.peer_device().expect("Failed to get peer device");
        let udid = peer_device
            .remotepairing_udid
            .as_deref()
            .expect("Failed to get remotepairing_udid from peer device")
            .to_string();
        let peer_info_json = json!({
            "account_id": peer_device.account_id,
            "alt_irk": peer_device.alt_irk,
            "model": peer_device.model,
            "name": peer_device.name,
            "remotepairing_udid": peer_device.remotepairing_udid,
        });

        (udid, peer_info_json)
    };

    let pairing_file_dir = get_data_path().join("pairing_files");
    fs::create_dir_all(&pairing_file_dir)?;

    // save pairing file
    let output = pairing_file_dir.join(format!("{}.plist", udid));
    pairing_file.write_to_file(output).await?;

    // save peer device info for reference
    let peer_info_output = pairing_file_dir.join(format!("{}.json", udid));
    fs::write(
        peer_info_output,
        serde_json::to_string_pretty(&peer_info_json)?,
    )?;

    log::info!("SUCCESS: Remote pairing completed");
    Ok(())
}
