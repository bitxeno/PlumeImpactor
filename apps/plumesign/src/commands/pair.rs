use crate::get_data_path;
use anyhow::Result;
use clap::Args;
use idevice::IdeviceError;
use idevice::remote_pairing::errors::RemotePairingError;
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

    /// Optional host identifier sent to the device during pairing
    #[arg(short = 'H', long = "host", value_name = "HOST")]
    pub host: Option<String>,

    /// The IP was specified manually rather than probed
    #[arg(long = "manual")]
    pub manual: bool,
}

pub async fn execute(args: PairArgs) -> Result<()> {
    let ip = IpAddr::from_str(&args.ip)
        .map_err(|e| anyhow::anyhow!("Invalid IP '{}': {}", args.ip, e))?;

    log::info!("Starting remote pairing with {}:{}", ip, args.port);
    debug!("Received pairing arguments: {:?}", args);

    let host = args
        .host
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            hostname::get()
                .ok()
                .and_then(|name| name.into_string().ok())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "plumesign".to_string())
        });
    let mut pairing_file = RpPairingFile::generate(&host);

    let (udid, peer_info_json) = {
        let conn = tokio::net::TcpStream::connect((ip, args.port)).await?;
        let conn = RpPairingSocket::new(conn);
        let mut rpc = RemotePairingClient::new(conn, &host, &mut pairing_file);

        // pair-verify runs first; a new host falls through to pair-setup and
        // prompts for the PIN shown on the device.
        rpc.connect(
            async |_| {
                let mut buf = String::new();
                print!("Enter PIN:");
                if let Err(e) = std::io::stdout().flush() {
                    log::warn!("failed to flush stdout: {e}");
                }
                if let Err(e) = std::io::stdin().read_line(&mut buf) {
                    log::error!("failed to read PIN: {e}");
                    return String::new();
                }
                buf.trim_end().to_string()
            },
            0u8,
        )
        .await
        .map_err(pair_error)?;

        let peer_device: &idevice::remote_pairing::PeerDevice = rpc
            .paired_peer_device()
            .map_err(|e| anyhow::anyhow!("failed to get paired device info: {e}"))?;
        let udid = peer_device.remotepairing_udid.clone();
        // Both fields are optional: `remotepairing_ip` records the IP used for
        // pairing, and `manual` records whether that IP was specified by the
        // user (`--manual`) instead of being probed.
        let remotepairing_ip = Some(args.ip.clone());
        let manual_flag = Some(args.manual);
        let peer_info_json = json!({
            "account_id": peer_device.account_id,
            "alt_irk": peer_device.alt_irk,
            "model": peer_device.model,
            "name": peer_device.name,
            "remotepairing_udid": udid,
            "remotepairing_ip": remotepairing_ip,
            "manual": manual_flag,
        });

        (udid, peer_info_json)
    };

    let pairing_file_dir = get_data_path().join("pairing_files");
    fs::create_dir_all(&pairing_file_dir)?;

    // save pairing file
    let output_path = pairing_file_dir.join(format!("{}.plist", udid));
    pairing_file
        .write_to_file(&output_path)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to write pairing file '{}': {}",
                output_path.display(),
                e
            )
        })?;

    // save peer device info for reference
    let peer_info_output = pairing_file_dir.join(format!("{}.json", udid));
    fs::write(
        &peer_info_output,
        serde_json::to_string_pretty(&peer_info_json)?,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to write peer info '{}': {}",
            peer_info_output.display(),
            e
        )
    })?;

    log::info!(
        "SUCCESS: Remote pairing file saved to '{}'",
        output_path.display()
    );
    Ok(())
}

fn pair_error(err: IdeviceError) -> anyhow::Error {
    match &err {
        IdeviceError::RemotePairing(RemotePairingError::PairingRejected(reason)) => {
            anyhow::anyhow!("device rejected pairing: {reason}")
        }
        IdeviceError::RemotePairing(RemotePairingError::PairVerifyFailed) => {
            anyhow::anyhow!("pair verification failed")
        }
        IdeviceError::RemotePairing(RemotePairingError::SrpAuthFailed) => {
            anyhow::anyhow!("wrong PIN")
        }
        IdeviceError::UnexpectedResponse(msg)
            if msg.contains("error response during pair consent") =>
        {
            anyhow::anyhow!("device rejected pairing; it may be in pairing backoff, wait and retry")
        }
        _ => anyhow::anyhow!("pairing failed: {err}"),
    }
}
