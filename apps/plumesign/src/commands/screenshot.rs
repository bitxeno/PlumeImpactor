use std::path::PathBuf;
use std::{fs, net::IpAddr, str::FromStr};

use anyhow::Result;
use clap::Args;
use idevice::RsdService;
use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};

use crate::get_data_path;

#[derive(Debug, Args)]
#[command(
    arg_required_else_help = true,
    about = "Take a screenshot from an iOS device over an RSD tunnel"
)]
pub struct ScreenshotArgs {
    /// Device IP address
    #[arg(short = 'i', long = "ip", value_name = "IP")]
    pub ip: String,

    /// Device pairing service port
    #[arg(short = 'p', long = "port", value_name = "PORT")]
    pub port: u16,

    /// Device UDID (resolves pairing file from the default pairing_files directory)
    #[arg(long, value_name = "UDID")]
    pub udid: Option<String>,

    /// Path to the pairing file
    #[arg(
        short = 'f',
        long = "file",
        visible_alias = "pairing-file",
        value_name = "PAIRING_FILE"
    )]
    pub pairing_file: Option<String>,

    /// Output path for the screenshot PNG
    #[arg(short = 'o', long = "output", value_name = "OUTPUT")]
    pub output: PathBuf,
}

pub async fn execute(args: ScreenshotArgs) -> Result<()> {
    let pairing_file = if let Some(pairing_file) = args.pairing_file.as_deref() {
        PathBuf::from(pairing_file)
    } else if let Some(udid) = args.udid.as_deref() {
        get_data_path()
            .join("pairing_files")
            .join(format!("{}.plist", udid))
    } else {
        return Err(anyhow::anyhow!(
            "pairing file is required: provide --udid or --file"
        ));
    };

    if !pairing_file.is_file() {
        return Err(anyhow::anyhow!(
            "pairing file not found: {}",
            pairing_file.display()
        ));
    }

    if let Some(parent) = args.output.parent()
        && !parent.as_os_str().is_empty()
        && !parent.is_dir()
    {
        return Err(anyhow::anyhow!(
            "output directory does not exist: {}",
            parent.display()
        ));
    }

    let ip = IpAddr::from_str(&args.ip)
        .map_err(|e| anyhow::anyhow!("invalid IP '{}': {}", args.ip, e))?;
    let host_name = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "plumesign".to_string());

    let pairing_file_path = pairing_file.clone();
    let mut pairing_file = RpPairingFile::read_from_file(&pairing_file)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "invalid pairing file '{}': {}",
                pairing_file_path.display(),
                e
            )
        })?;
    if pairing_file.alt_irk.is_none() {
        return Err(anyhow::anyhow!(
            "invalid pairing file '{}': alt_irk is empty",
            pairing_file_path.display()
        ));
    }

    log::info!(
        "Taking screenshot from {}:{} via RSD tunnel",
        args.ip,
        args.port
    );

    let conn = tokio::net::TcpStream::connect((ip, args.port)).await?;
    let conn = RpPairingSocket::new(conn);
    let mut rpc = RemotePairingClient::new(conn, &host_name, &mut pairing_file);

    let (mut provider, mut handshake) = rpc.start_tunnel(&args.ip).await?;

    // Make the connection to RemoteXPC
    let mut ts_client =
        idevice::dvt::remote_server::RemoteServerClient::connect_rsd(&mut provider, &mut handshake)
            .await?;

    let mut ts_client = idevice::dvt::screenshot::ScreenshotClient::new(&mut ts_client).await?;
    let png = ts_client.take_screenshot().await?;

    fs::write(&args.output, &png)?;
    log::info!(
        "SUCCESS: Screenshot saved to {} ({} bytes)",
        args.output.display(),
        png.len()
    );
    Ok(())
}
