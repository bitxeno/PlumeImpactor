use anyhow::Result;
use clap::Args;
use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};
use log::debug;
use std::{fs, io::Write, net::IpAddr, path::Path, str::FromStr};

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

    /// Path to save the generated remote pairing file
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<String>,
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

    if let Some(output) = args.output.as_deref() {
        // pairing file identifier is host identifier, not device identifier
        if let Some(parent) = Path::new(output).parent() {
            fs::create_dir_all(parent)?;
        }
        pairing_file.write_to_file(output).await?;
        log::info!(
            "SUCCESS: Remote pairing completed and pairing file saved to {}",
            output
        );
    } else {
        log::info!("SUCCESS: Remote pairing completed");
    }

    Ok(())
}
