use anyhow::Result;
use clap::Args;
use dialoguer::Password;
use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};
use std::{net::IpAddr, str::FromStr};

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

    let host = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "plumesign".to_string());
    let mut pairing_file = RpPairingFile::generate(&host);

    let conn = tokio::net::TcpStream::connect((ip, args.port)).await?;
    let conn = RpPairingSocket::new(conn);
    let mut rpc = RemotePairingClient::new(conn, &host, &mut pairing_file);

    rpc.connect(
        async |_| {
            Password::new()
                .with_prompt("Enter PIN:")
                .interact()
                .expect("Failed to read PIN")
        },
        0u8,
    )
    .await?;

    let output = args.output.unwrap_or_else(|| {
        format!(
            "remote_pairing_{}_{}.plist",
            args.ip.replace(':', "_"),
            args.port
        )
    });

    pairing_file.write_to_file(&output).await?;

    log::info!(
        "SUCCESS: Remote pairing completed and pairing file saved to {}",
        output
    );

    Ok(())
}
