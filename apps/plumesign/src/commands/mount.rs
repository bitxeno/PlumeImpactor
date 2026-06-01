use std::io::Write;
use std::path::PathBuf;
use std::{fs, net::IpAddr, str::FromStr};

use anyhow::Result;
use clap::Args;
use idevice::RsdService;
use idevice::lockdown::LockdownClient;
use idevice::mobile_image_mounter::ImageMounter;
use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};

use crate::get_data_path;

#[derive(Debug, Args)]
#[command(
    arg_required_else_help = true,
    about = "Mount a personalized developer disk image on an iOS device over an RSD tunnel"
)]
pub struct MountArgs {
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

    /// Path to the personalized developer disk image (e.g. DeveloperDiskImage.dmg)
    #[arg(long = "image", value_name = "IMAGE")]
    pub image: PathBuf,

    /// Path to the build manifest (iOS 17+, e.g. BuildManifest.plist)
    #[arg(short = 'b', long = "manifest", value_name = "MANIFEST")]
    pub manifest: PathBuf,

    /// Path to the trust cache (iOS 17+, e.g. DeveloperDiskImage.dmg.trustcache)
    #[arg(short = 't', long = "trustcache", value_name = "TRUSTCACHE")]
    pub trustcache: PathBuf,
}

pub async fn execute(args: MountArgs) -> Result<()> {
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

    for (label, path) in [
        ("image", &args.image),
        ("build manifest", &args.manifest),
        ("trust cache", &args.trustcache),
        ("pairing file", &pairing_file),
    ] {
        if !path.is_file() {
            return Err(anyhow::anyhow!("{label} not found: {}", path.display()));
        }
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

    let image = fs::read(&args.image)?;
    let trust_cache = fs::read(&args.trustcache)?;
    let build_manifest = fs::read(&args.manifest)?;

    log::info!(
        "Mounting personalized image {} ({} bytes) via RSD tunnel to {}:{}",
        args.image.display(),
        image.len(),
        args.ip,
        args.port
    );

    let conn = tokio::net::TcpStream::connect((ip, args.port)).await?;
    let conn = RpPairingSocket::new(conn);
    let mut rpc = RemotePairingClient::new(conn, &host_name, &mut pairing_file);

    let (mut provider, mut handshake) = rpc.start_tunnel(&args.ip).await?;

    let mut lockdown = LockdownClient::connect_rsd(&mut provider, &mut handshake).await?;
    let unique_chip_id = lockdown
        .get_value(Some("UniqueChipID"), None)
        .await?
        .as_unsigned_integer()
        .ok_or_else(|| anyhow::anyhow!("UniqueChipID was not an unsigned integer"))?;

    let mut mounter = ImageMounter::connect_rsd(&mut provider, &mut handshake).await?;
    if mounter.lookup_image("Personalized").await.is_ok() {
        log::info!("SUCCESS: Personalized image is already mounted, skipping");
        return Ok(());
    }

    let mut last_percent: i32 = -1;
    let image_size = image.len();

    mounter
        .mount_personalized_with_callback_rsd(
            &mut provider,
            &mut handshake,
            image,
            trust_cache,
            &build_manifest,
            None,
            unique_chip_id,
            |((sent, total), _)| async move {
                #[allow(unused_assignments)]
                {
                    let percent = if total == 0 {
                        0
                    } else {
                        ((sent as f64 / total as f64) * 100.0) as i32
                    };
                    if percent != last_percent {
                        last_percent = percent;
                        print!("\rUploading image: {percent}% ({sent}/{total} bytes)");
                        let _ = std::io::stdout().flush();
                    }
                    if sent == total && total != 0 {
                        println!();
                    }
                }
            },
            (),
        )
        .await
        .map_err(|e| anyhow::anyhow!("failed to mount personalized image: {e:?}"))?;

    log::info!(
        "SUCCESS: Personalized image ({} bytes) mounted successfully",
        image_size
    );
    Ok(())
}
