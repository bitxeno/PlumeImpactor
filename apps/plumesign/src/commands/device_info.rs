use std::io::Write;
use std::{net::IpAddr, str::FromStr};

use anyhow::Result;
use clap::Args;
use idevice::IdeviceService;
use idevice::RsdService;
use idevice::lockdown::LockdownClient;
use idevice::mobile_image_mounter::ImageMounter;
use idevice::provider::IdeviceProvider;
use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};
use idevice::usbmuxd::UsbmuxdAddr;
use plist::Value;

use crate::commands::device::select_device;

const DEVICE_INFO_LABEL: &str = "plumesign_device_info";

#[derive(Debug, Args)]
#[command(
    arg_required_else_help = false,
    about = "Show device information via usbmuxd/lockdown"
)]
pub struct DeviceInfoArgs {
    /// Device UDID to target (optional, will prompt if not provided)
    #[arg(short = 'u', long = "udid", value_name = "UDID")]
    pub udid: Option<String>,

    /// Device IP address
    #[arg(long = "ip", value_name = "IP", requires_all = ["port", "pairing_file"])]
    pub ip: Option<String>,

    /// Device pairing service port
    #[arg(long = "port", value_name = "PORT", requires_all = ["ip", "pairing_file"])]
    pub port: Option<u16>,

    /// Path to pairing file
    #[arg(
        short = 'f',
        long = "file",
        visible_alias = "pairing-file",
        value_name = "PAIRING_FILE",
        requires_all = ["ip", "port"]
    )]
    pub pairing_file: Option<String>,

    /// Print output as plist XML
    #[arg(short = 'x', long = "xml")]
    pub xml: bool,
}

pub async fn execute(args: DeviceInfoArgs) -> Result<()> {
    let value = if let (Some(ip), Some(port), Some(pairing_file_path)) =
        (args.ip.as_deref(), args.port, args.pairing_file.as_deref())
    {
        fetch_remote_device_info(ip, port, pairing_file_path).await?
    } else {
        fetch_usb_device_info(args.udid).await?
    };

    if args.xml {
        let mut stdout = std::io::stdout();
        value.to_writer_xml(&mut stdout)?;
        stdout.write_all(b"\n")?;
        return Ok(());
    }

    print_value(&value)?;

    Ok(())
}

async fn fetch_usb_device_info(udid: Option<String>) -> Result<Value> {
    let device = select_device(udid).await?;
    let usbmuxd_device = device
        .usbmuxd_device
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Device has no usbmuxd provider"))?;

    let provider = usbmuxd_device.to_provider(
        UsbmuxdAddr::from_env_var().unwrap_or_default(),
        DEVICE_INFO_LABEL,
    );

    let pairing_file = provider.get_pairing_file().await?;
    let mut lockdown = LockdownClient::connect(&provider).await?;
    lockdown.start_session(&pairing_file).await?;

    let mut value = lockdown.get_value(None, None).await?;
    let devstatus = lockdown
        .get_value(
            Some("DeveloperModeStatus"),
            Some("com.apple.security.mac.amfi"),
        )
        .await?;
    if let Some(dict) = value.as_dictionary_mut() {
        dict.insert("DeveloperModeStatus".to_string(), devstatus);
    }

    let mounted = match ImageMounter::connect(&provider).await {
        Ok(mut mounter_client) => mounter_client.lookup_image("Personalized").await.is_ok(),
        Err(_) => false,
    };
    merge_personalized_image_mounted(&mut value, mounted);

    Ok(value)
}

async fn fetch_remote_device_info(ip: &str, port: u16, pairing_file_path: &str) -> Result<Value> {
    let ip_addr =
        IpAddr::from_str(ip).map_err(|e| anyhow::anyhow!("Invalid IP '{}': {}", ip, e))?;
    let host = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "plumesign".to_string());

    let mut pairing_file = RpPairingFile::read_from_file(pairing_file_path)
        .await
        .map_err(|e| anyhow::anyhow!("invalid pairing file '{}': {}", pairing_file_path, e))?;

    let conn = tokio::net::TcpStream::connect((ip_addr, port)).await?;
    let conn = RpPairingSocket::new(conn);
    let mut rpc = RemotePairingClient::new(conn, &host, &mut pairing_file);

    let (mut provider, mut handshake) = rpc.tunnel_connect(ip).await?;
    let mut lockdown = LockdownClient::connect_rsd(&mut provider, &mut handshake).await?;

    let mut value = lockdown.get_value(None, None).await?;

    let devstatus = lockdown
        .get_value(
            Some("DeveloperModeStatus"),
            Some("com.apple.security.mac.amfi"),
        )
        .await?;
    if let Some(dict) = value.as_dictionary_mut() {
        dict.insert("DeveloperModeStatus".to_string(), devstatus);
    }

    let mounted = match ImageMounter::connect_rsd(&mut provider, &mut handshake).await {
        Ok(mut mounter_client) => mounter_client.lookup_image("Personalized").await.is_ok(),
        Err(_) => false,
    };
    merge_personalized_image_mounted(&mut value, mounted);

    Ok(value)
}

fn merge_personalized_image_mounted(value: &mut Value, personalized_image_mounted: bool) {
    if let Some(dict) = value.as_dictionary_mut() {
        dict.insert(
            "PersonalizedImageMounted".to_string(),
            Value::Boolean(personalized_image_mounted),
        );
    }
}

fn print_value(value: &Value) -> Result<()> {
    match value {
        Value::Dictionary(dict) => {
            let mut keys: Vec<_> = dict.keys().collect();
            keys.sort();

            for name in keys {
                if let Some(v) = dict.get(name) {
                    print_named_value(name, v, 0)?;
                }
            }
        }
        _ => print_named_value("Value", value, 0)?,
    }

    Ok(())
}

fn print_named_value(name: &str, value: &Value, indent: usize) -> Result<()> {
    let prefix = " ".repeat(indent);

    match value {
        Value::Dictionary(dict) => {
            println!("{}{}:", prefix, name);

            let mut keys: Vec<_> = dict.keys().collect();
            keys.sort();

            for key in keys {
                if let Some(v) = dict.get(key) {
                    print_named_value(key, v, indent + 1)?;
                }
            }
        }
        Value::Array(items) => {
            println!("{}{}[{}]:", prefix, name, items.len());

            for (index, item) in items.iter().enumerate() {
                print_indexed_value(index, item, indent + 1)?;
            }
        }
        _ => {
            println!("{}{}: {}", prefix, name, scalar_to_string(value));
        }
    }

    Ok(())
}

fn print_indexed_value(index: usize, value: &Value, indent: usize) -> Result<()> {
    let prefix = " ".repeat(indent);

    match value {
        Value::Dictionary(dict) => {
            println!("{}{}:", prefix, index);

            let mut keys: Vec<_> = dict.keys().collect();
            keys.sort();

            for key in keys {
                if let Some(v) = dict.get(key) {
                    print_named_value(key, v, indent + 1)?;
                }
            }
        }
        Value::Array(items) => {
            println!("{}{}[{}]:", prefix, index, items.len());

            for (nested_index, item) in items.iter().enumerate() {
                print_indexed_value(nested_index, item, indent + 1)?;
            }
        }
        _ => println!("{}{}: {}", prefix, index, scalar_to_string(value)),
    }

    Ok(())
}

fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::String(v) => v.clone(),
        Value::Boolean(v) => v.to_string(),
        Value::Integer(v) => integer_to_string(v),
        Value::Real(v) => v.to_string(),
        Value::Data(v) => base64_encode(v),
        Value::Date(v) => format!("{:?}", v),
        Value::Uid(v) => format!("{:?}", v),
        _ => format!("{:?}", value),
    }
}

fn integer_to_string(value: &plist::Integer) -> String {
    if let Some(v) = value.as_signed() {
        v.to_string()
    } else if let Some(v) = value.as_unsigned() {
        v.to_string()
    } else {
        format!("{:?}", value)
    }
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if data.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0usize;

    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }

    let rem = data.len() - i;
    if rem == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }

    out
}
