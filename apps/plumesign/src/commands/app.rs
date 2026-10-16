use std::{collections::HashMap, net::IpAddr, path::PathBuf, str::FromStr};

use anyhow::Result;
use clap::{Args, Subcommand};
use idevice::RsdService;
use idevice::dvt::message::AuxValue;
use idevice::mobile_image_mounter::ImageMounter;
use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket};
use plist::{Dictionary, Value};

use crate::get_data_path;

#[derive(Debug, Args)]
#[command(arg_required_else_help = true, about = "App management commands")]
pub struct AppArgs {
    #[command(subcommand)]
    pub command: AppCommands,
}

#[derive(Debug, Subcommand)]
pub enum AppCommands {
    /// Enable JIT for an app over an RSD tunnel
    #[command(name = "enable-jit", alias = "enable_jit")]
    EnableJit(EnableJitArgs),
}

#[derive(Debug, Args)]
#[command(
    arg_required_else_help = true,
    about = "Enable JIT for an app over an RSD tunnel"
)]
pub struct EnableJitArgs {
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

    /// Bundle identifier of the app to enable JIT for
    #[arg(
        short = 'b',
        long = "bundle-identifier",
        visible_aliases = ["bundle-id", "bundleIdentifier"],
        value_name = "BUNDLE_ID"
    )]
    pub bundle_identifier: String,
}

pub async fn execute(args: AppArgs) -> Result<()> {
    match args.command {
        AppCommands::EnableJit(jit_args) => enable_jit(jit_args).await,
    }
}

async fn enable_jit(args: EnableJitArgs) -> Result<()> {
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
        "Enabling JIT for {} via RSD tunnel to {}:{}",
        args.bundle_identifier,
        args.ip,
        args.port
    );

    let conn = tokio::net::TcpStream::connect((ip, args.port)).await?;
    let conn = RpPairingSocket::new(conn);
    let mut rpc = RemotePairingClient::new(conn, &host_name, &mut pairing_file);

    let (mut provider, mut handshake) = rpc.start_tunnel(&args.ip).await?;

    // DVT instruments and debugproxy live in the Personalized developer
    // image. Fail early with a clear hint instead of an obscure service
    // error later.
    let mounted = match ImageMounter::connect_rsd(&mut provider, &mut handshake).await {
        Ok(mut mounter) => mounter.lookup_image("Personalized").await.is_ok(),
        Err(_) => false,
    };
    if !mounted {
        return Err(anyhow::anyhow!(
            "Personalized developer image is not mounted; mount it first with 'plumesign mount'"
        ));
    }

    // Resolve the bundle identifier against installed apps. Signing appends
    // ".<team_id>" to the original identifier, so launching with the original
    // ID misses; fall back to prefix matching in that case.
    let bundle_identifier =
        resolve_bundle_identifier(&mut provider, &mut handshake, &args.bundle_identifier).await?;

    // Launch the app via DVT process control (Instruments remote server over
    // RSD).
    //
    // The DTX call is issued manually instead of going through
    // `ProcessControlClient::launch_app` so that the full device response is
    // logged and non-integer PID payloads / NSError dictionaries are surfaced
    // instead of collapsing into a generic `UnexpectedResponse`.
    let pid = {
        let mut remote_server = idevice::dvt::remote_server::RemoteServerClient::connect_rsd(
            &mut provider,
            &mut handshake,
        )
        .await?;
        let mut channel = remote_server
            .make_channel("com.apple.instruments.server.services.processcontrol")
            .await?;

        let mut options = Dictionary::new();
        options.insert("StartSuspendedKey".to_string(), Value::Boolean(false));
        // Never kill an already-running instance: launching with
        // KillExisting=false returns the existing PID, and (re-)attaching
        // the debugger is harmless, so JIT is ensured either way.
        options.insert("KillExisting".to_string(), Value::Boolean(false));

        channel
            .call_method(
                Some(Value::String(
                    "launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:"
                        .to_string(),
                )),
                Some(vec![
                    AuxValue::archived_value(""),
                    AuxValue::archived_value(bundle_identifier.clone()),
                    AuxValue::archived_value(Dictionary::new()),
                    AuxValue::archived_value(Value::Array(Vec::new())),
                    AuxValue::archived_value(options),
                ]),
                true,
            )
            .await?;
        let res = channel.read_message().await?;
        log::debug!("Launch response: {:?}", res.data);
        match parse_pid(&res.data) {
            Some(pid) => {
                log::info!("Launched {bundle_identifier} with PID {pid}");
                pid
            }
            None => {
                let detail = res
                    .data
                    .as_ref()
                    .and_then(extract_ns_error_message)
                    .map(|message| format!(": {message}"))
                    .unwrap_or_default();
                return Err(anyhow::anyhow!(
                    "failed to launch {bundle_identifier}{detail}"
                ));
            }
        }
    };

    // Attach the debugger via debugproxy, which grants the process JIT
    // entitlement, then detach and let the app keep running.
    let mut debug_proxy =
        idevice::debug_proxy::DebugProxyClient::connect_rsd(&mut provider, &mut handshake).await?;

    let attach_command = format!("vAttach;{pid:x}");
    let attach_response = debug_proxy
        .send_command(attach_command.as_str().into())
        .await
        .map_err(|e| anyhow::anyhow!("failed to attach debugger to PID {pid}: {e:?}"))?;
    match attach_response.as_deref() {
        Some(response) if response.starts_with('T') => {
            log::info!("Debugger attached to PID {pid}: {response}");
        }
        Some(response) if response.starts_with('E') || response.is_empty() => {
            return Err(anyhow::anyhow!(
                "debugger failed to attach to PID {pid}: {response}"
            ));
        }
        Some(response) => {
            log::info!("Debugger attach response for PID {pid}: {response}");
        }
        None => {
            return Err(anyhow::anyhow!(
                "debugger attach to PID {pid} received no response"
            ));
        }
    }

    match debug_proxy.send_command("D".into()).await {
        Ok(response) => {
            log::info!("Debugger detached: {response:?}");
        }
        Err(e) => {
            log::warn!("Debugger detach returned error (JIT may still be enabled): {e:?}");
        }
    }

    log::info!("SUCCESS: JIT enabled for {bundle_identifier} (PID {pid})");
    Ok(())
}

async fn resolve_bundle_identifier(
    provider: &mut impl idevice::provider::RsdProvider,
    handshake: &mut idevice::rsd::RsdHandshake,
    requested: &str,
) -> Result<String> {
    let mut proxy = match idevice::installation_proxy::InstallationProxyClient::connect_rsd(
        provider, handshake,
    )
    .await
    {
        Ok(proxy) => proxy,
        Err(e) => {
            log::warn!("Failed to connect installation proxy ({e:?}); using '{requested}' as-is");
            return Ok(requested.to_string());
        }
    };
    let apps = match proxy.get_apps(Some("User"), None).await {
        Ok(apps) => apps,
        Err(e) => {
            log::warn!("Failed to list installed apps ({e:?}); using '{requested}' as-is");
            return Ok(requested.to_string());
        }
    };
    match_installed_bundle_id(requested, &apps)
}

fn match_installed_bundle_id(
    requested: &str,
    apps: &HashMap<String, plist::Value>,
) -> Result<String> {
    if apps.contains_key(requested) {
        return Ok(requested.to_string());
    }
    // Signing rewrites the identifier to "{clean_id}.{team_id}", so an
    // installed ID either equals the request or extends it past a '.'.
    let prefix = format!("{requested}.");
    let mut candidates: Vec<&String> = apps.keys().filter(|id| id.starts_with(&prefix)).collect();
    candidates.sort();
    match candidates.len() {
        0 => Err(anyhow::anyhow!(
            "app '{requested}' is not installed (no installed user app ID equals it or starts with '{prefix}')"
        )),
        1 => {
            let matched = candidates[0].clone();
            log::info!("Resolved bundle identifier '{requested}' to installed app '{matched}'");
            Ok(matched)
        }
        _ => {
            let matched = candidates[0].clone();
            log::info!(
                "Bundle identifier '{requested}' matches multiple installed apps ({}); using first match '{matched}'",
                candidates
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Ok(matched)
        }
    }
}

fn parse_pid(value: &Option<Value>) -> Option<u64> {
    match value {
        Some(Value::Integer(v)) => v.as_unsigned(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

fn extract_ns_error_message(value: &Value) -> Option<String> {
    let dict = match value {
        Value::Dictionary(dict) => dict,
        _ => return None,
    };

    let user_info = match dict.get("NSUserInfo") {
        Some(Value::Array(items)) => items,
        _ => {
            return dict
                .get("NSLocalizedDescription")
                .and_then(Value::as_string)
                .map(ToOwned::to_owned);
        }
    };

    let mut description = dict
        .get("NSLocalizedDescription")
        .and_then(Value::as_string)
        .map(ToOwned::to_owned);
    let mut reason = dict
        .get("NSLocalizedFailureReason")
        .and_then(Value::as_string)
        .map(ToOwned::to_owned);

    for entry in user_info {
        let Value::Dictionary(item) = entry else {
            continue;
        };

        let key = item.get("key").and_then(Value::as_string);
        let value = item.get("value");

        match (key, value) {
            (Some("NSLocalizedDescription"), Some(Value::String(s))) if description.is_none() => {
                description = Some(s.clone());
            }
            (Some("NSLocalizedFailureReason"), Some(Value::String(s))) if reason.is_none() => {
                reason = Some(s.clone());
            }
            (Some("NSUnderlyingError"), Some(v)) => {
                if let Some(message) = extract_ns_error_message(v) {
                    return Some(message);
                }
            }
            _ => {}
        }
    }

    match (description, reason) {
        (Some(description), Some(reason)) => Some(format!("{description}: {reason}")),
        (Some(description), None) => Some(description),
        (None, Some(reason)) => Some(reason),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_apps() -> HashMap<String, plist::Value> {
        [
            "com.etan.tv.BilibiliLive.A1B2C3D4E5",
            "com.example.other",
            "com.example.other2.X",
        ]
        .into_iter()
        .map(|id| (id.to_string(), plist::Value::Dictionary(Dictionary::new())))
        .collect()
    }

    #[test]
    fn exact_match_wins() {
        let apps = test_apps();
        assert_eq!(
            match_installed_bundle_id("com.example.other", &apps).unwrap(),
            "com.example.other"
        );
    }

    #[test]
    fn prefix_match_resolves_suffixed_id() {
        let apps = test_apps();
        assert_eq!(
            match_installed_bundle_id("com.etan.tv.BilibiliLive", &apps).unwrap(),
            "com.etan.tv.BilibiliLive.A1B2C3D4E5"
        );
    }

    #[test]
    fn prefix_requires_dot_boundary() {
        let apps = test_apps();
        // Without the '.' boundary, "com.exampl" would prefix-match everything.
        assert!(match_installed_bundle_id("com.exampl", &apps).is_err());
        // With the boundary, the team-ID suffix still resolves.
        assert_eq!(
            match_installed_bundle_id("com.example.other2", &apps).unwrap(),
            "com.example.other2.X"
        );
    }

    #[test]
    fn multiple_candidates_use_first_sorted() {
        let apps = test_apps();
        assert_eq!(
            match_installed_bundle_id("com.example", &apps).unwrap(),
            "com.example.other"
        );
    }

    #[test]
    fn no_match_errors() {
        let apps = test_apps();
        assert!(match_installed_bundle_id("com.missing.app", &apps).is_err());
    }
}
