//! A library to generate "anisette" data. Docs are coming soon.
//!
//! If you want an async API, enable the `async` feature.
//!
//! If you want remote anisette, make sure the `remote-anisette` feature is enabled. (it's currently on by default)

use crate::adi_proxy::{ADIProxyAnisetteProvider, ConfigurableADIProxy};
use crate::anisette_headers_provider::AnisetteHeadersProvider;
use std::io;
use std::path::PathBuf;
use adi_proxy::ADIError;
use thiserror::Error;

pub mod adi_proxy;
pub mod anisette_headers_provider;
pub mod store_services_core;

#[cfg(feature = "remote-anisette-v3")]
pub mod remote_anisette_v3;

#[cfg(target_os = "macos")]
pub mod aos_kit;

#[cfg(feature = "remote-anisette")]
pub mod remote_anisette;

#[allow(dead_code)]
pub struct AnisetteHeaders;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum AnisetteError {
    #[allow(dead_code)]
    #[error("Unsupported device")]
    UnsupportedDevice,
    #[error("Invalid argument {0}")]
    InvalidArgument(String),
    #[error("Anisette not provisioned!")]
    AnisetteNotProvisioned,
    #[error("Plist serialization error {0}")]
    PlistError(#[from] plist::Error),
    #[error("Request Error {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[cfg(feature = "remote-anisette-v3")]
    #[error("Provisioning socket error {0}")]
    WsError(#[from] tokio_tungstenite::tungstenite::error::Error),
    #[cfg(feature = "remote-anisette-v3")]
    #[error("JSON error {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("IO error {0}")]
    IOError(#[from] io::Error),
    #[error("ADI error {0}")]
    ADIError(#[from] ADIError),
    #[error("Invalid library format")]
    InvalidLibraryFormat,
    #[error("Misc")]
    Misc,
    #[error("Missing Libraries")]
    MissingLibraries,
    #[error("{0}")]
    Anyhow(#[from] anyhow::Error)
}

pub const DEFAULT_ANISETTE_URL: &str = "https://ani.f1sh.me/";

pub const DEFAULT_ANISETTE_URL_V3: &str = "https://new.ani.sidestore.io";

/// Server that still speaks the pre-ADIB `adi_pb` format.  Anisette data
/// provisioned by older versions can only be used against this server.
pub const LEGACY_ANISETTE_URL_V3: &str = "https://ani.sidestore.io";

/// Directory (relative to `configuration_path`) holding per-account anisette
/// state, one subdirectory per Apple ID `adsid`.
pub const ANISETTE_ACCOUNT_DIR: &str = "anisette";

#[derive(Clone, Debug)]
pub struct AnisetteConfiguration {
    anisette_url: String,
    anisette_url_v3: String,
    configuration_path: PathBuf,
    macos_serial: String,
    /// When set, state lives in `<configuration_path>/anisette/<account>/`.
    account_id: Option<String>,
    /// This provider is being created for a login flow.
    login_mode: bool,
    /// Server to use for states holding a pre-ADIB `adi_pb`.
    legacy_server_url_v3: Option<String>,
}

impl Default for AnisetteConfiguration {
    fn default() -> Self {
        AnisetteConfiguration::new()
    }
}

impl AnisetteConfiguration {
    pub fn new() -> AnisetteConfiguration {
        AnisetteConfiguration {
            anisette_url: DEFAULT_ANISETTE_URL.to_string(),
            anisette_url_v3: DEFAULT_ANISETTE_URL_V3.to_string(),
            configuration_path: PathBuf::new(),
            macos_serial: "0".to_string(),
            account_id: None,
            login_mode: false,
            legacy_server_url_v3: Some(LEGACY_ANISETTE_URL_V3.to_string()),
        }
    }

    pub fn anisette_url(&self) -> &String {
        &self.anisette_url
    }

    pub fn anisette_url_v3(&self) -> &String {
        &self.anisette_url_v3
    }

    pub fn configuration_path(&self) -> &PathBuf {
        &self.configuration_path
    }

    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    pub fn login_mode(&self) -> bool {
        self.login_mode
    }

    pub fn legacy_server_url_v3(&self) -> Option<&String> {
        self.legacy_server_url_v3.as_ref()
    }

    pub fn set_legacy_server_url_v3(mut self, url: String) -> AnisetteConfiguration {
        self.legacy_server_url_v3 = Some(url);
        self
    }

    /// Directory holding this account's `state.plist`, or the legacy shared
    /// location when no account is selected.
    pub fn state_dir(&self) -> PathBuf {
        match &self.account_id {
            Some(account) => self
                .configuration_path
                .join(ANISETTE_ACCOUNT_DIR)
                .join(account_dir_name(account)),
            None => self.configuration_path.clone(),
        }
    }

    pub fn set_anisette_url(mut self, anisette_url: String) -> AnisetteConfiguration {
        self.anisette_url = anisette_url;
        self
    }

    pub fn set_anisette_url_v3(mut self, anisette_url_v3: String) -> AnisetteConfiguration {
        self.anisette_url_v3 = anisette_url_v3;
        self
    }

    pub fn set_macos_serial(mut self, macos_serial: String) -> AnisetteConfiguration {
        self.macos_serial = macos_serial;
        self
    }

    pub fn set_configuration_path(mut self, configuration_path: PathBuf) -> AnisetteConfiguration {
        self.configuration_path = configuration_path;
        self
    }

    pub fn set_account_id(mut self, account: String) -> AnisetteConfiguration {
        self.account_id = Some(account);
        self
    }

    /// Marks this configuration as belonging to a login flow.
    ///
    /// It does not discard existing anisette data: an account that already has
    /// a working `adi_pb` keeps using it.
    pub fn set_login_mode(mut self, login: bool) -> AnisetteConfiguration {
        self.login_mode = login;
        self
    }
}

pub enum AnisetteHeadersProviderType {
    Local,
    Remote,
}

pub struct AnisetteHeadersProviderRes {
    pub provider: Box<dyn AnisetteHeadersProvider>,
    pub provider_type: AnisetteHeadersProviderType,
}

impl AnisetteHeadersProviderRes {
    pub fn local(provider: Box<dyn AnisetteHeadersProvider>) -> AnisetteHeadersProviderRes {
        AnisetteHeadersProviderRes {
            provider,
            provider_type: AnisetteHeadersProviderType::Local,
        }
    }

    pub fn remote(provider: Box<dyn AnisetteHeadersProvider>) -> AnisetteHeadersProviderRes {
        AnisetteHeadersProviderRes {
            provider,
            provider_type: AnisetteHeadersProviderType::Remote,
        }
    }
}

/// Whether the configuration's data directory holds anisette data written by
/// the local SSC provider (`identifier` / `adi.pb`).
fn has_local_anisette_data(configuration: &AnisetteConfiguration) -> bool {
    let root = configuration.configuration_path();
    if configuration.account_id().is_some() {
        // Per-account state takes precedence; SSC only owns the shared files.
        if configuration.state_dir().join("state.plist").exists() {
            return false;
        }
    }
    // `identifier` alone is not evidence of local use: older remote versions
    // also created it.  The provisioning blob only exists for SSC accounts.
    root.join("adi.pb").exists()
}

impl AnisetteHeaders {
    /// Provider for a login: always provisions a fresh `adi_pb` with the
    /// identity advertised by the anisette server, so the newly issued
    /// `xcode_gs_token` matches that identity.
    pub fn get_login_anisette_headers_provider(
        configuration: AnisetteConfiguration,
    ) -> Result<AnisetteHeadersProviderRes, AnisetteError> {
        Self::get_anisette_headers_provider(configuration.set_login_mode(true))
    }

    pub fn get_anisette_headers_provider(
        configuration: AnisetteConfiguration,
    ) -> Result<AnisetteHeadersProviderRes, AnisetteError> {
        #[cfg(all(target_os = "macos", feature = "aos-kit"))]
        if let Ok(prov) = aos_kit::AOSKitAnisetteProvider::new() {
            return Ok(AnisetteHeadersProviderRes::local(Box::new(prov)));
        }

        // Local SSC is kept for accounts provisioned with it: their adi lives
        // in the SSC provisioning directory and cannot be consumed by a
        // remote server.  Only use it when that data exists and the account
        // has no per-account remote state yet.
        if !configuration.login_mode() && has_local_anisette_data(&configuration) {
            if let Ok(ssc) =
                AnisetteHeaders::get_ssc_anisette_headers_provider(configuration.clone())
            {
                return Ok(ssc);
            }
        }

        #[cfg(feature = "remote-anisette-v3")]
        return Ok(AnisetteHeadersProviderRes::remote(Box::new(
            remote_anisette_v3::RemoteAnisetteProviderV3::with_mode(
                configuration.anisette_url_v3.clone(),
                configuration.state_dir(),
                configuration.macos_serial.clone(),
                configuration.login_mode(),
                // Legacy shared files live in the data root, two levels above
                // `<root>/anisette/<email>/`.
                configuration
                    .account_id()
                    .map(|_| configuration.configuration_path().clone()),
                configuration.legacy_server_url_v3().cloned(),
            ),
        )));

        #[cfg(feature = "remote-anisette")]
        return Ok(AnisetteHeadersProviderRes::remote(Box::new(
            remote_anisette::RemoteAnisetteProvider::new(configuration.anisette_url),
        )));

        #[cfg(not(feature = "remote-anisette"))]
        bail!(AnisetteMetaError::UnsupportedDevice)
    }

    pub fn get_ssc_anisette_headers_provider(
        configuration: AnisetteConfiguration,
    ) -> Result<AnisetteHeadersProviderRes, AnisetteError> {
        let mut ssc_adi_proxy = store_services_core::StoreServicesCoreADIProxy::new(
            configuration.configuration_path(),
        )?;
        let config_path = configuration.configuration_path();
        ssc_adi_proxy.set_provisioning_path(config_path.to_str().ok_or(
            AnisetteError::InvalidArgument("configuration.configuration_path".to_string()),
        )?)?;
        Ok(AnisetteHeadersProviderRes::local(Box::new(
            ADIProxyAnisetteProvider::new(ssc_adi_proxy, config_path.to_path_buf())?,
        )))
    }
}

#[cfg(test)]
mod tests {
    use log::LevelFilter;
    use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};

    pub fn init_logger() {
        if TermLogger::init(
            LevelFilter::Trace,
            ConfigBuilder::new()
                .set_target_level(LevelFilter::Error)
                .add_filter_allow_str("omnisette")
                .build(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
        .is_ok()
        {}
    }

    #[cfg(not(feature = "async"))]
    #[test]
    fn fetch_anisette_auto() -> Result<()> {
        use crate::{AnisetteConfiguration, AnisetteHeaders};
        use log::info;
        use std::path::PathBuf;

        crate::tests::init_logger();

        let mut provider = AnisetteHeaders::get_anisette_headers_provider(
            AnisetteConfiguration::new()
                .set_configuration_path(PathBuf::new().join("anisette_test")),
        )?;
        info!(
            "Headers: {:?}",
            provider.provider.get_authentication_headers()?
        );
        Ok(())
    }
}

/// Map an account identifier (an Apple ID email) to a filesystem-safe
/// directory name without exposing it.
///
/// Uses SHA-256 over the normalised (trimmed, lowercased) email so the same
/// Apple ID always maps to the same directory on case-insensitive
/// filesystems, while the directory name reveals nothing about the user.
pub fn account_dir_name(account: &str) -> String {
    use sha2::{Digest, Sha256};
    let normalised = account.trim().to_lowercase();
    let digest = Sha256::digest(normalised.as_bytes());
    let mut out = String::with_capacity(32);
    for byte in &digest[..16] {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
