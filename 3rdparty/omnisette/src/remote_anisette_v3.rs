// Implementing the SideStore Anisette v3 protocol

use std::{collections::HashMap, fs, io::Cursor, path::PathBuf, time::Duration};

use crate::adi_proxy::{AKD_USER_AGENT, LOOKUP_CLIENT_INFO};
use async_trait::async_trait;
use base64::engine::general_purpose;
use base64::Engine;
use chrono::{DateTime, SubsecRound, Utc};
use futures_util::{stream::StreamExt, SinkExt};
use log::debug;
use plist::{Data, Dictionary};
use rand::Rng;
use reqwest::{Client, ClientBuilder, RequestBuilder, Response};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

use crate::{anisette_headers_provider::AnisetteHeadersProvider, AnisetteError};

fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, plist::Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

fn bin_serialize_opt<S>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(|i| Data::new(i)).serialize(s)
}

fn bin_deserialize_opt<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| i.into()))
}

fn bin_deserialize_16<'de, D>(d: D) -> Result<[u8; 16], D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    let s: Vec<u8> = s.into();
    Ok(s.try_into().unwrap())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(data.trim()).unwrap()
}

#[derive(Deserialize)]
struct AnisetteClientInfo {
    client_info: String,
    user_agent: String,
}

/// The client identity used by the stock (pre-server-identity) anisette flow.
///
/// Apple binds the developer session token (`xcode_gs_token`) to the
/// `X-Mme-Client-Info` that was used when the token was issued.  Every state
/// written before this field existed was provisioned with this identity, so
/// it has to be kept as the fallback; otherwise old accounts start failing
/// with `1100 Your session has expired` as soon as the header changes.
pub const LEGACY_CLIENT_INFO: &str =
    "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
pub const LEGACY_USER_AGENT: &str = "akd/1.0 CFNetwork/808.1.4";

#[derive(Serialize, Deserialize)]
pub struct AnisetteState {
    #[serde(
        serialize_with = "bin_serialize",
        deserialize_with = "bin_deserialize_16"
    )]
    keychain_identifier: [u8; 16],
    #[serde(
        serialize_with = "bin_serialize_opt",
        deserialize_with = "bin_deserialize_opt",
        default
    )]
    adi_pb: Option<Vec<u8>>,
    /// Identity this `adi_pb` was provisioned with.  `None` for states written
    /// by older versions, which are treated as [`LEGACY_CLIENT_INFO`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_info: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
}

impl Default for AnisetteState {
    fn default() -> Self {
        AnisetteState {
            keychain_identifier: rand::rng().random::<[u8; 16]>(),
            adi_pb: None,
            client_info: None,
            user_agent: None,
        }
    }
}

impl AnisetteState {
    pub fn new() -> AnisetteState {
        AnisetteState::default()
    }

    pub fn with_identifier(keychain_identifier: [u8; 16]) -> AnisetteState {
        AnisetteState {
            keychain_identifier,
            ..AnisetteState::default()
        }
    }

    pub fn is_provisioned(&self) -> bool {
        self.adi_pb.is_some()
    }

    /// Identity to use for Apple requests, falling back to the legacy one for
    /// states that predate identity tracking.
    fn identity(&self) -> (&str, &str) {
        (
            self.client_info.as_deref().unwrap_or(LEGACY_CLIENT_INFO),
            self.user_agent.as_deref().unwrap_or(LEGACY_USER_AGENT),
        )
    }

    /// Record the identity that was used to provision `adi_pb`.
    pub fn set_identity(&mut self, client_info: String, user_agent: String) {
        self.client_info = Some(client_info);
        self.user_agent = Some(user_agent);
    }

    /// True for states written by versions that did not track identity.
    pub fn has_recorded_identity(&self) -> bool {
        self.client_info.is_some()
    }

    #[doc(hidden)]
    pub fn identity_for_test(&self) -> (&str, &str) {
        self.identity()
    }

    #[doc(hidden)]
    pub fn device_id_for_test(&self) -> String {
        self.device_id()
    }

    #[doc(hidden)]
    pub fn set_adi_pb_for_test(&mut self, adi_pb: Vec<u8>) {
        self.adi_pb = Some(adi_pb);
    }

    fn md_lu(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.keychain_identifier);
        hasher.finalize().into()
    }

    fn device_id(&self) -> String {
        Uuid::from_bytes(self.keychain_identifier).to_string()
    }
}
pub struct AnisetteClient {
    client_info: AnisetteClientInfo,
    url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ProvisionBodyData {
    header: Dictionary,
    request: Dictionary,
}

#[derive(Debug)]
pub struct AnisetteData {
    machine_id: String,
    one_time_password: String,
    routing_info: String,
    device_description: String,
    local_user_id: String,
    device_unique_identifier: String,
}

impl AnisetteData {
    pub fn get_headers(&self, serial: String) -> HashMap<String, String> {
        let dt: DateTime<Utc> = Utc::now().round_subsecs(0);

        HashMap::from_iter(
            [
                (
                    "X-Apple-I-Client-Time".to_string(),
                    dt.format("%+").to_string().replace("+00:00", "Z"),
                ),
                ("X-Apple-I-SRL-NO".to_string(), serial),
                ("X-Apple-I-TimeZone".to_string(), "UTC".to_string()),
                ("X-Apple-Locale".to_string(), "en_US".to_string()),
                ("X-Apple-I-MD-RINFO".to_string(), self.routing_info.clone()),
                ("X-Apple-I-MD-LU".to_string(), self.local_user_id.clone()),
                (
                    "X-Mme-Device-Id".to_string(),
                    self.device_unique_identifier.clone(),
                ),
                ("X-Apple-I-MD".to_string(), self.one_time_password.clone()),
                ("X-Apple-I-MD-M".to_string(), self.machine_id.clone()),
                (
                    "X-Mme-Client-Info".to_string(),
                    self.device_description.clone(),
                ),
            ]
            .into_iter(),
        )
    }
}

/// Wire format of a stored `adi_pb`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdiFormat {
    /// `ADIB` bundle, produced by newer servers (adid_anisette).
    Adib,
    /// Pre-ADIB ADI blob (`00 00 00 01 ...`), produced by older servers.
    Legacy,
    /// Anything else; treated as legacy so it is sent to the legacy server.
    Unknown,
}

impl AdiFormat {
    pub fn of(adi_pb: &[u8]) -> AdiFormat {
        if adi_pb.starts_with(b"ADIB") {
            AdiFormat::Adib
        } else if adi_pb.starts_with(&[0, 0, 0, 1]) {
            AdiFormat::Legacy
        } else {
            AdiFormat::Unknown
        }
    }
}

/// How often a request is attempted before giving up.
const HTTP_ATTEMPTS: usize = 3;

/// Delay between attempts.  The anisette servers are occasionally fronted by
/// a proxy that answers 502 with an empty body, so a short retry is enough.
const HTTP_RETRY_DELAY: Duration = Duration::from_secs(3);

/// Decode a JSON body, turning an empty or malformed body into a readable
/// error instead of a bare "error decoding response body".
async fn decode_json<T: serde::de::DeserializeOwned>(
    response: Response,
    what: &str,
) -> Result<T, AnisetteError> {
    let status = response.status();
    let text = response.text().await?;
    if text.trim().is_empty() {
        return Err(AnisetteError::InvalidArgument(format!(
            "anisette server returned an empty body for {what} (HTTP {status}); \
             please try again later"
        )));
    }
    serde_json::from_str::<T>(&text).map_err(|err| {
        AnisetteError::InvalidArgument(format!(
            "anisette server returned an unexpected body for {what} (HTTP {status}); \
             please try again later: {err}"
        ))
    })
}

/// Send a request, retrying on transport errors and 5xx responses.
async fn send_with_retry(build: impl Fn() -> RequestBuilder) -> Result<Response, AnisetteError> {
    let mut last_error: Option<AnisetteError> = None;
    for attempt in 0..HTTP_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(HTTP_RETRY_DELAY).await;
        }
        match build().send().await {
            Ok(response) if response.status().is_server_error() => {
                debug!(
                    "anisette server returned {} (attempt {}/{})",
                    response.status(),
                    attempt + 1,
                    HTTP_ATTEMPTS
                );
                last_error = Some(AnisetteError::InvalidArgument(format!(
                    "anisette server returned HTTP {}; please try again later",
                    response.status()
                )));
            }
            Ok(response) => return response.error_for_status().map_err(Into::into),
            Err(err) => {
                debug!(
                    "anisette request failed: {err} (attempt {}/{})",
                    attempt + 1,
                    HTTP_ATTEMPTS
                );
                last_error = Some(AnisetteError::InvalidArgument(format!(
                    "anisette request failed; please try again later: {err}"
                )));
            }
        }
    }
    Err(last_error.unwrap_or(AnisetteError::Misc))
}

fn make_reqwest() -> Result<Client, AnisetteError> {
    Ok(ClientBuilder::new()
        .http1_title_case_headers()
        .danger_accept_invalid_certs(true) // TODO: pin the apple certificate
        .build()?)
}

impl AnisetteClient {
    pub async fn new(url: String) -> Result<AnisetteClient, AnisetteError> {
        let path = format!("{}/v3/client_info", url);
        let http_client = make_reqwest()?;
        let response = send_with_retry(|| http_client.get(&path)).await?;
        let client_info = decode_json::<AnisetteClientInfo>(response, "/v3/client_info").await?;
        Ok(AnisetteClient { client_info, url })
    }

    /// Identity advertised by the anisette server.  Only used when provisioning
    /// a fresh state; existing states keep the identity they were provisioned
    /// with so that tokens stay valid.
    pub fn server_identity(&self) -> (&str, &str) {
        (&self.client_info.client_info, &self.client_info.user_agent)
    }

    fn build_apple_request(
        &self,
        state: &AnisetteState,
        builder: RequestBuilder,
        client_info: &str,
        user_agent: &str,
    ) -> RequestBuilder {
        let dt: DateTime<Utc> = Utc::now().round_subsecs(0);

        builder
            .header("X-Mme-Client-Info", client_info)
            .header("User-Agent", user_agent)
            .header("Content-Type", "text/x-xml-plist")
            .header("X-Apple-I-MD-LU", encode_hex(&state.md_lu()))
            .header("X-Mme-Device-Id", state.device_id())
            .header("X-Apple-I-Client-Time", dt.format("%+").to_string())
            .header("X-Apple-I-TimeZone", "UTC")
            .header("X-Apple-Locale", "en_US")
    }

    pub async fn get_headers(&self, state: &AnisetteState) -> Result<AnisetteData, AnisetteError> {
        let path = format!("{}/v3/get_headers", self.url);
        let http_client = make_reqwest()?;

        #[derive(Serialize)]
        struct GetHeadersBody {
            identifier: String,
            adi_pb: String,
        }
        let body = GetHeadersBody {
            identifier: base64_encode(&state.keychain_identifier),
            adi_pb: base64_encode(
                state
                    .adi_pb
                    .as_ref()
                    .ok_or(AnisetteError::AnisetteNotProvisioned)?,
            ),
        };

        #[derive(Deserialize)]
        #[serde(tag = "result")]
        enum AnisetteHeaders {
            GetHeadersError {
                message: String,
            },
            Headers {
                #[serde(rename = "X-Apple-I-MD-M")]
                machine_id: String,
                #[serde(rename = "X-Apple-I-MD")]
                one_time_password: String,
                #[serde(rename = "X-Apple-I-MD-RINFO")]
                routing_info: String,
            },
        }

        let response = send_with_retry(|| http_client.post(&path).json(&body)).await?;
        let headers = decode_json::<AnisetteHeaders>(response, "/v3/get_headers").await?;
        match headers {
            AnisetteHeaders::GetHeadersError { message } => {
                if message.contains("-45061") {
                    Err(AnisetteError::AnisetteNotProvisioned)
                } else if message.contains("-80045") {
                    // Apple rejects the identity this `adi_pb` was provisioned
                    // with; the caller has to provision again with the current
                    // server identity.
                    Err(AnisetteError::AnisetteNotProvisioned)
                } else {
                    Err(AnisetteError::InvalidArgument(message))
                }
            }
            AnisetteHeaders::Headers {
                machine_id,
                one_time_password,
                routing_info,
            } => Ok(AnisetteData {
                machine_id,
                one_time_password,
                routing_info,
                device_description: state.identity().0.to_string(),
                local_user_id: encode_hex(&state.md_lu()),
                device_unique_identifier: state.device_id(),
            }),
        }
    }

    /// Provision a new `adi_pb` using `client_info`/`user_agent`.
    ///
    /// The identity is baked into the resulting `adi_pb`, so callers must pass
    /// the identity the account's token was issued with.  Logging in uses the
    /// server identity; refreshing reuses the stored one.
    pub async fn provision(
        &self,
        state: &mut AnisetteState,
        client_info: &str,
        user_agent: &str,
    ) -> Result<(), AnisetteError> {
        debug!("Provisioning Anisette");

        let http_client = make_reqwest()?;
        let resp = self
            .build_apple_request(
                &state,
                http_client.get("https://gsa.apple.com/grandslam/GsService2/lookup"),
                LOOKUP_CLIENT_INFO,
                AKD_USER_AGENT,
            )
            .send()
            .await?;
        let text = resp.text().await?;

        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
        let urls = protocol_val
            .as_dictionary()
            .unwrap()
            .get("urls")
            .unwrap()
            .as_dictionary()
            .unwrap();

        let start_provisioning_url = urls
            .get("midStartProvisioning")
            .unwrap()
            .as_string()
            .unwrap();
        let end_provisioning_url = urls
            .get("midFinishProvisioning")
            .unwrap()
            .as_string()
            .unwrap();
        debug!(
            "Got provisioning urls: {} and {}",
            start_provisioning_url, end_provisioning_url
        );

        let provision_ws_url =
            format!("{}/v3/provisioning_session", self.url).replace("https://", "wss://");
        let (mut connection, _) = connect_async(&provision_ws_url).await?;

        #[derive(Deserialize)]
        #[serde(tag = "result")]
        enum ProvisionInput {
            GiveIdentifier,
            GiveStartProvisioningData,
            GiveEndProvisioningData {
                #[allow(dead_code)] // it's not even dead, rust just has problems
                cpim: String,
            },
            ProvisioningSuccess {
                #[allow(dead_code)] // it's not even dead, rust just has problems
                adi_pb: String,
            },
        }

        loop {
            let Some(Ok(data)) = connection.next().await else {
                continue;
            };
            if data.is_text() {
                let txt = data.to_text().unwrap();
                let msg: ProvisionInput = serde_json::from_str(txt)?;
                match msg {
                    ProvisionInput::GiveIdentifier => {
                        #[derive(Serialize)]
                        struct Identifier {
                            identifier: String, // base64
                        }
                        let identifier = Identifier {
                            identifier: base64_encode(&state.keychain_identifier),
                        };
                        connection
                            .send(Message::Text(serde_json::to_string(&identifier)?.into()))
                            .await?;
                    }
                    ProvisionInput::GiveStartProvisioningData => {
                        let http_client = make_reqwest()?;
                        let body_data = ProvisionBodyData {
                            header: Dictionary::new(),
                            request: Dictionary::new(),
                        };
                        let resp = self
                            .build_apple_request(
                                state,
                                http_client.post(start_provisioning_url),
                                client_info,
                                user_agent,
                            )
                            .body(plist_to_string(&body_data)?)
                            .send()
                            .await?;
                        let text = resp.text().await?;

                        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
                        let spim = protocol_val
                            .as_dictionary()
                            .unwrap()
                            .get("Response")
                            .unwrap()
                            .as_dictionary()
                            .unwrap()
                            .get("spim")
                            .unwrap()
                            .as_string()
                            .unwrap();

                        debug!("GiveStartProvisioningData");
                        #[derive(Serialize)]
                        struct Spim {
                            spim: String, // base64
                        }
                        let spim = Spim {
                            spim: spim.to_string(),
                        };
                        connection
                            .send(Message::Text(serde_json::to_string(&spim)?.into()))
                            .await?;
                    }
                    ProvisionInput::GiveEndProvisioningData { cpim } => {
                        let http_client = make_reqwest()?;
                        let body_data = ProvisionBodyData {
                            header: Dictionary::new(),
                            request: Dictionary::from_iter([("cpim", cpim)].into_iter()),
                        };
                        let resp = self
                            .build_apple_request(
                                state,
                                http_client.post(end_provisioning_url),
                                client_info,
                                user_agent,
                            )
                            .body(plist_to_string(&body_data)?)
                            .send()
                            .await?;
                        let text = resp.text().await?;

                        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
                        let response = protocol_val
                            .as_dictionary()
                            .unwrap()
                            .get("Response")
                            .unwrap()
                            .as_dictionary()
                            .unwrap();

                        debug!("GiveEndProvisioningData");

                        #[derive(Serialize)]
                        struct EndProvisioning<'t> {
                            ptm: &'t str,
                            tk: &'t str,
                        }
                        let end_provisioning = EndProvisioning {
                            ptm: response.get("ptm").unwrap().as_string().unwrap(),
                            tk: response.get("tk").unwrap().as_string().unwrap(),
                        };
                        connection
                            .send(Message::Text(
                                serde_json::to_string(&end_provisioning)?.into(),
                            ))
                            .await?;
                    }
                    ProvisionInput::ProvisioningSuccess { adi_pb } => {
                        debug!("ProvisioningSuccess");
                        state.adi_pb = Some(base64_decode(&adi_pb));
                        state.set_identity(client_info.to_string(), user_agent.to_string());
                        connection.close(None).await?;
                        break;
                    }
                }
            } else if data.is_close() {
                break;
            }
        }

        Ok(())
    }
}

pub struct RemoteAnisetteProviderV3 {
    client_url: String,
    client: Option<AnisetteClient>,
    pub state: Option<AnisetteState>,
    configuration_path: PathBuf,
    serial: String,
    /// True when this provider is used for a login.  A login may adopt the
    /// server identity only for states that cannot be used as-is; an account
    /// that already has a working `adi_pb` keeps it.
    login_mode: bool,
    /// Data root holding legacy `state.plist` / `identifier` / `adi.pb`.
    legacy_root: Option<PathBuf>,
    /// Whether `configuration_path` is the account's own directory.  Legacy
    /// shared files must never be overwritten.
    account_scoped: bool,
    /// Server able to consume a pre-ADIB `adi_pb`.
    legacy_server_url: Option<String>,
}

impl RemoteAnisetteProviderV3 {
    pub fn new(
        url: String,
        configuration_path: PathBuf,
        serial: String,
    ) -> RemoteAnisetteProviderV3 {
        Self::with_mode(url, configuration_path, serial, false, None, None)
    }

    pub fn with_mode(
        url: String,
        configuration_path: PathBuf,
        serial: String,
        login_mode: bool,
        legacy_root: Option<PathBuf>,
        legacy_server_url: Option<String>,
    ) -> RemoteAnisetteProviderV3 {
        let account_scoped = configuration_path_is_account_dir(&configuration_path);
        RemoteAnisetteProviderV3 {
            client_url: url,
            client: None,
            state: None,
            configuration_path,
            serial,
            login_mode,
            // Scoped only when the state path is the per-account directory;
            // otherwise it is the legacy shared root and must stay read-only.
            account_scoped,
            legacy_root,
            legacy_server_url,
        }
    }

    /// Load state for this account.
    ///
    /// Order: the account's own `state.plist`; the legacy shared `state.plist`
    /// (older versions kept a single global state); the legacy local layout
    /// (`identifier` + `adi.pb`).  Legacy files are read only and never
    /// rewritten, so downgrading keeps working.
    fn load_state(&mut self) -> Result<(), AnisetteError> {
        let own = self.configuration_path.join("state.plist");
        if let Ok(state) = plist::from_file::<_, AnisetteState>(&own) {
            self.state = Some(state);
            return Ok(());
        }

        // A login starts a new device identity for this account.  Falling back
        // to the legacy shared state here would make the account inherit the
        // previous global identifier, which is not what "log in" means once
        // state is per account.
        if self.login_mode && self.account_scoped {
            self.state = Some(AnisetteState::new());
            return Ok(());
        }

        if let Some(root) = &self.legacy_root {
            let legacy_global = root.join("state.plist");
            if let Ok(state) = plist::from_file::<_, AnisetteState>(&legacy_global) {
                self.state = Some(state);
                return Ok(());
            }

            let legacy_identifier = root.join("identifier");
            let legacy_adi = root.join("adi.pb");
            if let (Ok(identifier), Ok(adi_pb)) = (
                std::fs::read(&legacy_identifier),
                std::fs::read(&legacy_adi),
            ) {
                if identifier.len() == 16 {
                    let mut keychain_identifier = [0u8; 16];
                    keychain_identifier.copy_from_slice(&identifier);
                    let mut state = AnisetteState::with_identifier(keychain_identifier);
                    state.adi_pb = Some(adi_pb);
                    self.state = Some(state);
                    return Ok(());
                }
            }
        }

        self.state = Some(AnisetteState::new());
        Ok(())
    }
}

#[async_trait]
impl AnisetteHeadersProvider for RemoteAnisetteProviderV3 {
    async fn get_anisette_headers(
        &mut self,
        _skip_provisioning: bool,
    ) -> Result<HashMap<String, String>, AnisetteError> {
        if self.state.is_none() {
            self.load_state()?;
        }

        // A stored pre-ADIB `adi_pb` can only be consumed by the legacy
        // server, so pick the endpoint based on the data we actually have.
        // New states and fresh provisioning use the configured server.
        if self.client.is_none() {
            let url = self.effective_server_url();
            self.client = Some(AnisetteClient::new(url).await?);
        }

        let (server_client_info, server_user_agent) = {
            let (ci, ua) = self.client.as_ref().unwrap().server_identity();
            (ci.to_string(), ua.to_string())
        };

        let state = self.state.as_ref().unwrap();
        let has_adi = state.is_provisioned();
        let has_identity = state.has_recorded_identity();

        // An account that already has a working `adi_pb` keeps it, on login as
        // well as on refresh.  Provisioning only happens when there is no adi
        // yet, or when a legacy state (provisioned before identities were
        // recorded) is used for a login and therefore has to adopt the server
        // identity.  Nothing here ever discards an existing adi: resetting is
        // an explicit user action (`reset-anisette`).
        let needs_provision = !has_adi || (self.login_mode && !has_identity);

        let identity = if has_identity {
            let (ci, ua) = state.identity();
            (ci.to_string(), ua.to_string())
        } else if needs_provision {
            (server_client_info, server_user_agent)
        } else {
            // Legacy state used for refresh: keep the identity its token was
            // issued with instead of silently switching to the server's.
            let (ci, ua) = state.identity();
            (ci.to_string(), ua.to_string())
        };

        if needs_provision {
            let client = self.client.as_ref().unwrap();
            let state = self.state.as_mut().unwrap();
            client.provision(state, &identity.0, &identity.1).await?;
            self.persist_state()?;
        }

        // Never auto-recover by re-provisioning: a rejected adi means the user
        // has to run `reset-anisette` explicitly.
        let data = self.get_headers_from_state().await?;
        Ok(data.get_headers(self.serial.clone()))
    }
}

impl RemoteAnisetteProviderV3 {
    /// Server to talk to for the state currently loaded.
    fn effective_server_url(&self) -> String {
        let legacy_adi = self
            .state
            .as_ref()
            .and_then(|s| s.adi_pb.as_deref())
            .map(|adi| AdiFormat::of(adi) != AdiFormat::Adib)
            .unwrap_or(false);
        if legacy_adi {
            if let Some(url) = &self.legacy_server_url {
                return url.clone();
            }
        }
        self.client_url.clone()
    }

    async fn get_headers_from_state(&self) -> Result<AnisetteData, AnisetteError> {
        let client = self.client.as_ref().unwrap();
        let state = self.state.as_ref().unwrap();
        client.get_headers(state).await
    }

    fn persist_state(&self) -> Result<(), AnisetteError> {
        if !self.account_scoped {
            // Legacy shared location: read only, so older versions and
            // accounts that have not logged in again keep working.
            return Ok(());
        }
        fs::create_dir_all(&self.configuration_path)?;
        if let Some(state) = &self.state {
            plist::to_file_xml(self.configuration_path.join("state.plist"), state)?;
        }
        Ok(())
    }
}

/// Write a brand-new state to `path`: fresh random `keychain_identifier` and
/// no `adi_pb`.
///
/// This is "reset anisette data" in the destructive sense: the next use
/// provisions as a different device.  Writing the file (rather than deleting
/// it) also stops the loader from falling back to the legacy shared state,
/// which would otherwise resurrect the old identity.
pub fn reset_state_file(path: &PathBuf) -> Result<(), AnisetteError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let state = AnisetteState::new();
    plist::to_file_xml(path, &state)?;
    Ok(())
}

/// True when the path looks like `<root>/anisette/<account>`.
fn configuration_path_is_account_dir(path: &PathBuf) -> bool {
    path.parent()
        .and_then(|p| p.file_name())
        .map(|name| name == crate::ANISETTE_ACCOUNT_DIR)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use crate::anisette_headers_provider::AnisetteHeadersProvider;
    use crate::remote_anisette_v3::RemoteAnisetteProviderV3;
    use crate::{AnisetteError, DEFAULT_ANISETTE_URL_V3};
    use log::info;

    #[test]
    fn legacy_state_without_identity_uses_pixel7() {
        let state = super::AnisetteState::new();
        assert!(!state.has_recorded_identity());
        assert_eq!(state.identity().0, super::LEGACY_CLIENT_INFO);
        assert_eq!(state.identity().1, super::LEGACY_USER_AGENT);
        assert!(state.identity().0.contains("<Pixel 7>"));
    }

    #[test]
    fn recorded_identity_is_kept() {
        let mut state = super::AnisetteState::new();
        state.set_identity("<PC> <Windows;6.2(0,0);9200> <x>".into(), "ua".into());
        assert!(state.has_recorded_identity());
        assert_eq!(state.identity().0, "<PC> <Windows;6.2(0,0);9200> <x>");
        assert_eq!(state.identity().1, "ua");
    }

    #[tokio::test]
    async fn fetch_anisette_remote_v3() -> Result<(), AnisetteError> {
        crate::tests::init_logger();

        let mut provider = RemoteAnisetteProviderV3::new(
            DEFAULT_ANISETTE_URL_V3.to_string(),
            "anisette_test".into(),
            "0".to_string(),
        );
        info!(
            "Remote headers: {:?}",
            (&mut provider as &mut dyn AnisetteHeadersProvider)
                .get_authentication_headers()
                .await?
        );
        Ok(())
    }
}
