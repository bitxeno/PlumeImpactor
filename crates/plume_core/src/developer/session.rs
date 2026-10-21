use omnisette::AnisetteConfiguration;
use omnisette::adi_proxy::{
    CLIENT_INFO_HEADER, LEGACY_CLIENT_INFO_HEADER, MACOS_CLIENT_INFO_HEADER,
};
use reqwest::header::HeaderName;
use std::sync::Arc;
use tokio::sync::Mutex;

use plist::{Dictionary, Value};
use reqwest::Client;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use uuid::Uuid;

use crate::Error;

use crate::auth::Account;
use crate::auth::anisette_data::{AnisetteData, normalize_client_info};
use crate::developer::client_identity::{self, AccountIdentity};
use crate::developer::qh::QHResponseMeta;
use crate::developer::v1::V1ErrorResponse;

pub struct DeveloperSession {
    anisette: Arc<Mutex<AnisetteData>>,
    client: Client,
    adsid: String,          // from grandslam's SPD "adsid"
    xcode_gs_token: String, // requested from spd initially // com.apple.gs.xcode.auth
}

fn identity_candidates(stored: Option<&AccountIdentity>) -> Vec<Option<&str>> {
    let mut candidates = Vec::new();
    let mut should_probe = true;

    match stored {
        Some(AccountIdentity::Resolved { client_info }) if !client_info.is_empty() => {
            candidates.push(Some(client_info.as_str()));
        }
        Some(AccountIdentity::Checked) => {
            candidates.push(None);
            should_probe = false;
        }
        _ => {}
    }

    if should_probe {
        for candidate in [
            MACOS_CLIENT_INFO_HEADER,
            CLIENT_INFO_HEADER,
            LEGACY_CLIENT_INFO_HEADER,
        ] {
            let normalized = normalize_client_info(candidate);
            let duplicate = candidates.iter().any(|existing| {
                existing.is_some_and(|existing| normalize_client_info(existing) == normalized)
            });

            if !duplicate {
                candidates.push(Some(candidate));
            }
        }

        if !candidates.contains(&None) {
            candidates.push(None);
        }
    }

    candidates
}

impl DeveloperSession {
    pub async fn using_account(email: String, account: Account) -> Result<Self, Error> {
        let adsid = account
            .spd
            .as_ref()
            .unwrap()
            .get("adsid")
            .unwrap()
            .as_string()
            .unwrap();
        let xcode_gs_token = account
            .get_app_token("com.apple.gs.xcode.auth")
            .await?
            .auth_token;

        let login_anisette = account.get_anisette().await;
        if let (Some(path), Some(client_info)) = (
            client_identity::path(&login_anisette.config),
            login_anisette.effective_client_info(),
        ) {
            client_identity::record(&path, &email, AccountIdentity::Resolved { client_info }).await;
        }

        Ok(DeveloperSession {
            anisette: account.anisette.clone(),
            client: account.client.clone(),
            adsid: adsid.into(),
            xcode_gs_token,
        })
    }

    pub async fn new(
        email: String,
        adsid: String,
        xcode_gs_token: String,
        config: AnisetteConfiguration,
    ) -> Result<Self, Error> {
        let anisette = AnisetteData::new(config).await?;
        Self::new_with_anisette(email, adsid, xcode_gs_token, Arc::new(Mutex::new(anisette))).await
    }

    pub async fn new_with_anisette(
        email: String,
        adsid: String,
        xcode_gs_token: String,
        anisette: Arc<Mutex<AnisetteData>>,
    ) -> Result<Self, Error> {
        let store_path = {
            let anisette = anisette.lock().await;
            client_identity::path(&anisette.config)
        };

        let stored_identity = match &store_path {
            Some(path) => client_identity::lookup(path, &email).await,
            None => None,
        };

        let candidates = identity_candidates(stored_identity.as_ref());

        let mut primary_error = None;

        for candidate in candidates {
            let effective_client_info = {
                let mut anisette = anisette.lock().await;
                anisette.set_client_info_override(candidate.map(str::to_owned));
                anisette.effective_client_info()
            };

            let session = Self {
                anisette: anisette.clone(),
                client: crate::client()?,
                adsid: adsid.clone(),
                xcode_gs_token: xcode_gs_token.clone(),
            };

            // we test the session by listing teams
            // if this fails, the session is invalid (obviously)
            match session.qh_list_teams().await {
                Ok(_) => {
                    if let (Some(path), Some(client_info)) = (&store_path, effective_client_info) {
                        client_identity::record(
                            path,
                            &email,
                            AccountIdentity::Resolved { client_info },
                        )
                        .await;
                    }
                    return Ok(session);
                }
                Err(err) => {
                    let session_expired = matches!(
                        &err,
                        Error::DeveloperApi {
                            result_code: 1100,
                            ..
                        }
                    );

                    if !session_expired {
                        return Err(err);
                    }

                    if primary_error.is_none() {
                        primary_error = Some(err);
                    }
                }
            }
        }

        if let Some(path) = &store_path {
            client_identity::record(path, &email, AccountIdentity::Checked).await;
        }

        Err(primary_error.unwrap_or(Error::DeveloperSessionRequestFailed))
    }

    pub fn adsid(&self) -> &String {
        &self.adsid
    }

    pub fn xcode_gs_token(&self) -> &String {
        &self.xcode_gs_token
    }
}

impl DeveloperSession {
    pub async fn qh_send_request(
        &self,
        url: &str,
        body: Option<Dictionary>,
    ) -> Result<Dictionary, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_static("text/x-xml-plist"));
        headers.insert("Accept", HeaderValue::from_static("text/x-xml-plist"));
        self.insert_identity_headers(&mut headers).await;
        self.insert_anisette_headers(&mut headers).await;

        let mut body = body.unwrap_or_default();
        body.insert(
            "requestId".into(),
            Value::String(Uuid::new_v4().to_string().to_uppercase()),
        );

        let request_builder = self.client.post(url).headers(headers);

        let mut buffer = Vec::new();
        plist::to_writer_xml(&mut buffer, &body)?;

        log::debug!("QH Request to {}: {:?}", url, body);

        let response = request_builder.body(buffer).send().await?;
        let response_bytes = response.bytes().await?;
        let response_dict: Dictionary = plist::from_bytes(&response_bytes)?;

        log::debug!("QH Response from {}: {:?}", url, response_dict);

        let response_meta: QHResponseMeta =
            plist::from_value(&Value::Dictionary(response_dict.clone()))?;

        if response_meta.result_code.as_signed().unwrap_or(0) != 0 {
            return Err(response_meta.to_error(url.to_string()));
        }

        Ok(response_dict)
    }

    pub async fn v1_send_request(
        &self,
        url: &str,
        body: Option<serde_json::Value>,
        request_type: Option<RequestType>,
    ) -> Result<serde_json::Value, Error> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Type",
            HeaderValue::from_static("application/vnd.api+json"),
        );
        headers.insert(
            "Accept",
            HeaderValue::from_static("application/json, text/plain, */*"),
        );
        headers.insert(
            "X-Requested-With",
            HeaderValue::from_static("XMLHttpRequest"),
        );
        self.insert_identity_headers(&mut headers).await;
        if let Some(RequestType::Get) = request_type {
            headers.insert("X-HTTP-Method-Override", HeaderValue::from_static("GET"));
        }
        self.insert_anisette_headers(&mut headers).await;

        let mut request_builder = match request_type {
            Some(RequestType::Patch) => self.client.patch(url).headers(headers.clone()),
            Some(RequestType::Post) | _ if body.is_some() => {
                self.client.post(url).headers(headers.clone())
            }
            _ => self.client.get(url).headers(headers.clone()),
        };

        log::debug!("V1 Request to {}: {:?}", url, &body);

        if let Some(body) = body {
            request_builder = request_builder.json(&body);
        }

        let response = request_builder.send().await?;
        let response_text = response.text().await?;

        log::debug!("V1 Response from {}: {}", url, response_text);

        let response_json: serde_json::Value = serde_json::from_str(&response_text)?;

        if let Ok(errors) = serde_json::from_value::<V1ErrorResponse>(response_json.clone()) {
            return Err(errors.errors[0].to_error(url.to_string()));
        }

        Ok(response_json)
    }

    // TODO: this can be deduplicated as well, for reuse in `fn build_2fa_headers`
    async fn insert_identity_headers(&self, headers: &mut HeaderMap) {
        headers.insert("Accept-Language", HeaderValue::from_static("en-us"));
        headers.insert("User-Agent", HeaderValue::from_static("Xcode"));
        headers.insert(
            "X-Apple-I-Identity-Id",
            HeaderValue::from_str(&self.adsid).unwrap(),
        );
        headers.insert(
            "X-Apple-GS-Token",
            HeaderValue::from_str(&self.xcode_gs_token).unwrap(),
        );
    }

    async fn insert_anisette_headers(&self, headers: &mut HeaderMap) {
        let valid_anisette = self.get_anisette().await;
        for (k, v) in valid_anisette.generate_headers(false, true, true) {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(&v).unwrap(),
            );
        }
        if let Ok(locale) = valid_anisette.get_header("x-apple-locale") {
            headers.insert("X-Apple-Locale", HeaderValue::from_str(&locale).unwrap());
        }
    }

    // TODO: deduplicate?
    pub async fn get_anisette(&self) -> AnisetteData {
        let mut locked = self.anisette.lock().await;
        if locked.needs_refresh() {
            *locked = locked.refresh().await.unwrap();
        }
        locked.clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    Get,
    Post,
    Patch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_identity_probes_legacy_identities_in_order() {
        let candidates = identity_candidates(None);

        assert_eq!(
            candidates,
            vec![
                Some(MACOS_CLIENT_INFO_HEADER),
                Some(CLIENT_INFO_HEADER),
                Some(LEGACY_CLIENT_INFO_HEADER),
                None,
            ]
        );
    }

    #[test]
    fn resolved_identity_is_tried_first_without_duplicates() {
        let stored = AccountIdentity::Resolved {
            client_info: CLIENT_INFO_HEADER.to_string(),
        };

        let candidates = identity_candidates(Some(&stored));

        assert_eq!(
            candidates,
            vec![
                Some(CLIENT_INFO_HEADER),
                Some(MACOS_CLIENT_INFO_HEADER),
                Some(LEGACY_CLIENT_INFO_HEADER),
                None,
            ]
        );
    }

    #[test]
    fn checked_identity_only_uses_the_provider_default() {
        let candidates = identity_candidates(Some(&AccountIdentity::Checked));

        assert_eq!(candidates, vec![None]);
    }
}
