use std::collections::HashMap;
use std::time::SystemTime;

#[cfg(target_os = "linux")]
use std::fs::{self, File};
#[cfg(target_os = "linux")]
use std::io::{self, Cursor, copy};

#[cfg(target_os = "linux")]
use reqwest::Client;
#[cfg(target_os = "linux")]
use zip::ZipArchive;

#[cfg(target_os = "linux")]
use omnisette::AnisetteError;
use omnisette::{AnisetteConfiguration, AnisetteHeaders};

use crate::Error;

const AUTHKIT_CLIENT_INFO: &str = "com.apple.AuthKit/1 (com.apple.akd/1.0)";

pub(crate) fn normalize_client_info(client_info: &str) -> String {
    match client_info.split('<').nth(3) {
        Some(segment) => {
            let component = segment.split('>').next().unwrap_or(segment);
            if component.is_empty() {
                client_info.to_string()
            } else {
                client_info.replace(component, AUTHKIT_CLIENT_INFO)
            }
        }
        None => client_info.to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
    pub generated_at: SystemTime,
    pub config: AnisetteConfiguration,
    client_info_override: Option<String>,
}

impl AnisetteData {
    pub async fn new(config: AnisetteConfiguration) -> Result<Self, Error> {
        let mut b = AnisetteHeaders::get_anisette_headers_provider(config.clone())?;
        let base_headers = b.provider.get_authentication_headers().await?;

        Ok(AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            config,
            client_info_override: None,
        })
    }

    pub fn set_client_info_override(&mut self, client_info: Option<String>) {
        self.client_info_override = client_info;
    }

    pub(crate) fn effective_client_info(&self) -> Option<String> {
        self.client_info_override
            .as_deref()
            .or_else(|| {
                self.base_headers
                    .get("X-Mme-Client-Info")
                    .map(String::as_str)
            })
            .map(normalize_client_info)
    }

    pub fn needs_refresh(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() > 60
    }

    pub fn is_valid(&self) -> bool {
        let elapsed = self.generated_at.elapsed().unwrap();
        elapsed.as_secs() < 90
    }

    pub async fn refresh(&self) -> Result<Self, crate::Error> {
        let mut refreshed = Self::new(self.config.clone()).await?;
        refreshed.client_info_override = self.client_info_override.clone();
        Ok(refreshed)
    }

    pub fn generate_headers(
        &self,
        cpd: bool,
        client_info: bool,
        app_info: bool,
    ) -> HashMap<String, String> {
        if !self.is_valid() {
            panic!("Invalid data!")
        }

        let mut headers = self.base_headers.clone();
        let old_client_info = headers.remove("X-Mme-Client-Info");

        if client_info {
            let client_info = match self
                .client_info_override
                .as_deref()
                .or(old_client_info.as_deref())
            {
                Some(v) => normalize_client_info(v),
                None => {
                    return headers;
                }
            };
            headers.insert("X-Mme-Client-Info".to_owned(), client_info);
        }

        if app_info {
            headers.insert(
                "X-Apple-App-Info".to_owned(),
                "com.apple.gs.xcode.auth".to_owned(),
            );
            headers.insert("X-Xcode-Version".to_owned(), "11.2 (11B41)".to_owned());
        }

        if cpd {
            headers.insert("bootstrap".to_owned(), "true".to_owned());
            headers.insert("icscrec".to_owned(), "true".to_owned());
            headers.insert("loc".to_owned(), "en_GB".to_owned());
            headers.insert("pbe".to_owned(), "false".to_owned());
            headers.insert("prkgen".to_owned(), "true".to_owned());
            headers.insert("svct".to_owned(), "iCloud".to_owned());
        }

        headers
    }

    pub fn to_plist(&self, cpd: bool, client_info: bool, app_info: bool) -> plist::Dictionary {
        let mut plist = plist::Dictionary::new();
        for (key, value) in self.generate_headers(cpd, client_info, app_info).iter() {
            plist.insert(key.to_owned(), plist::Value::String(value.to_owned()));
        }

        plist
    }

    pub fn get_header(&self, header: &str) -> Result<String, Error> {
        let headers = self
            .generate_headers(true, true, true)
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect::<HashMap<String, String>>();

        match headers.get(&header.to_lowercase()) {
            Some(v) => Ok(v.to_string()),
            None => Err(Error::DeveloperSessionRequestFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisette::adi_proxy::{CLIENT_INFO_HEADER, LEGACY_CLIENT_INFO_HEADER};

    fn data_with_client_info(client_info: &str) -> AnisetteData {
        AnisetteData {
            base_headers: HashMap::from([(
                "X-Mme-Client-Info".to_string(),
                client_info.to_string(),
            )]),
            generated_at: SystemTime::now(),
            config: AnisetteConfiguration::new(),
            client_info_override: None,
        }
    }

    #[test]
    fn provider_identity_is_rewritten_for_apple_requests() {
        let data = data_with_client_info(CLIENT_INFO_HEADER);
        let headers = data.generate_headers(false, true, false);

        assert_eq!(
            headers.get("X-Mme-Client-Info").unwrap(),
            "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
    }

    #[test]
    fn override_takes_precedence_over_provider_identity() {
        let mut data = data_with_client_info(CLIENT_INFO_HEADER);
        data.set_client_info_override(Some(LEGACY_CLIENT_INFO_HEADER.to_string()));

        let headers = data.generate_headers(false, true, false);

        assert_eq!(
            headers.get("X-Mme-Client-Info").unwrap(),
            "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        );
    }
}
