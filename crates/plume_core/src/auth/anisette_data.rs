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

#[derive(Debug, Clone)]
pub struct AnisetteData {
    pub base_headers: HashMap<String, String>,
    pub generated_at: SystemTime,
    pub config: AnisetteConfiguration,
}

impl AnisetteData {
    pub async fn new(config: AnisetteConfiguration) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        Self::check_and_download_deps_libs(&config.configuration_path()).await?;

        let mut b = AnisetteHeaders::get_anisette_headers_provider(config.clone())?;
        let base_headers = b.provider.get_authentication_headers().await?;

        Ok(AnisetteData {
            base_headers,
            generated_at: SystemTime::now(),
            config,
        })
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
        Self::new(self.config.clone()).await
    }

    #[cfg(target_os = "linux")]
    async fn check_and_download_deps_libs(
        configuration_path: &std::path::Path,
    ) -> Result<(), AnisetteError> {
        #[cfg(target_arch = "x86_64")]
        let arch = "x86_64";
        #[cfg(target_arch = "x86")]
        let arch = "x86";
        #[cfg(target_arch = "aarch64")]
        let arch = "arm64-v8a";
        #[cfg(target_arch = "arm")]
        let arch = "armeabi-v7a";
        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "arm"
        )))]
        return Ok(());

        let lib_path = configuration_path.join("lib").join(arch);
        let libs = ["libstoreservicescore.so", "libCoreADI.so"];
        let missing = libs.iter().any(|lib| !lib_path.join(lib).exists());

        if !missing {
            return Ok(());
        }

        if !lib_path.exists() {
            fs::create_dir_all(&lib_path)?;
        }

        log::info!("Downloading Apple Music APK...");
        let client = Client::builder().build()?;

        let response = client
            .get("https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk")
            .send()
            .await?;

        let content = response.bytes().await?;
        let reader = Cursor::new(content);

        let mut archive =
            ZipArchive::new(reader).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let apk_arch_path = format!("lib/{}/", arch);

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let name = file.name().to_string();

            if name.starts_with(&apk_arch_path) && name.ends_with(".so") {
                let file_name = std::path::Path::new(&name).file_name().unwrap();
                let file_name_str = file_name.to_str().unwrap();

                if libs.contains(&file_name_str) {
                    let dest_path = lib_path.join(file_name);
                    let mut dest_file = File::create(&dest_path)?;
                    copy(&mut file, &mut dest_file)?;
                }
            }
        }

        log::info!("Anisette dependency extracted to: {}", lib_path.display());
        Ok(())
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
            let client_info = match old_client_info {
                Some(v) => {
                    let temp = v.as_str();

                    temp.replace(
                        temp.split('<').nth(3).unwrap().split('>').nth(0).unwrap(),
                        "com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)",
                    )
                }
                None => {
                    return headers;
                }
            };
            headers.insert("X-Mme-Client-Info".to_owned(), client_info.to_owned());
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
