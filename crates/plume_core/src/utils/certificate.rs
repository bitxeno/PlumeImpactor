use std::{fs, path::PathBuf, vec};

use apple_codesign::{
    SigningSettings,
    cryptography::{InMemoryPrivateKey, PrivateKey},
};
// TODO: why do we have pem and pem_rfc7468 deps again?
use pem_rfc7468::{LineEnding, encode_string};
use rand::rngs::OsRng;
use rcgen::{DnType, KeyPair, PKCS_RSA_SHA256};
use rsa::{
    RsaPrivateKey,
    pkcs1::EncodeRsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use x509_certificate::{CapturedX509Certificate, X509Certificate};

use crate::{
    Error,
    developer::{DeveloperSession, qh::certs::Cert},
};

pub(crate) const MACHINE_NAME: &str = "AltStore";

/// How many times a single run may ask to free a certificate slot before the
/// request is considered stuck. One revocation normally makes room.
const MAX_CERT_RESET_ATTEMPTS: u32 = 3;

/// The answer when a run is told it must revoke a certificate to make room.
/// The three outcomes need different errors: a refusal is final, while a
/// missing authorization is something the caller can still supply.
#[derive(Debug, PartialEq, Eq)]
pub enum CertificateReset {
    /// Revoke exactly this certificate, then retry.
    Revoke(String),
    /// A person was asked and declined.
    Cancelled,
    /// Nothing authorizes a revocation: a headless run without approval, or
    /// the one approved certificate has already been spent.
    NoAuthorization,
}

pub struct CertificateIdentity {
    pub cert: Option<CapturedX509Certificate>,
    pub key: Option<Box<dyn PrivateKey>>,
    pub machine_id: Option<String>,
    pub serial_number: Option<String>,
    pub p12_data: Option<Vec<u8>>,
    pub new: bool,
}

impl CertificateIdentity {
    // Use for cli context or if you actually store pems? why would you do that though
    pub async fn new_with_paths(paths: Option<Vec<PathBuf>>) -> Result<Self, Error> {
        let mut cert = Self {
            cert: None,
            key: None,
            machine_id: None,
            p12_data: None,
            serial_number: None,
            new: false,
        };

        if let Some(paths) = paths {
            for path in &paths {
                let pem_data = fs::read(path)?;
                cert.resolve_certificate_from_contents(pem_data)?;
            }
        }

        Ok(cert)
    }

    pub async fn new_with_session(
        session: &DeveloperSession,
        config_path: PathBuf,
        machine_name: Option<String>,
        team_id: &String,
        is_export: bool,
        on_certificate_reset: Option<&mut dyn FnMut(&[Cert]) -> CertificateReset>,
    ) -> Result<Self, Error> {
        let machine_name = machine_name.unwrap_or_else(|| MACHINE_NAME.to_string());

        let key_path = Self::key_dir(config_path, &team_id)?.join("key.pem");

        let mut identity = Self {
            cert: None,
            key: None,
            machine_id: None,
            p12_data: None,
            serial_number: None,
            new: false,
        };

        // To same some unnecessary requests, we're going to list our certificates first here
        // then pass them into the necessary functions that need it, if the functions absolutely
        // need to request certificates (after submitting a CSR, for example), they can do so
        let certs = session.qh_list_certs(&team_id).await?.certificates;

        // Only the key will be written to disk, certificate can just be gotten via the request
        // request we've made, by trying to match our public key with the requests public key
        let key_pair: [Vec<u8>; 2] = if key_path.exists() {
            let key_string = fs::read_to_string(&key_path)?;
            let priv_key = RsaPrivateKey::from_pkcs8_pem(&key_string)?;

            if let Some(certificate) = identity.find_certificate(certs.clone(), &priv_key).await? {
                let cert_pem = encode_string(
                    "CERTIFICATE",
                    LineEnding::LF,
                    certificate
                        .cert_content
                        .ok_or(Error::CertificatePemMissing)?
                        .as_ref(),
                )
                .unwrap();
                let key_pem = priv_key.to_pkcs8_pem(Default::default())?.to_string();

                [cert_pem.into_bytes(), key_pem.into_bytes()]
            } else {
                let (certificate, priv_key) = identity
                    .request_new_certificate(
                        session,
                        team_id,
                        &machine_name,
                        certs,
                        on_certificate_reset,
                    )
                    .await?;

                let cert_pem = encode_string(
                    "CERTIFICATE",
                    LineEnding::LF,
                    certificate
                        .cert_content
                        .ok_or(Error::CertificatePemMissing)?
                        .as_ref(),
                )
                .unwrap();
                let key_pem = priv_key.to_pkcs8_pem(Default::default())?.to_string();

                fs::write(&key_path, &key_pem)?;
                identity.new = true;
                [cert_pem.into_bytes(), key_pem.into_bytes()]
            }
        } else {
            let (cert, priv_key) = identity
                .request_new_certificate(
                    session,
                    team_id,
                    &machine_name,
                    certs,
                    on_certificate_reset,
                )
                .await?;
            let cert_pem = encode_string(
                "CERTIFICATE",
                LineEnding::LF,
                cert.cert_content
                    .ok_or(Error::CertificatePemMissing)?
                    .as_ref(),
            )
            .unwrap();
            let key_pem = priv_key.to_pkcs8_pem(Default::default())?.to_string();

            fs::write(&key_path, &key_pem)?;
            identity.new = true;
            [cert_pem.into_bytes(), key_pem.into_bytes()]
        };

        // TODO: this may be horrendious
        if let Some(p12_data) = identity.create_pkcs12(&key_pair, is_export) {
            identity.p12_data = Some(p12_data);
        }

        for pem in key_pair {
            identity.resolve_certificate_from_contents(pem)?;
        }

        Ok(identity)
    }

    // <config_path>/keys/<team_id>
    fn key_dir(path: PathBuf, team_id: &String) -> Result<PathBuf, Error> {
        let dir = path.join("keys").join(team_id);

        fs::create_dir_all(&dir)?;

        Ok(dir)
    }

    fn set_machine_id(&mut self, machine_id: String) {
        self.machine_id = Some(machine_id);
    }

    fn set_serial_number(&mut self, serial_number: String) {
        self.serial_number = Some(serial_number);
    }

    // TODO: cleanest p12 code of them all
    // the main horror about p12 creation is that we rely on p12-keystore which is
    // just another unnecessary dependency, but the p12 crate that applecodesign-rs
    // uses has no support for modern encryption, hopefully this doesn't add that
    // much more bloat
    pub fn create_pkcs12(&self, data: &[Vec<u8>; 2], is_export: bool) -> Option<Vec<u8>> {
        let cert_der = pem::parse(&data[0]).ok()?.contents().to_vec();
        let key_der = pem::parse(&data[1]).ok()?.contents().to_vec();

        let cert = p12_keystore::Certificate::from_der(&cert_der).ok()?;

        let local_key_id = {
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(&key_der);
            let hash = hasher.finalize();
            hash[..8].to_vec()
        };

        let key_chain = p12_keystore::PrivateKeyChain::new(key_der, local_key_id, vec![cert]);

        let mut keystore = p12_keystore::KeyStore::new();
        keystore.add_entry(
            "plume",
            p12_keystore::KeyStoreEntry::PrivateKeyChain(key_chain),
        );

        // when exporting the user has no idea what the password is, just dont set one
        // otherwise, when not exporting (used for SideStore/AltStore) we use the
        // machine_id since it needs it to locate a matching certificate
        let password = if is_export {
            "".to_string()
        } else {
            self.machine_id.as_deref().unwrap_or("").to_string()
        };

        let writer = keystore.writer(&password);
        writer.write().ok()
    }

    // applecodesign-rs needs our contents as strings to sign
    fn resolve_certificate_from_contents(&mut self, contents: Vec<u8>) -> Result<(), Error> {
        for pem in pem::parse_many(contents).map_err(Error::Pem)? {
            match pem.tag() {
                "CERTIFICATE" => {
                    self.cert = Some(CapturedX509Certificate::from_der(pem.contents())?);
                }
                "PRIVATE KEY" => {
                    self.key = Some(Box::new(InMemoryPrivateKey::from_pkcs8_der(
                        pem.contents(),
                    )?));
                }
                "RSA PRIVATE KEY" => {
                    self.key = Some(Box::new(InMemoryPrivateKey::from_pkcs1_der(
                        pem.contents(),
                    )?));
                }
                tag => log::debug!("(unhandled PEM tag {}; ignoring)", tag),
            }
        }

        Ok(())
    }
}

impl CertificateIdentity {
    /// Finds the certificate on the developer portal that belongs to `priv_key`.
    ///
    /// A certificate belongs to this key when its public key matches, which is
    /// what Apple's signing already proves. The machine name registered by the
    /// tool that created the certificate (AltStore, SideStore, iLoader, ...) is
    /// deliberately ignored: private ownership of the key is the only real
    /// credential, so ignoring it lets one certificate be shared across tools.
    ///
    /// Expired certificates are not reusable, so they are skipped: the caller
    /// then requests a new certificate instead of signing with a dead one.
    async fn find_certificate(
        &mut self,
        certs: Vec<Cert>,
        priv_key: &RsaPrivateKey,
    ) -> Result<Option<Cert>, Error> {
        let pub_key_der_obj = priv_key.to_public_key().to_pkcs1_der()?.as_bytes().to_vec();

        for cert in certs {
            if let Some(cert_content) = &cert.cert_content {
                // Skip entries we cannot parse instead of failing the whole
                // lookup: every certificate is inspected now, not just the ones
                // matching a name.
                let parsed_cert = match X509Certificate::from_der(cert_content) {
                    Ok(parsed_cert) => parsed_cert,
                    Err(e) => {
                        log::debug!("Ignoring certificate {}: {}", cert.serial_number, e);
                        continue;
                    }
                };
                if !parsed_cert.time_constraints_valid(None) {
                    log::debug!("Ignoring expired certificate {}", cert.serial_number);
                    continue;
                }
                if pub_key_der_obj == parsed_cert.public_key_data().as_ref() {
                    // We need to save the machine_id for our P12
                    if let Some(ref machine_id) = cert.machine_id {
                        self.set_machine_id(machine_id.clone());
                    }

                    self.set_serial_number(cert.serial_number.clone());

                    return Ok(Some(cert));
                }
            }
        }

        Ok(None)
    }

    async fn request_new_certificate(
        &mut self,
        session: &DeveloperSession,
        team_id: &String,
        machine_name: &String,
        certs: Vec<Cert>,
        mut on_certificate_reset: Option<&mut dyn FnMut(&[Cert]) -> CertificateReset>,
    ) -> Result<(Cert, RsaPrivateKey), Error> {
        let priv_key = RsaPrivateKey::new(&mut OsRng, 2048)?;
        let priv_key_der = priv_key.to_pkcs8_der()?;
        let priv_key_pair = KeyPair::from_der(priv_key_der.as_bytes())?;

        let mut params = rcgen::CertificateParams::new(vec![]);
        params.alg = &PKCS_RSA_SHA256;
        params.key_pair = Some(priv_key_pair);

        let dn = &mut params.distinguished_name;
        dn.push(DnType::CountryName, "US");
        dn.push(DnType::StateOrProvinceName, "STATE");
        dn.push(DnType::LocalityName, "LOCAL");
        dn.push(DnType::OrganizationName, "ORGNIZATION");
        dn.push(DnType::CommonName, "CN");

        let cert_csr = rcgen::Certificate::from_params(params)?.serialize_request_pem()?;

        // A CSR is rejected with result code 7460 when the account is already
        // holding as many certificates as Apple allows; a slot has to be freed
        // by revoking one first. Which certificate loses is the user's call,
        // never ours:
        // - every round asks the callback again, so no certificate is ever
        //   revoked behind a confirmation that covered a different one;
        // - only the serial the callback authorized is revoked; if that fails
        //   the request aborts instead of falling back to another candidate.
        // A run without an authorization stops with
        // CertificateResetRequired so callers (atvloadly's install page) can
        // present the candidates and retry with an explicit one.
        let mut revocable = certs;
        let mut attempts = 0u32;
        let cert_id = loop {
            attempts += 1;
            if attempts > MAX_CERT_RESET_ATTEMPTS {
                return Err(Error::Certificate(format!(
                    "Still at the certificate limit after {MAX_CERT_RESET_ATTEMPTS} revocations"
                )));
            }

            match session
                .qh_submit_cert_csr(&team_id, cert_csr.clone(), machine_name)
                .await
            {
                Ok(id) => break id,
                Err(e) => {
                    // 7460 is for too many certificates (I think)
                    if matches!(&e, Error::DeveloperApi { result_code, .. } if *result_code == 7460)
                    {
                        // A caller that can ask the user (a GUI) reports a
                        // refusal as cancelled. A headless caller with no way
                        // to ask reports the missing authorization together
                        // with the candidates it was offered, so the caller
                        // (atvloadly's install page) can present them and
                        // retry with --revoke-certificate.
                        let decision = match on_certificate_reset.as_deref_mut() {
                            Some(cb) => cb(&revocable),
                            None => CertificateReset::NoAuthorization,
                        };
                        let serial = match decision {
                            CertificateReset::Revoke(serial) => serial,
                            CertificateReset::Cancelled => {
                                return Err(Error::Certificate(
                                    "Certificate reset cancelled".into(),
                                ));
                            }
                            CertificateReset::NoAuthorization => {
                                for cert in &revocable {
                                    log::info!(
                                        "Certificate that could be revoked: `{}` (serial `{}`, expires {:?}, machine `{}`)",
                                        cert.name,
                                        cert.serial_number,
                                        cert.expiration_date,
                                        cert.machine_name.as_deref().unwrap_or("")
                                    );
                                }
                                let err = Error::CertificateResetRequired(revocable);
                                // Callers read the engine's log output, not
                                // the process exit value: write the Display,
                                // which carries the [certificate_reset_required]
                                // marker, where they can see it.
                                log::error!("{err}");
                                return Err(err);
                            }
                        };

                        match session.qh_revoke_cert(&team_id, &serial).await {
                            Ok(_) => log::warn!("Revoked certificate with serial number {serial}"),
                            Err(revoke_err) => {
                                return Err(Error::Certificate(format!(
                                    "Failed to revoke certificate {serial}: {revoke_err}"
                                )));
                            }
                        }

                        // The certificate we were told to free is gone; do not
                        // offer it (or anything already spent) again.
                        revocable.retain(|c| c.serial_number != serial);
                        continue;
                    }

                    return Err(e);
                }
            }
        }
        .cert_request;

        // We need to save the machine_id for our P12
        if let Some(ref machine_id) = cert_id.machine_id {
            self.set_machine_id(machine_id.clone());
        }

        self.set_serial_number(cert_id.serial_num.clone());

        // We request again, and hope this has our new certificate
        // ready.... if not then woops... thats too bad isnt it
        let certs = session
            .qh_list_certs(&team_id)
            .await?
            .certificates
            .into_iter()
            .find(|c| c.certificate_id == cert_id.certificate_id);

        Ok((certs.ok_or(Error::CertificatePemMissing)?, priv_key))
    }
}

impl CertificateIdentity {
    pub fn load_into_signing_settings<'settings, 'slf: 'settings>(
        &'slf self,
        settings: &'settings mut SigningSettings<'slf>,
    ) -> Result<(), Error> {
        let signing_cert = self.cert.clone().ok_or(Error::CertificatePemMissing)?;
        let signing_key = self.key.as_ref().ok_or(Error::CertificatePemMissing)?;

        settings.set_signing_key(signing_key.as_key_info_signer(), signing_cert);
        settings.chain_apple_certificates();
        settings.set_team_id_from_signing_certificate();

        Ok(())
    }

    pub async fn find_active_certificate(
        config_path: PathBuf,
        team_id: &String,
        certs: &[Cert],
    ) -> Option<CertificateIdentity> {
        let key_path = Self::key_dir(config_path, &team_id).ok()?.join("key.pem");

        if key_path.exists() {
            let key_string = fs::read_to_string(&key_path).ok()?;
            let priv_key = RsaPrivateKey::from_pkcs8_pem(&key_string).ok()?;

            let mut cert: CertificateIdentity = Self {
                cert: None,
                key: None,
                machine_id: None,
                p12_data: None,
                serial_number: None,
                new: false,
            };

            if let Some(_found_cert) = cert
                .find_certificate(certs.to_vec(), &priv_key)
                .await
                .ok()?
            {
                return Some(cert);
            }
        }

        None
    }

    pub async fn export_pkcs12(
        session: &DeveloperSession,
        config_path: PathBuf,
        team_id: &String,
        password: &str,
    ) -> Result<Vec<u8>, Error> {
        let key_path = Self::key_dir(config_path, team_id)?.join("key.pem");

        let certs = session.qh_list_certs(team_id).await?.certificates;

        let key_pair: [Vec<u8>; 2] = if key_path.exists() {
            let key_string = fs::read_to_string(&key_path)?;
            let priv_key = RsaPrivateKey::from_pkcs8_pem(&key_string)?;

            let mut cert = Self {
                cert: None,
                key: None,
                machine_id: None,
                p12_data: None,
                serial_number: None,
                new: false,
            };
            if let Some(cert) = cert.find_certificate(certs.clone(), &priv_key).await? {
                let cert_pem = encode_string(
                    "CERTIFICATE",
                    LineEnding::LF,
                    cert.cert_content
                        .ok_or(Error::CertificatePemMissing)?
                        .as_ref(),
                )
                .unwrap();
                let key_pem = priv_key.to_pkcs8_pem(Default::default())?.to_string();

                [cert_pem.into_bytes(), key_pem.into_bytes()]
            } else {
                return Err(Error::Certificate("Certificate not found".into()));
            }
        } else {
            return Err(Error::Certificate("Certificate key not found".into()));
        };

        let cert_der = pem::parse(&key_pair[0])
            .map_err(Error::Pem)?
            .contents()
            .to_vec();
        let key_der = pem::parse(&key_pair[1])
            .map_err(Error::Pem)?
            .contents()
            .to_vec();

        let cert = p12_keystore::Certificate::from_der(&cert_der)
            .map_err(|e| Error::Certificate(format!("Failed to parse certificate: {:?}", e)))?;

        let local_key_id = {
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(&key_der);
            let hash = hasher.finalize();
            hash[..8].to_vec()
        };

        let key_chain = p12_keystore::PrivateKeyChain::new(key_der, local_key_id, vec![cert]);

        let mut keystore = p12_keystore::KeyStore::new();
        keystore.add_entry(
            "plume",
            p12_keystore::KeyStoreEntry::PrivateKeyChain(key_chain),
        );

        let writer = keystore.writer(password);
        let p12_data = writer
            .write()
            .map_err(|e| Error::Certificate(format!("Failed to write P12: {:?}", e)))?;

        Ok(p12_data)
    }

    fn extract_unlinked_pkcs12_key_bag(p12_data: &[u8]) -> der::Result<Option<Vec<u8>>> {
        use der::{
            Decode, Encode,
            asn1::{ContextSpecific, ObjectIdentifier, OctetString},
        };
        use pkcs12::{
            authenticated_safe::AuthenticatedSafe,
            pfx::Pfx,
            safe_bag::{PrivateKeyInfo, SafeContents},
        };

        let data_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
        let key_bag_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.1");

        let pfx = Pfx::from_der(p12_data)?;
        if pfx.auth_safe.content_type != data_oid {
            return Ok(None);
        }

        let auth_safe_der = OctetString::from_der(&pfx.auth_safe.content.to_der()?)?.into_bytes();
        let auth_safe = AuthenticatedSafe::from_der(&auth_safe_der)?;

        for safe in auth_safe {
            if safe.content_type != data_oid {
                continue;
            }

            let safe_der = OctetString::from_der(&safe.content.to_der()?)?.into_bytes();
            let bags = SafeContents::from_der(&safe_der)?;

            for bag in bags {
                if bag.bag_id != key_bag_oid {
                    continue;
                }

                let key: ContextSpecific<PrivateKeyInfo> =
                    ContextSpecific::from_der(&bag.bag_value)?;
                return Ok(Some(key.value.to_der()?));
            }
        }

        Ok(None)
    }

    fn extract_pkcs12_private_key(p12_data: &[u8], password: &str) -> Result<Vec<u8>, Error> {
        let keystore = p12_keystore::KeyStore::from_pkcs12(p12_data, password)
            .map_err(|e| Error::Certificate(format!("Failed to parse P12: {:?}", e)))?;

        for (_, entry) in keystore.entries() {
            if let p12_keystore::KeyStoreEntry::PrivateKeyChain(chain) = entry {
                return Ok(chain.key().to_vec());
            }
        }

        if let Some(key) = Self::extract_unlinked_pkcs12_key_bag(p12_data)
            .map_err(|e| Error::Certificate(format!("Failed to parse P12 key bag: {:?}", e)))?
        {
            return Ok(key);
        }

        Err(Error::Certificate(
            "No private key found in P12 file".into(),
        ))
    }

    pub async fn import_pkcs12(
        session: &DeveloperSession,
        config_path: PathBuf,
        team_id: &String,
        p12_data: &[u8],
        password: &str,
    ) -> Result<(), Error> {
        let key_der = Self::extract_pkcs12_private_key(p12_data, password)?;

        let certificates = session.qh_list_certs(&team_id).await?.certificates;
        let parsed_key = RsaPrivateKey::from_pkcs8_der(&key_der)
            .map_err(|e| Error::Certificate(format!("Failed to parse private key: {:?}", e)))?;

        let pub_key_der_obj = parsed_key
            .to_public_key()
            .to_pkcs1_der()?
            .as_bytes()
            .to_vec();
        let mut expired: Option<String> = None;
        for cert in certificates {
            if let Some(cert_content) = &cert.cert_content {
                // The key from the P12 must have a live certificate on this
                // team; its machine name is irrelevant for that.
                let parsed_cert = match X509Certificate::from_der(cert_content) {
                    Ok(parsed_cert) => parsed_cert,
                    Err(e) => {
                        log::debug!("Ignoring certificate {}: {}", cert.serial_number, e);
                        continue;
                    }
                };
                if pub_key_der_obj != parsed_cert.public_key_data().as_ref() {
                    continue;
                }
                if !parsed_cert.time_constraints_valid(None) {
                    // Remember it so the failure can name the certificate:
                    // storing this key would succeed and then never be found
                    // again by find_certificate, which skips expired ones.
                    expired = Some(cert.serial_number);
                    continue;
                }

                // Convert DER to PEM
                let key_pem = pem_rfc7468::encode_string("PRIVATE KEY", LineEnding::LF, &key_der)
                    .map_err(|e| {
                    Error::Certificate(format!("Failed to encode key as PEM: {:?}", e))
                })?;

                let key_path = Self::key_dir(config_path, team_id)?.join("key.pem");
                if let Some(parent) = key_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&key_path, key_pem)?;
                return Ok(());
            }
        }

        if let Some(serial) = expired {
            return Err(Error::Certificate(format!(
                "The private key matches certificate {serial}, which has expired; \
                 it cannot be imported for signing"
            )));
        }

        Err(Error::Certificate(
            "No matching certificate found for the provided P12".into(),
        ))
    }
}

#[cfg(test)]
mod issue_195_pkcs12_tests {
    use super::*;

    use cms::content_info::ContentInfo;
    use der::{
        Any, Decode, Encode,
        asn1::{ObjectIdentifier, OctetString},
    };
    use pkcs12::{
        authenticated_safe::AuthenticatedSafe,
        cert_type::CertBag,
        pfx::{Pfx, Version},
        safe_bag::{SafeBag, SafeContents},
    };

    fn data_content(payload: Vec<u8>) -> ContentInfo {
        let data_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
        let octets = OctetString::new(payload).unwrap();
        let octets_der = octets.to_der().unwrap();

        ContentInfo {
            content_type: data_oid,
            content: Any::from_der(&octets_der).unwrap(),
        }
    }

    fn certificate_der(key: &RsaPrivateKey) -> Vec<u8> {
        let key_der = key.to_pkcs8_der().unwrap();
        let key_pair = KeyPair::from_der(key_der.as_bytes()).unwrap();

        let mut params = rcgen::CertificateParams::new(vec![]);
        params.alg = &PKCS_RSA_SHA256;
        params.key_pair = Some(key_pair);
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);

        rcgen::Certificate::from_params(params)
            .unwrap()
            .serialize_der()
            .unwrap()
    }

    fn sidestore_style_p12(key: &RsaPrivateKey) -> Vec<u8> {
        let key_bag_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.1");
        let cert_bag_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.12.10.1.3");
        let x509_cert_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.22.1");

        let key_der = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let key_bag = SafeBag {
            bag_id: key_bag_oid,
            bag_value: key_der.clone(),
            bag_attributes: None,
        };
        let key_safe: SafeContents = vec![key_bag];

        let cert_der = certificate_der(key);

        let cert_bag_value = CertBag {
            cert_id: x509_cert_oid,
            cert_value: OctetString::new(cert_der).unwrap(),
        }
        .to_der()
        .unwrap();

        let cert_bag = SafeBag {
            bag_id: cert_bag_oid,
            bag_value: cert_bag_value,
            bag_attributes: None,
        };
        let cert_safe: SafeContents = vec![cert_bag];

        let authenticated_safe: AuthenticatedSafe = vec![
            data_content(key_safe.to_der().unwrap()),
            data_content(cert_safe.to_der().unwrap()),
        ];

        let pfx = Pfx {
            version: Version::V3,
            auth_safe: data_content(authenticated_safe.to_der().unwrap()),
            mac_data: None,
        };

        pfx.to_der().unwrap()
    }

    #[test]
    fn issue_195_imports_sidestore_key_bag_without_local_key_id() {
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let p12 = sidestore_style_p12(&key);

        let keystore = p12_keystore::KeyStore::from_pkcs12(&p12, "ignored").unwrap();
        assert!(
            !keystore
                .entries()
                .any(|(_, entry)| matches!(entry, p12_keystore::KeyStoreEntry::PrivateKeyChain(_))),
            "fixture must reproduce p12-keystore dropping SideStore's unlinked keyBag"
        );

        let extracted = CertificateIdentity::extract_pkcs12_private_key(&p12, "ignored").unwrap();

        assert_eq!(
            extracted,
            key.to_pkcs8_der().unwrap().as_bytes(),
            "fallback must recover the exact PKCS#8 private key"
        );
    }

    #[test]
    fn issue_195_existing_linked_p12_path_still_works() {
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let key_der = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let cert = p12_keystore::Certificate::from_der(&certificate_der(&key)).unwrap();

        let chain = p12_keystore::PrivateKeyChain::new(key_der.clone(), [1, 2, 3, 4], vec![cert]);
        let mut keystore = p12_keystore::KeyStore::new();
        keystore.add_entry(
            "linked",
            p12_keystore::KeyStoreEntry::PrivateKeyChain(chain),
        );

        let p12 = keystore.writer("secret").write().unwrap();

        let extracted = CertificateIdentity::extract_pkcs12_private_key(&p12, "secret").unwrap();
        assert_eq!(extracted, key_der);

        assert!(
            CertificateIdentity::extract_pkcs12_private_key(&p12, "wrong-password").is_err(),
            "existing password validation must remain intact"
        );
    }

    #[test]
    fn issue_195_certificate_only_p12_still_has_no_private_key() {
        let pfx = Pfx {
            version: Version::V3,
            auth_safe: data_content(Vec::<ContentInfo>::new().to_der().unwrap()),
            mac_data: None,
        }
        .to_der()
        .unwrap();

        let err = CertificateIdentity::extract_pkcs12_private_key(&pfx, "").unwrap_err();
        assert!(
            err.to_string().contains("No private key found in P12 file"),
            "unexpected error: {err}"
        );
    }
}
