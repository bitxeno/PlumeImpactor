mod login;
mod token;
mod two_factor_auth;

use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use reqwest::Response;
use sha2::Sha256;
use srp::client::SrpClientVerifier;

use crate::Error;

pub async fn parse_response(
    res: Result<Response, reqwest::Error>,
) -> Result<plist::Dictionary, Error> {
    let res = res?;
    let status = res.status();
    let res = res.text().await?;
    if !status.is_success() {
        let mut error = plist::Dictionary::new();
        error.insert(
            "ec".to_string(),
            plist::Value::Integer(status.as_u16().into()),
        );

        // Try to extract the HTML <title> from the response body to use as the error message.
        let mut em_msg = "Possibly triggered Apple's risk control.".to_string();
        if let Some(start_tag) = res.find("<title") {
            if let Some(gt_pos) = res[start_tag..].find('>') {
                let content_start = start_tag + gt_pos + 1;
                if content_start < res.len() {
                    if let Some(end_rel) = res[content_start..].find("</title>") {
                        let end = content_start + end_rel;
                        let title = res[content_start..end].trim().to_string();
                        if !title.is_empty() {
                            em_msg = format!("{}. {}", title, em_msg);
                        }
                    }
                }
            }
        }

        error.insert("em".to_string(), plist::Value::String(em_msg));
        return Ok(error);
    }
    let res: plist::Dictionary = plist::from_bytes(res.as_bytes())?;
    let res: plist::Value = res.get("Response").unwrap().to_owned();
    match res {
        plist::Value::Dictionary(dict) => Ok(dict),
        _ => Err(crate::Error::Parse),
    }
}

pub fn check_error(res: &plist::Dictionary) -> Result<(), Error> {
    let res = match res.get("Status") {
        Some(plist::Value::Dictionary(d)) => d,
        _ => &res,
    };

    if res.get("ec").unwrap().as_signed_integer().unwrap() != 0 {
        return Err(Error::AuthSrpWithMessage(
            res.get("ec").unwrap().as_signed_integer().unwrap().into(),
            res.get("em").unwrap().as_string().unwrap().to_owned(),
        ));
    }

    Ok(())
}

pub fn decrypt_cbc(usr: &SrpClientVerifier<Sha256>, data: &[u8]) -> Vec<u8> {
    let extra_data_key = create_session_key(usr, "extra data key:");
    let extra_data_iv = create_session_key(usr, "extra data iv:");
    let extra_data_iv = &extra_data_iv[..16];

    cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)
        .unwrap()
        .decrypt_padded_vec_mut::<Pkcs7>(&data)
        .unwrap()
}

pub fn create_session_key(usr: &SrpClientVerifier<Sha256>, name: &str) -> Vec<u8> {
    Hmac::<Sha256>::new_from_slice(&usr.key())
        .unwrap()
        .chain_update(name.as_bytes())
        .finalize()
        .into_bytes()
        .to_vec()
}
