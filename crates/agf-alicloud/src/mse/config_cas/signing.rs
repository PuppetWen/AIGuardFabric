use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderValue};
use sha1::Sha1;

// Classic RAM algorithm verified against the official SDK aliyun_auth.ts:
// resource = namespace + '+' + group, or group for the public namespace;
// signature = base64(HMAC-SHA1(secret, resource + '+' + timestamp)). No RPC '&' suffix.
pub(super) fn validate_credential(credential: &CloudCredential) -> DomainResult<()> {
    if credential.access_key_id.is_empty()
        || credential.access_key_id.len() > 256
        || credential.access_key_secret.is_empty()
        || credential.access_key_secret.len() > 4096
        || credential.is_expired(Timestamp::now())
    {
        return Err(DomainError::Unauthenticated("Nacos credentials are missing, invalid or expired".into()));
    }
    if credential.security_token.as_ref().is_some_and(|token| token.is_empty() || token.len() > 16 * 1024) {
        return Err(DomainError::Unauthenticated("Nacos security token is invalid".into()));
    }
    Ok(())
}
pub(super) fn signature(key: &ConfigKey, secret: &str, timestamp: i64) -> DomainResult<String> {
    let resource =
        if key.namespace_id.is_empty() { key.group.clone() } else { format!("{}+{}", key.namespace_id, key.group) };
    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes())
        .map_err(|_| DomainError::Crypto("Cannot initialize Nacos request signer".into()))?;
    mac.update(format!("{resource}+{timestamp}").as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}
pub(super) fn headers(key: &ConfigKey, credential: &CloudCredential, timestamp: i64) -> DomainResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert("spas-accesskey", value_header(&credential.access_key_id)?);
    headers.insert("timestamp", value_header(&timestamp.to_string())?);
    headers.insert("spas-signature", value_header(&signature(key, &credential.access_key_secret, timestamp)?)?);
    if let Some(token) = &credential.security_token {
        headers.insert("spas-securitytoken", value_header(token)?);
    }
    headers.insert("accept", HeaderValue::from_static("application/json"));
    Ok(headers)
}
fn value_header(value: &str) -> DomainResult<HeaderValue> {
    let mut header = HeaderValue::from_str(value)
        .map_err(|_| DomainError::Unauthenticated("Nacos credential headers are invalid".into()))?;
    header.set_sensitive(true);
    Ok(header)
}
