//! Independent RFC 2104 / ACS3 verifier for actual requests, never the production signer.
use axum::http::{HeaderMap, Uri};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt::Write as _};

pub(super) fn query(uri: &Uri) -> anyhow::Result<BTreeMap<String, String>> {
    let url = reqwest::Url::parse(&format!("http://127.0.0.1{uri}"))?;
    let mut result = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        anyhow::ensure!(result.insert(key.into_owned(), value.into_owned()).is_none(), "duplicate RPC field");
    }
    Ok(result)
}
fn text<'a>(headers: &'a HeaderMap, name: &str) -> anyhow::Result<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok()).ok_or_else(|| anyhow::anyhow!("required RPC header absent"))
}
fn encoded(value: &str) -> anyhow::Result<String> {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            write!(out, "%{byte:02X}")?;
        }
    }
    Ok(out)
}
pub(super) fn verify(headers: &HeaderMap, uri: &Uri) -> anyhow::Result<BTreeMap<String, String>> {
    let host = reqwest::Url::parse(&format!("http://{}", text(headers, "host")?))?;
    anyhow::ensure!(
        host.host_str() == Some("127.0.0.1") && host.port().is_some(),
        "RPC host must be the owned literal loopback"
    );
    anyhow::ensure!(text(headers, "x-acs-version")? == "2024-06-24", "RPC version differs");
    let authorization = text(headers, "authorization")?
        .strip_prefix("ACS3-HMAC-SHA256 ")
        .ok_or_else(|| anyhow::anyhow!("RPC signing scheme differs"))?;
    let mut parts = BTreeMap::new();
    for part in authorization.split(',') {
        let (key, value) = part.split_once('=').ok_or_else(|| anyhow::anyhow!("invalid RPC authorization"))?;
        anyhow::ensure!(parts.insert(key, value).is_none(), "duplicate RPC auth field");
    }
    anyhow::ensure!(
        parts.len() == 3 && parts.get("Credential").copied() == Some(super::provider::ACCESS_KEY),
        "RPC key differs"
    );
    let signed = *parts.get("SignedHeaders").ok_or_else(|| anyhow::anyhow!("signed headers absent"))?;
    let names: Vec<_> = signed.split(';').collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    anyhow::ensure!(names == sorted, "RPC headers not canonical");
    let mut canonical_headers = String::new();
    for required in
        ["host", "x-acs-action", "x-acs-version", "x-acs-date", "x-acs-signature-nonce", "x-acs-content-sha256"]
    {
        anyhow::ensure!(names.contains(&required), "RPC required header not signed");
    }
    for name in names {
        writeln!(canonical_headers, "{name}:{}", text(headers, name)?.trim())?;
    }
    chrono::DateTime::parse_from_rfc3339(text(headers, "x-acs-date")?)?;
    anyhow::ensure!(
        !text(headers, "x-acs-signature-nonce")?.is_empty() && !headers.contains_key("x-acs-security-token"),
        "RPC metadata differs"
    );
    let payload_hash = format!("{:x}", Sha256::digest([]));
    anyhow::ensure!(text(headers, "x-acs-content-sha256")? == payload_hash, "RPC body hash differs");
    let values = query(uri)?;
    let mut pairs = Vec::new();
    for (key, value) in &values {
        pairs.push((encoded(key)?, encoded(value)?));
    }
    pairs.sort();
    let canonical_query = pairs.into_iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join("&");
    anyhow::ensure!(uri.to_string() == format!("/?{canonical_query}"), "RPC query encoding differs");
    let canonical = format!("GET\n/\n{canonical_query}\n{canonical_headers}\n{signed}\n{payload_hash}");
    let to_sign = format!("ACS3-HMAC-SHA256\n{:x}", Sha256::digest(canonical.as_bytes()));
    let expected = hmac(super::provider::SECRET.as_bytes(), to_sign.as_bytes());
    anyhow::ensure!(parts.get("Signature").copied() == Some(expected.as_str()), "independent RPC MAC differs");
    Ok(values)
}
fn hmac(key: &[u8], message: &[u8]) -> String {
    let mut block = [0_u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    format!("{:x}", outer.finalize())
}
