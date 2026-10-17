use super::{ACCESS_KEY, SECRET, TOKEN, wire::Captured, wire::fixture_error};
use agf_core::error::DomainResult;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fmt::Write as _};

pub(crate) fn query(request: &Captured) -> DomainResult<BTreeMap<String, String>> {
    let (path, raw) = request.target.split_once('?').unwrap_or((&request.target, ""));
    if path != "/" {
        return Err(fixture_error("RPC path differs"));
    }
    let mut values = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if values.insert(name.into_owned(), value.into_owned()).is_some() {
            return Err(fixture_error("duplicate RPC query key"));
        }
    }
    Ok(values)
}

pub(crate) fn form(request: &Captured) -> DomainResult<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(request.body.as_bytes()) {
        if values.insert(name.into_owned(), value.into_owned()).is_some() {
            return Err(fixture_error("duplicate RPC form key"));
        }
    }
    let encoded = canonical(&values)?;
    if encoded != request.body {
        return Err(fixture_error("form is not canonically encoded"));
    }
    Ok(values)
}

// The typed runtime uses ACS3 for these RPC contracts. Do not call production sign_v3 to verify it.
pub(crate) fn verify_signature(request: &Captured, origin: &str) -> DomainResult<()> {
    if !matches!(request.method.as_str(), "GET" | "POST")
        || (request.method == "GET" && !request.body.is_empty())
        || (request.method == "POST"
            && (request.body.is_empty()
                || request.headers.get("content-type").map(String::as_str)
                    != Some("application/x-www-form-urlencoded")))
        || request.headers.get("host").map(String::as_str) != origin.strip_prefix("http://")
    {
        return Err(fixture_error("RPC origin, method or body differs"));
    }
    let authorization =
        request.headers.get("authorization").ok_or_else(|| fixture_error("ACS3 authorization absent"))?;
    let mut parts = BTreeMap::new();
    for part in authorization
        .strip_prefix("ACS3-HMAC-SHA256 ")
        .ok_or_else(|| fixture_error("signature algorithm differs"))?
        .split(',')
    {
        let (name, value) = part.split_once('=').ok_or_else(|| fixture_error("invalid authorization field"))?;
        if parts.insert(name, value).is_some() {
            return Err(fixture_error("duplicate authorization field"));
        }
    }
    if parts.len() != 3
        || parts.get("Credential").copied() != Some(ACCESS_KEY)
        || request.headers.get("x-acs-version").map(String::as_str) != Some("2024-06-24")
        || request.headers.get("x-acs-security-token").map(String::as_str) != Some(TOKEN)
        || !matches!(
            request.headers.get("x-acs-action").map(String::as_str),
            Some("GetApp" | "ListJobs" | "UpdateJob" | "OperateDisableJobs" | "OperateEnableJobs")
        )
        || request.headers.get("x-acs-signature-nonce").is_none_or(String::is_empty)
    {
        return Err(fixture_error("signed ACS3 RPC metadata differs"));
    }
    chrono::DateTime::parse_from_rfc3339(
        request.headers.get("x-acs-date").ok_or_else(|| fixture_error("date absent"))?,
    )
    .map_err(|_| fixture_error("invalid signed date"))?;
    let signed = parts.get("SignedHeaders").ok_or_else(|| fixture_error("signed headers absent"))?;
    let names: Vec<_> = signed.split(';').collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if names != sorted {
        return Err(fixture_error("signed headers are not canonical"));
    }
    for required in [
        "host",
        "x-acs-action",
        "x-acs-version",
        "x-acs-date",
        "x-acs-signature-nonce",
        "x-acs-security-token",
        "x-acs-content-sha256",
    ] {
        if !names.contains(&required) {
            return Err(fixture_error("required RPC header is unsigned"));
        }
    }
    let mut canonical_headers = String::new();
    for name in names {
        let value = request.headers.get(name).ok_or_else(|| fixture_error("signed header absent on wire"))?;
        writeln!(canonical_headers, "{name}:{}", value.trim()).map_err(|_| fixture_error("header encoding failed"))?;
    }
    let payload_hash = hex::encode(Sha256::digest(request.body.as_bytes()));
    if request.headers.get("x-acs-content-sha256") != Some(&payload_hash) {
        return Err(fixture_error("payload digest differs"));
    }
    let values = query(request)?;
    let canonical_query = canonical(&values)?;
    let target = if canonical_query.is_empty() { "/".into() } else { format!("/?{canonical_query}") };
    if request.target != target {
        return Err(fixture_error("RPC query is not canonically encoded"));
    }
    let canonical = format!("{}\n/\n{canonical_query}\n{canonical_headers}\n{signed}\n{payload_hash}", request.method);
    let to_sign = format!("ACS3-HMAC-SHA256\n{}", hex::encode(Sha256::digest(canonical.as_bytes())));
    let mut mac =
        Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).map_err(|_| fixture_error("MAC initialization failed"))?;
    mac.update(to_sign.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if parts.get("Signature").copied() != Some(expected.as_str()) {
        return Err(fixture_error("independent RPC MAC differs"));
    }
    Ok(())
}

fn canonical(values: &BTreeMap<String, String>) -> DomainResult<String> {
    let mut encoded = Vec::new();
    for (name, value) in values {
        encoded.push((encode(name)?, encode(value)?));
    }
    encoded.sort();
    Ok(encoded.into_iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>().join("&"))
}

fn encode(value: &str) -> DomainResult<String> {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            write!(out, "%{byte:02X}").map_err(|_| fixture_error("RFC3986 encoding failed"))?;
        }
    }
    Ok(out)
}
