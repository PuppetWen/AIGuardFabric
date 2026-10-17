//! Transport metadata validation before policy evaluation; forwarded headers follow the checked body.
use super::invalid;
use agf_core::error::DomainResult;
use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;

pub(super) const MODERN: &str = "2026-07-28";
pub(super) const VERSIONS: [&str; 4] = [MODERN, "2025-11-25", "2025-06-18", "2025-03-26"];

pub(super) fn text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

pub(super) fn version(headers: &HeaderMap, frame: &Value) -> String {
    text(headers, "mcp-protocol-version")
        .or_else(|| frame.pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion").and_then(Value::as_str))
        .unwrap_or("2025-03-26")
        .into()
}

fn header_value(value: &str) -> DomainResult<HeaderValue> {
    HeaderValue::from_str(value).map_err(|_| invalid("MCP header contains invalid characters"))
}

fn encode(value: &str) -> String {
    if value.trim() != value
        || !value.bytes().all(|b| b == 9 || (32..=126).contains(&b))
        || (value.starts_with("=?base64?") && value.ends_with("?="))
    {
        format!("=?base64?{}?=", STANDARD.encode(value))
    } else {
        value.into()
    }
}

fn decode(value: &str) -> Option<String> {
    if let Some(value) = value.strip_prefix("=?base64?").and_then(|value| value.strip_suffix("?=")) {
        String::from_utf8(STANDARD.decode(value).ok()?).ok()
    } else if value.trim() == value && value.bytes().all(|b| b == 9 || (32..=126).contains(&b)) {
        Some(value.into())
    } else {
        None
    }
}

pub(super) fn valid_frame(frame: &Value, modern: bool) -> bool {
    if !frame.is_object() || frame["jsonrpc"] != "2.0" {
        return false;
    }
    if let Some(id) = frame.get("id") {
        if !(id.is_string() || id.is_i64() || id.is_u64()) {
            return false;
        }
    }
    if let Some(method) = frame.get("method") {
        method.as_str().is_some_and(|method| !method.is_empty())
            && frame.get("params").is_none_or(Value::is_object)
            && !frame.as_object().is_some_and(|obj| obj.contains_key("result") || obj.contains_key("error"))
    } else {
        !modern && frame.get("id").is_some() && (frame.get("result").is_some() ^ frame.get("error").is_some())
    }
}

fn name(frame: &Value) -> Option<&str> {
    match frame["method"].as_str()? {
        "tools/call" | "prompts/get" => frame.pointer("/params/name").and_then(Value::as_str),
        "resources/read" => frame.pointer("/params/uri").and_then(Value::as_str),
        _ => None,
    }
}

pub(super) fn validate(headers: &HeaderMap, frame: &Value) -> DomainResult<()> {
    if version(headers, frame) != MODERN {
        return Ok(());
    }
    let version = frame.pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion").and_then(Value::as_str);
    if text(headers, "mcp-protocol-version") != version
        || version != Some(MODERN)
        || text(headers, "mcp-method") != frame["method"].as_str()
    {
        return Err(invalid("HeaderMismatch: MCP-Protocol-Version / Mcp-Method must match the JSON-RPC body"));
    }
    let needs_name = matches!(frame["method"].as_str(), Some("tools/call" | "prompts/get" | "resources/read"));
    if needs_name && (name(frame).is_none() || text(headers, "mcp-name").and_then(decode).as_deref() != name(frame)) {
        return Err(invalid("HeaderMismatch: Mcp-Name must match params.name / params.uri"));
    }
    Ok(())
}

pub(super) fn outgoing(headers: &HeaderMap, before: &Value, after: &Value) -> DomainResult<HeaderMap> {
    let mut result = HeaderMap::new();
    result.insert("accept", HeaderValue::from_static("application/json, text/event-stream"));
    if let Some(version) = text(headers, "mcp-protocol-version") {
        result.insert("mcp-protocol-version", header_value(version)?);
    }
    if version(headers, before) == MODERN {
        result.insert("mcp-method", header_value(after["method"].as_str().unwrap_or_default())?);
        if let Some(name) = name(after) {
            result.insert("mcp-name", header_value(&encode(name))?);
        }
    }
    // Unknown mirrored parameters must be forwarded. Without the upstream schema we cannot
    // safely rewrite them after redaction; refuse the call instead of forwarding stale secrets.
    for (key, value) in headers.iter().filter(|(key, _)| key.as_str().starts_with("mcp-param-")) {
        if before.get("params") != after.get("params") {
            return Err(invalid(
                "Policy redaction changed MCP parameters with mirrored headers; update the tool schema or arguments",
            ));
        }
        if value.len() > 8192 || value.to_str().ok().and_then(decode).is_none() {
            return Err(invalid("Malformed Mcp-Param header"));
        }
        result.insert(key.clone(), value.clone());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn mirrored_metadata_unicode_and_redaction() {
        let frame = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"查询",
            "_meta":{"io.modelcontextprotocol/protocolVersion":MODERN},"arguments":{"secret":"private"}}});
        let mut headers = HeaderMap::new();
        headers.insert("mcp-protocol-version", HeaderValue::from_static(MODERN));
        headers.insert("mcp-method", HeaderValue::from_static("tools/call"));
        headers.insert("mcp-name", header_value(&encode("查询")).unwrap());
        assert!(validate(&headers, &frame).is_ok());
        assert_eq!(decode(&encode("=?base64?literal?=")), Some("=?base64?literal?=".into()));
        headers.insert("mcp-name", HeaderValue::from_static("different"));
        assert!(validate(&headers, &frame).is_err());
        headers.insert("mcp-param-key", HeaderValue::from_static("private"));
        let mut redacted = frame.clone();
        redacted["params"]["arguments"]["secret"] = json!("[REDACTED]");
        assert!(outgoing(&headers, &frame, &redacted).is_err());
        assert!(!valid_frame(&json!({"jsonrpc":"2.0","id":1,"result":{}}), true));
    }
}
