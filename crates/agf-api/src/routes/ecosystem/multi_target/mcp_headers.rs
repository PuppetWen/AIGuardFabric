//! Only the existing one-string read-only tool schema is mirrored; unknown annotations fail closed.
use super::mcp_frames::invalid;
use agf_core::error::{DomainError, DomainResult};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

pub(super) fn encoded(value: &str) -> DomainResult<HeaderValue> {
    if value.len() > 4096 {
        return Err(invalid());
    }
    let plain = value.trim() == value
        && value.bytes().all(|b| matches!(b, 9 | 32..=126))
        && !(value.starts_with("=?base64?") && value.ends_with("?="));
    let value = if plain { value.to_owned() } else { format!("=?base64?{}?=", STANDARD.encode(value.as_bytes())) };
    HeaderValue::from_str(&value).map_err(|_| invalid())
}
fn annotation_count(value: &Value, depth: usize) -> DomainResult<usize> {
    if depth > 16 {
        return Err(invalid());
    }
    match value {
        Value::Object(fields) => {
            let mut total = usize::from(fields.contains_key("x-mcp-header"));
            for (name, value) in fields {
                if name != "x-mcp-header" {
                    total = total.checked_add(annotation_count(value, depth + 1)?).ok_or_else(invalid)?;
                }
            }
            Ok(total)
        }
        Value::Array(values) => values.iter().try_fold(0usize, |total, value| {
            total.checked_add(annotation_count(value, depth + 1)?).ok_or_else(invalid)
        }),
        _ => Ok(0),
    }
}
fn unsupported() -> DomainError {
    DomainError::PreconditionFailed("MCP tool header annotation requires one direct string property and a valid bounded token; select a supported read-only tool".into())
}
pub(super) fn tool(schema: &Value, argument: &str) -> DomainResult<Option<HeaderName>> {
    let declared = schema["properties"][argument].get("x-mcp-header");
    if annotation_count(schema, 0)? != usize::from(declared.is_some()) {
        return Err(unsupported());
    }
    let Some(declared) = declared else {
        return Ok(None);
    };
    let name = declared.as_str().filter(|name| !name.is_empty() && name.len() <= 64).ok_or_else(unsupported)?;
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == 96 || b"!#$%&'*+-.^_|~".contains(&b)) {
        return Err(unsupported());
    }
    if schema["properties"][argument]["type"] != "string" {
        return Err(unsupported());
    }
    Ok(Some(HeaderName::from_bytes(format!("Mcp-Param-{name}").as_bytes()).map_err(|_| unsupported())?))
}
pub(super) fn parameters(name: Option<&HeaderName>, value: &str) -> DomainResult<HeaderMap> {
    let mut out = HeaderMap::new();
    if let Some(name) = name {
        out.insert(name.clone(), encoded(value)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_controls_padding_and_literal_sentinel_are_encoded_without_header_injection() -> DomainResult<()> {
        for text in ["涓栫晫", " padded ", "line\r\nbreak", "=?base64?literal?="] {
            let value = encoded(text)?;
            let encoded = value.to_str().map_err(|_| invalid())?;
            assert!(encoded.starts_with("=?base64?") && encoded.ends_with("?="));
            assert_eq!(STANDARD.decode(&encoded[9..encoded.len() - 2]).map_err(|_| invalid())?, text.as_bytes());
        }
        assert_eq!(encoded("safe_query")?, HeaderValue::from_static("safe_query"));
        Ok(())
    }
    #[test]
    fn only_one_statically_reachable_string_annotation_is_supported() -> DomainResult<()> {
        let mut schema =
            serde_json::json!({"type":"object","properties":{"query":{"type":"string","x-mcp-header":"Query"}}});
        assert!(tool(&schema, "query")?.is_some());
        schema["allOf"] = serde_json::json!([{"x-mcp-header":"Other"}]);
        assert!(tool(&schema, "query").is_err());
        schema["allOf"] = Value::Null;
        schema["properties"]["query"]["x-mcp-header"] = serde_json::json!("bad\r\nheader");
        assert!(tool(&schema, "query").is_err());
        Ok(())
    }
}
