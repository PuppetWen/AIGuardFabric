use super::{CarrierPresence, HttpConfiguration, MAX_RESPONSE_BYTES};
use crate::http::RpcResponse;
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub(super) fn invalid() -> DomainError {
    DomainError::Parse("Scheduler observation has invalid, missing or contradictory evidence".into())
}

pub(super) fn unavailable() -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "alicloud-schedulerx3".into(),
        cause: "Scheduler read failed; no complete observation was published".into(),
    }
}

pub(super) fn data(response: &RpcResponse) -> DomainResult<(&Value, String, usize)> {
    match response.status {
        401 => return Err(DomainError::Unauthenticated("Scheduler provider rejected this read".into())),
        403 => return Err(DomainError::Forbidden("Scheduler provider rejected this read".into())),
        200..300 => {}
        _ => return Err(unavailable()),
    }
    let bytes = serde_json::to_vec(&response.body)?.len();
    if bytes > MAX_RESPONSE_BYTES
        || response.body["Code"].as_i64() != Some(200)
        || response.body["Success"].as_bool() != Some(true)
    {
        return Err(invalid());
    }
    let request_id = required_text(&response.body, "RequestId", 256)?.to_owned();
    if request_id.trim() != request_id {
        return Err(invalid());
    }
    let object = response.body.get("Data").filter(|value| value.is_object()).ok_or_else(invalid)?;
    Ok((object, request_id, bytes))
}

pub(super) fn required_text<'a>(value: &'a Value, key: &str, max: usize) -> DomainResult<&'a str> {
    let text = value.get(key).and_then(Value::as_str).ok_or_else(invalid)?;
    if text.trim().is_empty() || text.len() > max || text.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(text)
}

pub(super) fn optional_text(value: &Value, key: &str, max: usize) -> DomainResult<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.len() <= max && !text.chars().any(char::is_control) => Ok(Some(text.clone())),
        _ => Err(invalid()),
    }
}

pub(super) fn identifier(value: &Value) -> DomainResult<String> {
    let id = match value {
        Value::Number(number) => number.as_i64().ok_or_else(invalid)?,
        Value::String(text) => {
            if text.len() > 19 || text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            let number = text.parse::<i64>().map_err(|_| invalid())?;
            if number.to_string() != *text {
                return Err(invalid());
            }
            number
        }
        _ => return Err(invalid()),
    };
    if id <= 0 {
        return Err(invalid());
    }
    Ok(id.to_string())
}

pub(super) fn optional_identifier(value: &Value, key: &str) -> DomainResult<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(id) => identifier(id).map(Some),
    }
}

pub(super) fn optional_integer(value: &Value, key: &str) -> DomainResult<Option<i32>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(number) => number.as_i64().and_then(|number| i32::try_from(number).ok()).map(Some).ok_or_else(invalid),
    }
}

pub(super) fn nonnegative(value: &Value, key: &str) -> DomainResult<Option<i32>> {
    let number = optional_integer(value, key)?;
    if number.is_some_and(|number| number < 0) {
        return Err(invalid());
    }
    Ok(number)
}

pub(super) fn required_count(value: &Value, key: &str) -> DomainResult<u32> {
    value.get(key).and_then(Value::as_u64).and_then(|number| u32::try_from(number).ok()).ok_or_else(invalid)
}

pub(super) fn native_time(value: &Value) -> DomainResult<Option<String>> {
    match value.get("UpdateTime") {
        None | Some(Value::Null) => Ok(None),
        Some(number) => {
            number.as_i64().filter(|number| *number >= 0).map(|number| Some(number.to_string())).ok_or_else(invalid)
        }
    }
}

pub(super) fn alias<'a>(value: &'a Value, first: &str, second: &str) -> DomainResult<Option<&'a Value>> {
    match (value.get(first), value.get(second)) {
        (Some(left), Some(right)) if left != right => Err(invalid()),
        (Some(left), _) => Ok(Some(left)),
        (_, right) => Ok(right),
    }
}

pub(super) fn zone(value: &Value) -> DomainResult<Option<String>> {
    match alias(value, "TimeZone", "Timezone")? {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.len() <= 64 && !text.chars().any(char::is_control) => Ok(Some(text.clone())),
        _ => Err(invalid()),
    }
}

fn carrier(value: Option<&Value>) -> DomainResult<CarrierPresence> {
    match value {
        None => Ok(CarrierPresence::Missing),
        Some(Value::Null) => Ok(CarrierPresence::Null),
        Some(Value::String(text)) if text.len() <= 65_536 => {
            Ok(if text.is_empty() { CarrierPresence::Empty } else { CarrierPresence::Present })
        }
        _ => Err(invalid()),
    }
}

pub(super) fn opaque(value: &Value) -> DomainResult<HttpConfiguration> {
    let parameters = value.get("Parameters");
    let handler = value.get("JobHandler");
    let attributes = alias(value, "Xattrs", "XAttrs")?;
    let script = value.get("Script");
    let presence = [carrier(parameters)?, carrier(handler)?, carrier(attributes)?, carrier(script)?];
    let fingerprint = hash(&json!({"presence":presence,"values":[parameters,handler,attributes,script]}))?;
    Ok(HttpConfiguration {
        verified: false,
        parameters: presence[0],
        handler: presence[1],
        attributes: presence[2],
        script: presence[3],
        fingerprint,
    })
}

pub(super) fn hash(value: &Value) -> DomainResult<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&canonical(value))?)))
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            let mut sorted = Map::new();
            for key in keys {
                sorted.insert(key.clone(), canonical(&object[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        _ => value.clone(),
    }
}
