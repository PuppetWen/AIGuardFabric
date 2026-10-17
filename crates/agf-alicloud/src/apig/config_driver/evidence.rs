use super::{
    ContentBinding, ModelBinding, Observation,
    parse::{invalid, parse_content, parse_models},
};
use crate::http::RpcResponse;
use agf_core::error::DomainResult;
use serde_json::{Value, json};

/// Restore AEAD-authenticated content evidence; current workflow ownership remains mandatory.
///
/// # Errors
/// Evidence shape, exact target or current parser rejects the sealed original.
pub fn restore_content(binding: &ContentBinding, value: &Value) -> DomainResult<Observation> {
    let target = json!({"kind":"content","binding":binding});
    parse_content(binding, &response(restore(value, &target)?))
}
/// Restore AEAD-authenticated ModelAPI evidence without trusting client-supplied fingerprints.
///
/// # Errors
/// Evidence shape or exact selected resource validation fails.
pub fn restore_models(binding: &ModelBinding, value: &Value) -> DomainResult<Observation> {
    let target = json!({"kind":"models","binding":binding});
    parse_models(binding, &response(restore(value, &target)?))
}
fn restore(value: &Value, target: &Value) -> DomainResult<Value> {
    if value.to_string().len() > 100 * 1024
        || value.as_object().map(serde_json::Map::len) != Some(3)
        || value["schema"] != json!(1)
        || value["target"] != *target
    {
        return Err(invalid("APIG sealed configuration evidence has an invalid schema or target"));
    }
    value.get("response").filter(|v| v.is_object()).cloned().ok_or_else(|| invalid("APIG sealed response is missing"))
}
pub(super) fn response(data: Value) -> RpcResponse {
    RpcResponse {
        status: 200,
        body: json!({"code":"Ok","requestId":"sealed-local-evidence","data":data}),
        raw: String::new(),
    }
}
