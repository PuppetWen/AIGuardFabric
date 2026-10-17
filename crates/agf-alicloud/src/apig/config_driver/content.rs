use super::{
    ContentSettings, Observation, Prepared,
    parse::{invalid, parse_content},
    types::Target,
};
use agf_core::error::DomainResult;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;

/// Prepare one installed-plugin update, retaining credentials and unmanaged JSON/YAML fields.
///
/// # Errors
/// Unsupported baseline, invalid denial code or no actual public-field change.
pub fn prepare_content(baseline: &Observation, settings: ContentSettings) -> DomainResult<Prepared> {
    let Target::Content(binding) = &baseline.target else {
        return Err(invalid("Content baseline is required"));
    };
    if !(100..=599).contains(&settings.deny_code) {
        return Err(invalid("Content denial code must be 100..599"));
    }
    let mut desired = baseline.config.clone();
    desired["checkRequest"] = json!(settings.check_request);
    desired["checkResponse"] = json!(settings.check_response);
    desired["denyCode"] = json!(settings.deny_code);
    let original = baseline.raw["pluginConfig"].as_str().ok_or_else(|| invalid("Content configuration is missing"))?;
    let original = STANDARD.decode(original).map_err(|_| invalid("Content configuration is not Base64"))?;
    let original = std::str::from_utf8(&original).map_err(|_| invalid("Content configuration is not UTF-8"))?;
    let encoded = STANDARD.encode(super::json::encode_like(original, &desired)?);
    let body =
        json!({"attachResourceIds":[binding.model.http_api_id],"enable":settings.enabled,"pluginConfig":encoded});
    let mut raw = baseline.raw.clone();
    raw["enable"] = json!(settings.enabled);
    raw["pluginConfig"] = body["pluginConfig"].clone();
    let desired = parse_content(binding, &super::evidence::response(raw))?;
    if baseline.safe_view() == desired.safe_view() {
        return Err(invalid("No public content-security setting changed"));
    }
    Ok(Prepared { baseline: baseline.clone(), body, desired })
}
