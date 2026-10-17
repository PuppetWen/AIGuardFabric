use super::{ContentBinding, ContentSettings, ModelBinding, ModelService, Observation, json, types::Target};
use crate::http::RpcResponse;
use agf_core::error::{DomainError, DomainResult};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json as value};

/// Validate the exact installed ai-security-guard attachment and private JSON/YAML configuration.
///
/// # Errors
/// Missing identity, unsafe/ambiguous document, ambiguous attachment or untrusted response.
pub fn parse_content(binding: &ContentBinding, response: &RpcResponse) -> DomainResult<Observation> {
    binding.validate()?;
    let raw = data(response)?;
    for (key, expected) in [("pluginAttachmentId", &binding.attachment_id), ("pluginId", &binding.plugin_id)] {
        if text(&raw, key)? != expected {
            return Err(invalid("Content plugin identity changed"));
        }
    }
    gateway(&raw["gatewayInfo"], &binding.model.gateway_id)?;
    if text(&raw["environmentInfo"], "environmentId")? != binding.model.environment_id {
        return Err(invalid("Content plugin environment changed"));
    }
    gateway(&raw["environmentInfo"]["gatewayInfo"], &binding.model.gateway_id)?;
    let class = &raw["pluginClassInfo"];
    for (key, expected) in [
        ("pluginClassId", binding.class_id.as_str()),
        ("version", binding.class_version.as_str()),
        ("name", "ai-security-guard"),
        ("type", "AI"),
        ("mode", "Wasm"),
    ] {
        if text(class, key)? != expected {
            return Err(invalid("Content plugin class or revision is unsupported"));
        }
    }
    let resources = raw["resourceInfos"]
        .as_array()
        .filter(|items| items.len() == 1)
        .ok_or_else(|| invalid("Exactly one content attachment resource is required"))?;
    if text(&resources[0], "resourceId")? != binding.model.http_api_id
        || !matches!(text(&resources[0], "resourceType")?, "HttpApi" | "LLMApi")
    {
        return Err(invalid("Content attachment scope changed"));
    }
    let encoded = raw["pluginConfig"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("Content plugin configuration is missing"))?;
    if encoded.len() > 88 * 1024 {
        return Err(invalid("Content plugin configuration exceeds the bound"));
    }
    let bytes = STANDARD.decode(encoded).map_err(|_| invalid("Content plugin configuration is not Base64"))?;
    let decoded = std::str::from_utf8(&bytes).map_err(|_| invalid("Content plugin configuration is not UTF-8"))?;
    let config = json::parse(decoded)
        .map_err(|_| invalid("This profile requires bounded unique string-key JSON or restricted YAML"))?;
    for field in ["serviceName", "serviceHost", "accessKey", "secretKey"] {
        if config[field].as_str().is_none_or(str::is_empty) {
            return Err(invalid("Content plugin required private configuration is missing"));
        }
    }
    if !config.get("servicePort").is_some_and(|v| {
        v.as_u64().is_some_and(|n| (1..=65_535).contains(&n))
            || v.as_str().and_then(|s| s.parse::<u16>().ok()).is_some_and(|n| n > 0)
    }) {
        return Err(invalid("Content plugin service port is unknown"));
    }
    let settings = ContentSettings {
        enabled: boolean(&raw, "enable")?,
        check_request: switch(&config, "checkRequest")?,
        check_response: switch(&config, "checkResponse")?,
        deny_code: deny_code(&config)?,
    };
    finish(
        Target::Content(binding.clone()),
        raw,
        config,
        value!({"settings":settings,"responseMayBecomeNonStreaming":settings.check_response}),
    )
}

/// Validate one current existing ModelAPI deployment, retaining all unknown configuration privately.
///
/// # Errors
/// Ambiguous deployment, unknown service identity or unsupported routing profile.
pub fn parse_models(binding: &ModelBinding, response: &RpcResponse) -> DomainResult<Observation> {
    binding.validate()?;
    let raw = data(response)?;
    if text(&raw, "httpApiId")? != binding.http_api_id
        || text(&raw, "type")? != "LLM"
        || text(&raw, "gatewayId")? != binding.gateway_id
    {
        return Err(invalid("Exact ModelAPI and gateway identity were not observed"));
    }
    let base = raw["basePath"]
        .as_str()
        .filter(|s| s.starts_with('/') && s.len() <= 1024 && !s.chars().any(char::is_control))
        .ok_or_else(|| invalid("ModelAPI base path is unknown"))?;
    let deployments = raw["deployConfigs"]
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= 100)
        .ok_or_else(|| invalid("ModelAPI deployment list is missing or exceeds the bound"))?;
    let mut selected = None;
    for (index, item) in deployments.iter().enumerate() {
        let gateway_id = text(item, "gatewayId")?;
        let environment_id = text(item, "environmentId")?;
        if gateway_id == binding.gateway_id && environment_id == binding.environment_id {
            if selected.is_some() {
                return Err(invalid("ModelAPI deployment is ambiguous"));
            }
            gateway(&item["gatewayInfo"], &binding.gateway_id)?;
            selected = Some(index);
        }
    }
    let index = selected.ok_or_else(|| invalid("Selected ModelAPI environment was not observed"))?;
    let scene = text(&deployments[index], "backendScene")?;
    if !matches!(scene, "SingleService" | "MultiServiceByRatio") {
        return Err(invalid("Model route scene requires another explicit profile"));
    }
    let services = services(&deployments[index])?;
    if scene == "SingleService" && services.len() != 1 {
        return Err(invalid("Single-service ModelAPI must contain one service"));
    }
    let view = value!({"services":services,"backendScene":scene,"basePath":base,"selectedDeploymentIndex":index,
        "configurationOnly":true,"deploymentVerified":null,"consumerApplied":null});
    finish(Target::Models(binding.clone()), raw.clone(), raw["deployConfigs"].clone(), view)
}
pub(super) fn services(deployment: &Value) -> DomainResult<Vec<ModelService>> {
    let values = deployment["serviceConfigs"]
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= 32)
        .ok_or_else(|| invalid("Model services are missing or exceed 32 entries"))?;
    let mut seen = std::collections::BTreeSet::new();
    let mut output = Vec::new();
    for item in values {
        let service_id = text(item, "serviceId")?.to_owned();
        let model_name = text(item, "modelName")?.to_owned();
        let version = match item.get("version") {
            None | Some(Value::Null) => None,
            Some(Value::String(v)) if !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control) => {
                Some(v.clone())
            }
            _ => return Err(invalid("Service revision is unknown")),
        };
        if !seen.insert((service_id.clone(), version.clone(), model_name.clone())) {
            return Err(invalid("Duplicate ModelAPI service slot"));
        }
        if !matches!(text(item, "protocol")?, "HTTP" | "HTTPS") {
            return Err(invalid("Unsupported model service protocol"));
        }
        let weight = item["weight"]
            .as_u64()
            .filter(|n| (1..=100).contains(n))
            .ok_or_else(|| invalid("Model service weight is unknown"))?;
        output.push(ModelService {
            service_id,
            version,
            model_name,
            weight: u32::try_from(weight).map_err(|_| invalid("Model service weight is invalid"))?,
        });
    }
    Ok(output)
}
pub(super) fn data(response: &RpcResponse) -> DomainResult<Value> {
    if !(200..300).contains(&response.status)
        || response.raw.len() > 128 * 1024
        || response.body.to_string().len() > 128 * 1024
        || response.body["code"].as_str() != Some("Ok")
    {
        return Err(invalid("APIG configuration response is not trusted or bounded"));
    }
    text(&response.body, "requestId")?;
    response
        .body
        .get("data")
        .filter(|v| v.is_object())
        .cloned()
        .ok_or_else(|| invalid("APIG configuration response has no object data"))
}
pub(super) fn finish(target: Target, raw: Value, config: Value, view: Value) -> DomainResult<Observation> {
    if raw.to_string().len() > 96 * 1024 {
        return Err(invalid("APIG configuration evidence exceeds 96 KiB"));
    }
    let fingerprint = json::fingerprint(&value!({"target":target,"raw":raw}));
    Ok(Observation { target, raw, config, fingerprint, view })
}
pub(super) fn text<'a>(value: &'a Value, field: &str) -> DomainResult<&'a str> {
    value[field]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 1024 && s.trim() == *s && !s.chars().any(char::is_control))
        .ok_or_else(|| invalid("APIG required configuration identity is unknown"))
}
fn gateway(value: &Value, expected: &str) -> DomainResult<()> {
    if text(value, "gatewayId")? != expected || text(value, "gatewayEdition")? != "Professional" {
        return Err(invalid("This profile requires the exact dedicated Professional gateway"));
    }
    Ok(())
}
fn switch(value: &Value, field: &str) -> DomainResult<bool> {
    match value.get(field) {
        None => Ok(false),
        Some(Value::Bool(v)) => Ok(*v),
        _ => Err(invalid("Content inspection switch is not boolean")),
    }
}
fn boolean(value: &Value, field: &str) -> DomainResult<bool> {
    value[field].as_bool().ok_or_else(|| invalid("APIG enabled state is unknown"))
}
fn deny_code(config: &Value) -> DomainResult<u16> {
    let value = config
        .get("denyCode")
        .map_or(Some(200), Value::as_u64)
        .filter(|n| (100..=599).contains(n))
        .ok_or_else(|| invalid("Content denial status is invalid"))?;
    u16::try_from(value).map_err(|_| invalid("Content denial status is invalid"))
}
pub(super) fn invalid(cause: &str) -> DomainError {
    DomainError::PreconditionFailed(cause.into())
}
