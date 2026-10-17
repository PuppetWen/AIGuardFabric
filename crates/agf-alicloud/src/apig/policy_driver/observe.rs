use super::{Binding, Observation, contract::Action, json};
use crate::http::RpcResponse;
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json as value};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Validate independent-policy and attachment evidence for one exact ModelAPI deployment.
/// Unknown fields are retained internally, but never become proof of authorization or data-plane application.
///
/// # Errors
/// Response identity, class, deployment, legacy configuration or attachment evidence is missing or contradictory.
pub fn parse_current(
    binding: &Binding,
    api: &RpcResponse,
    policy: &RpcResponse,
    attachment: &RpcResponse,
) -> DomainResult<Observation> {
    binding.validate()?;
    let captured_evidence = super::evidence::capture(api, policy, attachment)?;
    let api = data(api, Action::HttpApi)?;
    if text(&api, "httpApiId", 256)? != binding.http_api_id || text(&api, "type", 32)? != "LLM" {
        return Err(evidence("Selected resource is not the exact ModelAPI"));
    }
    if api.get("gatewayId").is_some_and(|id| id.as_str() != Some(binding.gateway_id.as_str())) {
        return Err(evidence("ModelAPI owner gateway differs or is explicitly unknown"));
    }
    let deployment = deployment(&api, binding)?;
    let policy = data(policy, Action::Policy)?;
    if text(&policy, "policyId", 256)? != binding.policy_id || text(&policy, "className", 64)? != "AiTokenRateLimit" {
        return Err(evidence("Independent policy identity or class differs"));
    }
    text(&policy, "classId", 256)?;
    text(&policy, "name", 512)?;
    optional_text(&policy, "description", 8192)?;
    let config = json::parse(configuration(&policy)?)?;
    let attachment = data(attachment, Action::Attachment)?;
    attachment_matches(&attachment, binding, &config)?;
    let digest = json::fingerprint(&value!({
        "binding": binding, "apiGatewayId": api.get("gatewayId"), "deployment": deployment,
        "policy": policy, "config": config, "attachment": attachment,
    }));
    Ok(Observation { binding: binding.clone(), policy, config, attachment, digest, evidence: captured_evidence })
}

fn deployment(api: &Value, binding: &Binding) -> DomainResult<Value> {
    let deployments = api["deployConfigs"]
        .as_array()
        .filter(|items| items.len() <= 200)
        .ok_or_else(|| evidence("Deployment evidence is missing or exceeds 200 items"))?;
    let mut selected = None;
    for deployment in deployments {
        let gateway = text(deployment, "gatewayId", 256)?;
        let environment = text(deployment, "environmentId", 256)?;
        if gateway != binding.gateway_id || environment != binding.environment_id {
            continue;
        }
        if selected.is_some() {
            return Err(evidence("Selected deployment appears more than once"));
        }
        let info = &deployment["gatewayInfo"];
        if text(info, "gatewayId", 256)? != gateway
            || !matches!(text(info, "gatewayEdition", 64)?, "Professional" | "Serverless")
        {
            return Err(evidence("Gateway evidence is contradictory or unsupported"));
        }
        let configs = deployment["policyConfigs"]
            .as_array()
            .filter(|items| items.len() <= 200)
            .ok_or_else(|| evidence("Selected deployment has no bounded policy list"))?;
        let mut matches = 0;
        for config in configs {
            if text(config, "type", 64)? != "AiTokenRateLimit" {
                continue;
            }
            matches += 1;
            let reference = &config["policyReference"];
            if text(reference, "policyId", 256)? != binding.policy_id
                || text(reference, "policyAttachmentId", 256)? != binding.attachment_id
                || config["enable"] != Value::Bool(true)
            {
                return Err(evidence("Independent policy reference or enabled state differs"));
            }
            if config.get("aiTokenRateLimitConfig").is_some_and(|legacy| !legacy.is_null()) {
                return Err(evidence("Expanded or legacy inline policy requires explicit migration review"));
            }
        }
        if matches != 1 {
            return Err(evidence("Exactly one independent AiTokenRateLimit reference is required"));
        }
        selected = Some(deployment.clone());
    }
    selected.ok_or_else(|| evidence("Selected gateway and environment deployment was not observed"))
}

fn attachment_matches(attachment: &Value, binding: &Binding, config: &Value) -> DomainResult<()> {
    let expected = [
        ("policyAttachmentId", binding.attachment_id.as_str()),
        ("policyId", binding.policy_id.as_str()),
        ("attachResourceId", binding.http_api_id.as_str()),
        ("gatewayId", binding.gateway_id.as_str()),
        ("environmentId", binding.environment_id.as_str()),
    ];
    for (field, id) in expected {
        if text(attachment, field, 256)? != id {
            return Err(evidence("Attachment identity differs from binding"));
        }
    }
    // The ModelAPI creation guide uses LLMApi; the Get schema also documents HttpApi.
    // Both require the exact LLM API and independent-reference evidence above.
    if !matches!(text(attachment, "attachResourceType", 64)?, "LLMApi" | "HttpApi") {
        return Err(evidence("Unsupported attachment resource type"));
    }
    if let Some(raw) = attachment.get("config").filter(|value| !value.is_null()) {
        let raw = raw
            .as_str()
            .filter(|raw| raw.len() <= json::MAX_CONFIG_BYTES)
            .ok_or_else(|| evidence("Attachment config is not a bounded string"))?;
        if !raw.is_empty() && json::canonical(&json::parse(raw)?) != json::canonical(config) {
            return Err(evidence("Attachment config conflicts with the independent policy"));
        }
    }
    Ok(())
}

pub(super) fn data(response: &RpcResponse, action: Action) -> DomainResult<Value> {
    if !(200..300).contains(&response.status) || response.body.to_string().len() > MAX_RESPONSE_BYTES {
        return Err(evidence("APIG response is unsuccessful or too large"));
    }
    let code = if action == Action::Attachment { "200" } else { "Ok" };
    if response.body["code"].as_str() != Some(code) {
        return Err(evidence("APIG response has no documented successful status"));
    }
    text(&response.body, "requestId", 256)?;
    response
        .body
        .get("data")
        .filter(|data| data.is_object())
        .cloned()
        .ok_or_else(|| evidence("APIG response is missing object data"))
}

pub(super) fn text<'a>(value: &'a Value, field: &str, maximum: usize) -> DomainResult<&'a str> {
    optional_text(value, field, maximum)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| evidence("APIG evidence is missing a nonempty string"))
}

pub(super) fn configuration(value: &Value) -> DomainResult<&str> {
    value["config"]
        .as_str()
        .filter(|raw| !raw.is_empty() && raw.len() <= json::MAX_CONFIG_BYTES)
        .ok_or_else(|| evidence("APIG policy has no bounded JSON config string"))
}

pub(super) fn optional_text<'a>(value: &'a Value, field: &str, maximum: usize) -> DomainResult<Option<&'a str>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) if raw.len() <= maximum && !raw.chars().any(char::is_control) => Ok(Some(raw)),
        _ => Err(evidence("APIG evidence has an invalid string")),
    }
}

pub(super) fn evidence(detail: &str) -> DomainError {
    DomainError::PreconditionFailed(detail.into())
}
