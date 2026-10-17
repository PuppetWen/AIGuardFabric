use super::{
    Observation, Prepared, ServicePatch,
    parse::{invalid, parse_models, services},
    types::{Target, identifier},
};
use agf_core::error::DomainResult;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Prepare a configuration-only ModelAPI edit of already observed service/model slots.
///
/// Every other deployment and nested policy/domain/backend field is retained.
/// New model or provider creation, intelligent routing and deployment are outside this profile.
///
/// # Errors
/// Unknown slot, unsupported mutable metadata, invalid weights or no actual change.
pub fn prepare_models(baseline: &Observation, patches: &[ServicePatch]) -> DomainResult<Prepared> {
    let Target::Models(binding) = &baseline.target else {
        return Err(invalid("ModelAPI baseline is required"));
    };
    if patches.is_empty() || patches.len() > 32 {
        return Err(invalid("Select 1..32 actual ModelAPI service slots"));
    }
    // These GET aliases require a separately verified writable struct mapping; never silently omit them.
    if ["versionInfo", "ingressInfo"].iter().any(|key| baseline.raw.get(key).is_some_and(|v| !v.is_null())) {
        return Err(invalid("API version/ingress configuration requires another explicit profile"));
    }
    let index = baseline.view["selectedDeploymentIndex"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| invalid("Selected deployment index is invalid"))?;
    let existing = services(&baseline.raw["deployConfigs"][index])?;
    let mut desired = baseline.raw.clone();
    let mut selected = BTreeSet::new();
    for patch in patches {
        identifier(&patch.service_id)?;
        identifier(&patch.model_name)?;
        identifier(&patch.expected_model_name)?;
        if patch.version.as_ref().is_some_and(|v| identifier(v).is_err()) || !(1..=100).contains(&patch.weight) {
            return Err(invalid("Service patch revision or weight is invalid"));
        }
        let slot = existing
            .iter()
            .position(|row| {
                let expected_model = row.model_name == patch.expected_model_name;
                row.service_id == patch.service_id && row.version == patch.version && expected_model
            })
            .ok_or_else(|| invalid("Exact baseline service/model slot was not observed"))?;
        if !selected.insert(slot) {
            return Err(invalid("A service slot may only be edited once"));
        }
        if !existing.iter().any(|row| {
            row.service_id == patch.service_id && row.version == patch.version && row.model_name == patch.model_name
        }) {
            return Err(invalid("Desired model has not been observed for this exact service revision"));
        }
        desired["deployConfigs"][index]["serviceConfigs"][slot]["modelName"] = json!(patch.model_name);
        desired["deployConfigs"][index]["serviceConfigs"][slot]["weight"] = json!(patch.weight);
    }
    let updated = services(&desired["deployConfigs"][index])?;
    if updated.iter().map(|row| row.weight).sum::<u32>() != 100 {
        return Err(invalid("Model route weights must total exactly 100"));
    }
    let desired = parse_models(binding, &super::evidence::response(desired))?;
    if baseline.fingerprint() == desired.fingerprint() {
        return Err(invalid("No ModelAPI configuration changed"));
    }
    let mut body = serde_json::Map::new();
    for key in [
        "basePath",
        "deployConfigs",
        "agentProtocols",
        "aiProtocols",
        "authConfig",
        "description",
        "enableAuth",
        "firstByteTimeout",
        "protocols",
        "removeBasePathOnForward",
    ] {
        if let Some(value) = desired.raw.get(key) {
            body.insert(key.into(), value.clone());
        }
    }
    body.insert("onlyChangeConfig".into(), Value::Bool(true));
    let body = Value::Object(body);
    if body.to_string().len() > 96 * 1024 {
        return Err(invalid("ModelAPI update body exceeds 96 KiB"));
    }
    Ok(Prepared { baseline: baseline.clone(), body, desired })
}
