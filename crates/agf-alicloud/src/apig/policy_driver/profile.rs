use super::{
    ManagedLimit, Observation, PreparedUpdate, json,
    observe::{evidence, text},
};
use agf_core::error::DomainResult;
use serde_json::{Value, json as value};

/// Change exactly one existing global minute-rule limit, preserving the rest of the observed config.
///
/// This does not translate arbitrary policy languages, enable a disabled policy, or synchronize usage counters.
///
/// # Errors
/// The rule is absent/ambiguous, config is not an enabled flat ModelAPI profile, or a value exceeds int32.
pub fn prepare_limit(baseline: &Observation, mode: ManagedLimit, limit: u32) -> DomainResult<PreparedUpdate> {
    if limit == 0 || i32::try_from(limit).is_err() {
        return Err(evidence("Limit must be a positive int32"));
    }
    let (index, _) = selected_slot(baseline, mode)?;
    let mut desired = baseline.config.clone();
    let rules = desired["globalRules"].as_array_mut().ok_or_else(|| evidence("Missing global rules"))?;
    rules[index]["limitValue"] = value!(limit);
    let result = PreparedUpdate { baseline: baseline.clone(), desired, mode, limit };
    update_input(&result)?;
    Ok(result)
}

/// Read the current threshold of the same writable, unique global minute-rule profile.
///
/// This validates the full existing config and attachment exactly as `prepare_limit` does.
///
/// # Errors
/// The target, enabled config, attachment, unique rule or positive int32 threshold is invalid.
pub fn current_limit(baseline: &Observation, mode: ManagedLimit) -> DomainResult<u32> {
    selected_slot(baseline, mode).map(|(_, limit)| limit)
}

fn selected_slot(baseline: &Observation, mode: ManagedLimit) -> DomainResult<(usize, u32)> {
    baseline.binding.validate()?;
    validate_config(&baseline.config)?;
    writable_attachment(&baseline.attachment)?;
    let rules = baseline.config["globalRules"].as_array().ok_or_else(|| evidence("Missing global rules"))?;
    let mut index = None;
    for (candidate, rule) in rules.iter().enumerate() {
        if text(rule, "limitMode", 64)? == mode.name() {
            if index.is_some() {
                return Err(evidence("Managed global rule is ambiguous"));
            }
            index = Some(candidate);
        }
    }
    let index =
        index.ok_or_else(|| evidence("Managed global rule does not exist; creation requires another workflow"))?;
    Ok((index, positive_limit(&rules[index])?))
}

pub(super) fn validate_config(config: &Value) -> DomainResult<()> {
    if config["enable"] != Value::Bool(true) || config["enableGlobalRules"] != Value::Bool(true) {
        return Err(evidence("This profile requires the existing policy and global rules to be enabled"));
    }
    if ["redisConfig", "pluginStatus", "type", "policyReference", "aiTokenRateLimitConfig"]
        .iter()
        .any(|key| config.get(key).is_some())
    {
        return Err(evidence("Legacy, credential or read-only fields cannot be written by this profile"));
    }
    let local_rules = config["rules"]
        .as_array()
        .filter(|rules| rules.len() <= 200)
        .ok_or_else(|| evidence("The existing local rules must be an explicit bounded array"))?;
    let global_rules = config["globalRules"]
        .as_array()
        .filter(|rules| !rules.is_empty() && rules.len() <= 200)
        .ok_or_else(|| evidence("The existing global rules must be a nonempty bounded array"))?;
    for rule in local_rules {
        if !rule.is_object() {
            return Err(evidence("An existing local rule is not an object"));
        }
        text(rule, "limitType", 64)?;
        text(rule, "limitMode", 64)?;
        positive_limit(rule)?;
    }
    for rule in global_rules {
        if text(rule, "limitType", 64)? != "Global" {
            return Err(evidence("Global rule has an unsupported limitType"));
        }
        text(rule, "limitMode", 64)?;
        positive_limit(rule)?;
        for field in ["matchKey", "matchType", "matchValue"] {
            if rule.get(field).is_some_and(|value| value.as_str() != Some("")) {
                return Err(evidence("Global rules cannot silently preserve nonempty match conditions"));
            }
        }
    }
    Ok(())
}

pub(super) fn writable_attachment(attachment: &Value) -> DomainResult<()> {
    match attachment.get("config") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(raw)) if raw.is_empty() => Ok(()),
        _ => {
            Err(evidence("A nonempty attachment config needs an explicitly reviewed override contract before writing"))
        }
    }
}

fn positive_limit(rule: &Value) -> DomainResult<u32> {
    match rule["limitValue"].as_u64() {
        Some(value) if value > 0 && i32::try_from(value).is_ok() => {
            u32::try_from(value).map_err(|_| evidence("An existing rule has an invalid int32 limit"))
        }
        _ => Err(evidence("An existing rule has an invalid int32 limit")),
    }
}

pub(super) fn encoded_desired(update: &PreparedUpdate) -> DomainResult<String> {
    let raw = json::canonical(&update.desired).to_string();
    if raw.len() > json::MAX_CONFIG_BYTES {
        return Err(evidence("Desired config exceeds 64 KiB"));
    }
    Ok(raw)
}

pub(super) fn update_input(update: &PreparedUpdate) -> DomainResult<Value> {
    let raw = encoded_desired(update)?;
    let mut body = value!({"name":text(&update.baseline.policy,"name",512)?,"config":raw});
    // Missing/null and empty description remain distinct in the stored baseline.
    // No invented empty description is sent when the provider did not supply one.
    if let Some(Value::String(description)) = update.baseline.policy.get("description") {
        body["description"] = value!(description);
    }
    let input = value!({"policyId": update.baseline.binding.policy_id, "body": body});
    if input.to_string().len() > 128 * 1024 {
        return Err(evidence("Encoded UpdatePolicy request exceeds 128 KiB"));
    }
    Ok(input)
}
