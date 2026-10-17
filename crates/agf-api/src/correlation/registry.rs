//! 配置串行更新与版本历史，避免多管理员覆盖配置；每次发布执行正负序列回归。
use super::{Definition, Registry, Revision, TenantId};
use crate::state::AppState;
use agf_core::{
    audit::AuditLog,
    error::{DomainError, DomainResult},
    ids::deterministic_id,
    time::Timestamp,
};
use agf_correlate::temporal::CorrelationRule;

pub(crate) const KIND: &str = "correlation-rules";

pub(crate) fn record(tenant: TenantId) -> agf_core::ids::Id {
    deterministic_id(KIND, &tenant.to_string())
}

pub async fn get(state: &AppState, tenant: TenantId) -> DomainResult<Registry> {
    Ok(state.configurations.get(tenant, KIND, record(tenant)).await?.unwrap_or_default())
}

pub async fn active(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Revision>> {
    Ok(active_from_registry(get(state, tenant).await?))
}

pub(crate) fn active_from_registry(registry: Registry) -> Vec<Revision> {
    registry
        .entries
        .into_values()
        .filter_map(|versions| versions.last().cloned())
        .filter(|r| !r.deleted && r.definition.enabled)
        .collect()
}

pub fn validate(definition: &Definition) -> DomainResult<serde_json::Value> {
    let key = definition.rule.key();
    if key.is_empty() || key.len() > 64 || !key.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)) {
        return Err(invalid("Rule key must contain 1–64 letters, digits, hyphens or underscores"));
    }
    if !(1..=604_800).contains(&definition.window_secs) {
        return Err(invalid("Window must be 1–604800 seconds"));
    }
    if definition.positive.is_empty()
        || definition.negative.is_empty()
        || definition.positive.len() > 128
        || definition.negative.len() > 128
    {
        return Err(invalid("Supply 1–128 events in each positive and negative sample sequence"));
    }
    for sample in [&definition.positive, &definition.negative] {
        let tenant = sample[0].tenant_id;
        let ids = sample.iter().map(|e| e.id).collect::<std::collections::BTreeSet<_>>();
        if ids.len() != sample.len() || sample.iter().any(|e| e.tenant_id != tenant) {
            return Err(invalid("Sample events must have distinct IDs and belong to one tenant"));
        }
    }
    match &definition.rule {
        CorrelationRule::Match { name, rule_keys, .. } => {
            valid_name(name)?;
            if rule_keys.is_empty() || rule_keys.len() > 32 {
                return Err(invalid("Select 1–32 detection rule keys"));
            }
        }
        CorrelationRule::Temporal(rule) => {
            valid_name(&rule.name)?;
            if rule.window_secs != definition.window_secs
                || rule.steps.is_empty()
                || rule.steps.len() > 16
                || rule.steps.iter().all(|step| step.optional)
                || rule.steps.iter().any(|step| step.min_events > 1000)
            {
                return Err(invalid(
                    "Temporal rules need 1–16 steps, a required step and the same window as the configuration",
                ));
            }
        }
        CorrelationRule::Graph(rule) => {
            valid_name(&rule.name)?;
            if !(1..=8).contains(&rule.max_hops) {
                return Err(invalid("Graph paths must have 1–8 hops"));
            }
        }
        CorrelationRule::Baseline(rule) => {
            valid_name(&rule.name)?;
            if !super::evaluate::METRICS.contains(&rule.metric.as_str())
                || !(5..=10_000).contains(&rule.min_samples)
                || !rule.z_threshold.is_finite()
                || !(0.1..=100.0).contains(&rule.z_threshold)
            {
                return Err(invalid("Choose a supported metric, 5–10000 warm-up samples and a Z threshold of 0.1–100"));
            }
        }
    }
    let preview = |events: &[super::Event]| {
        events.last().and_then(|anchor| super::evaluate::run(definition, anchor.tenant_id, events, anchor.id))
    };
    let positive = preview(&definition.positive);
    let negative = preview(&definition.negative);
    Ok(serde_json::json!({"passed":positive.is_some() && negative.is_none(),"positive":positive,"negative":negative}))
}

pub async fn save(
    state: &AppState,
    tenant: TenantId,
    actor: String,
    definition: Definition,
    expected: u64,
    deleted: bool,
) -> DomainResult<Revision> {
    save_inner(state, tenant, actor, definition, expected, deleted, None).await
}

/// Persist a rule revision and its success audit in one tenant transaction.
pub async fn save_audited(
    state: &AppState,
    tenant: TenantId,
    actor: String,
    definition: Definition,
    expected: u64,
    deleted: bool,
    audit: AuditLog,
) -> DomainResult<Revision> {
    save_inner(state, tenant, actor, definition, expected, deleted, Some(audit)).await
}

async fn save_inner(
    state: &AppState,
    tenant: TenantId,
    actor: String,
    definition: Definition,
    expected: u64,
    deleted: bool,
    audit: Option<AuditLog>,
) -> DomainResult<Revision> {
    let result = validate(&definition)?;
    if result["passed"] != true {
        return Err(invalid("Positive sample must match and negative sample must not match"));
    }
    let key = definition.rule.key().to_owned();
    let lookup = key.clone();
    let update = move |registry: &mut Registry| {
        if !registry.entries.contains_key(&key) && registry.entries.len() >= 64 {
            return Err(invalid("A tenant can retain at most 64 correlation rules"));
        }
        let versions = registry.entries.entry(key).or_default();
        if versions.last().map_or(0, |r| r.version) != expected {
            return Err(DomainError::Conflict("Rule changed; reload its latest version before saving".into()));
        }
        versions.push(Revision { definition, version: expected + 1, actor, changed_at: Timestamp::now(), deleted });
        if versions.len() > 10 {
            versions.remove(0);
        }
        Ok(())
    };
    let id = deterministic_id(KIND, &tenant.to_string());
    let (registry, sealed) = if let Some(entry) = audit.as_ref() {
        state.configurations.mutate_audited::<Registry, _>(tenant, KIND, id, entry.clone(), update).await?
    } else {
        (state.configurations.mutate::<Registry, _>(tenant, KIND, id, update).await?, None)
    };
    if let Some(entry) = audit {
        if let Some(sealed) = sealed {
            if let Err(error) = state.store.hydrate_audit(&sealed) {
                tracing::warn!(%error, "已提交的关联规则审计内存投影刷新失败");
            }
        } else {
            state.store.audit_append_durable(entry).await?;
        }
    }
    registry.entries.get(&lookup).and_then(|v| v.last()).cloned().ok_or_else(|| invalid("Rule was not saved"))
}

fn valid_name(name: &str) -> DomainResult<()> {
    if name.trim().is_empty() || name.len() > 320 {
        Err(invalid("Rule name must contain 1–320 bytes"))
    } else {
        Ok(())
    }
}
fn invalid(message: &str) -> DomainError {
    DomainError::Validation(message.into())
}
