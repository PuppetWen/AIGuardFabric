//! Per-tenant rule revisions. Publication requires positive/negative sample regression.
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    rule::RuleDefinition,
    time::Timestamp,
};
use agf_scan::{
    loader::{RulePack, RulePackLoader},
    samples::SampleRegression,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

pub(crate) const KIND: &str = "detection-rules";
pub(crate) mod publication;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    pub definition: RuleDefinition,
    pub changed_at: Timestamp,
    pub actor: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    pub entries: BTreeMap<String, Vec<Revision>>,
}

#[derive(Debug, Default)]
pub struct RuleCache {
    inner: std::sync::Mutex<BTreeMap<TenantId, (String, Arc<RulePack>)>>,
}

pub(crate) fn record(tenant: TenantId) -> Id {
    deterministic_id(KIND, &tenant.to_string())
}

pub async fn registry(state: &AppState, tenant: TenantId) -> DomainResult<Registry> {
    Ok(state.configurations.get(tenant, KIND, record(tenant)).await?.unwrap_or_default())
}

pub async fn pack(state: &AppState, tenant: TenantId) -> DomainResult<Arc<RulePack>> {
    let registry = registry(state, tenant).await?;
    pack_from_registry(state, tenant, registry)
}

/// Reuse the same compilation/cache semantics after an authoritative transaction read.
pub(crate) fn pack_from_registry(
    state: &AppState,
    tenant: TenantId,
    registry: Registry,
) -> DomainResult<Arc<RulePack>> {
    if registry.entries.is_empty() {
        return Ok(state.rules.clone());
    }
    let fingerprint = agf_core::secret::content_hash(&format!(
        "{}:{}",
        state.rules.report.pack_fingerprint,
        serde_json::to_string(&registry)?
    ));
    {
        let cache = state.rule_cache.inner.lock().map_err(|e| DomainError::Internal(e.to_string()))?;
        if let Some((saved, pack)) = cache.get(&tenant) {
            if saved == &fingerprint {
                return Ok(pack.clone());
            }
        }
    }
    let mut rules: BTreeMap<_, _> = state.rules.rules.iter().map(|r| (r.key.clone(), r.clone())).collect();
    for (key, revisions) in registry.entries {
        if let Some(revision) = revisions.last() {
            rules.insert(key, revision.definition.clone());
        }
    }
    let pack = Arc::new(RulePackLoader::strict().load_inline(rules.into_values().collect())?);
    let mut cache = state.rule_cache.inner.lock().map_err(|e| DomainError::Internal(e.to_string()))?;
    if cache.len() >= 128 {
        cache.clear();
    }
    cache.insert(tenant, (fingerprint, pack.clone()));
    Ok(pack)
}

pub async fn get(state: &AppState, tenant: TenantId, key: &str) -> DomainResult<RuleDefinition> {
    pack(state, tenant)
        .await?
        .rules
        .iter()
        .find(|r| r.key == key)
        .cloned()
        .ok_or_else(|| DomainError::NotFound { entity: "rule", id: key.into() })
}

/// Atomic modification avoids lost updates between enable/rollout/editor operations.
pub async fn change<F>(
    state: &AppState,
    tenant: TenantId,
    key: &str,
    actor: String,
    apply: F,
) -> DomainResult<RuleDefinition>
where
    F: FnOnce(Option<RuleDefinition>) -> DomainResult<RuleDefinition> + Send,
{
    let builtin = state.rules.rules.iter().find(|r| r.key == key).cloned();
    let mut saved = None;
    state
        .configurations
        .mutate::<Registry, _>(tenant, KIND, record(tenant), |registry| {
            saved = Some(revise(registry, key, builtin, actor, apply)?);
            Ok(())
        })
        .await?;
    saved.ok_or_else(|| DomainError::Internal("规则未保存".into()))
}

fn revise<F>(
    registry: &mut Registry,
    key: &str,
    builtin: Option<RuleDefinition>,
    actor: String,
    apply: F,
) -> DomainResult<RuleDefinition>
where
    F: FnOnce(Option<RuleDefinition>) -> DomainResult<RuleDefinition>,
{
    let history = registry.entries.entry(key.into()).or_default();
    let previous = history.last().map(|r| r.definition.clone()).or(builtin);
    let previous_version = previous.as_ref().map_or(0, |r| r.version);
    let mut definition = apply(previous.clone())?;
    if definition.key != key
        || key.is_empty()
        || key.len() > 128
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(DomainError::Validation(
            "规则键须为 1..128 位字母、数字、点、短横线或下划线，发布后不可修改".into(),
        ));
    }
    definition.version = previous_version.checked_add(1).ok_or_else(|| DomainError::Conflict("规则版本溢出".into()))?;
    RulePackLoader::strict().load_inline(vec![definition.clone()])?;
    let outcome = SampleRegression::new().run_rule(&definition)?;
    if !outcome.passed {
        return Err(DomainError::Validation(format!("正负样本回归失败：{:?}", outcome.failure_notes())));
    }
    if history.is_empty() {
        if let Some(original) = previous {
            history.push(Revision { definition: original, changed_at: Timestamp::now(), actor: "builtin".into() });
        }
    }
    history.push(Revision { definition: definition.clone(), changed_at: Timestamp::now(), actor });
    if history.len() > 100 {
        history.drain(..history.len() - 100);
    }
    Ok(definition)
}
