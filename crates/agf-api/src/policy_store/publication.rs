//! Pure readers of durable signed policy snapshots; they never initialize or publish records.
use super::*;
use agf_core::asset::Asset;
use agf_storage::configuration::ConfigurationGuard;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct TrustedPolicySelection {
    pub policies: Vec<Policy>,
    pub guards: Vec<ConfigurationGuard<'static>>,
    pub agent_ids: Vec<Id>,
}

/// Read the complete signed registry for a publication chooser without initializing records.
pub(crate) fn publication_candidates(
    state: &AppState,
    tenant: TenantId,
    payload: Option<Value>,
) -> DomainResult<Vec<Policy>> {
    let Some(payload) = payload else {
        return Ok(Vec::new());
    };
    let rows: registry::Registry =
        serde_json::from_value(payload).map_err(|_| DomainError::Internal("持久策略注册表结构已损坏".into()))?;
    rows.validate(tenant, &signer(state)?)?;
    if !rows.initialized {
        return Ok(Vec::new());
    }
    Ok(rows.entries.into_values().filter(|row| row.deleted_at.is_none()).collect())
}

/// Public evidence contains identities and fingerprints, never configuration credentials.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PublicationDependencyEvidence {
    pub kind: String,
    pub id: Id,
    pub version: Option<u64>,
    pub fingerprint: String,
}

pub(crate) fn parse_publication_snapshot(
    state: &AppState,
    tenant: TenantId,
    payload: Option<Value>,
    expected: &BTreeMap<Id, u32>,
) -> DomainResult<TrustedPolicySelection> {
    if expected.is_empty() || expected.len() > 20 || expected.iter().any(|(id, version)| id.is_nil() || *version == 0) {
        return Err(DomainError::Validation("发布须选择1到20条政策及真实正版本".into()));
    }
    let payload = payload.ok_or_else(|| {
        DomainError::PreconditionFailed("尚无持久可信策略注册表；请先在策略中心保存并核对政策".into())
    })?;
    let rows: registry::Registry = serde_json::from_value(payload)
        .map_err(|_| DomainError::Internal("持久策略注册表结构已损坏；请核对存储".into()))?;
    rows.validate(tenant, &signer(state)?).map_err(|error| match error {
        DomainError::Crypto(_) => {
            DomainError::PreconditionFailed("完整策略注册表的身份、hash或签名不可信，不能发布".into())
        }
        other => other,
    })?;
    if !rows.initialized {
        return Err(DomainError::PreconditionFailed("持久策略注册表尚未完成可信初始化".into()));
    }
    let mut policies = Vec::with_capacity(expected.len());
    let mut guards = BTreeMap::new();
    let mut agents = BTreeSet::new();
    for (id, version) in expected {
        let row = rows
            .entries
            .get(id)
            .filter(|row| row.deleted_at.is_none() && row.enabled)
            .ok_or_else(|| DomainError::PreconditionFailed("所选政策不存在、未启用或已删除；请重新选择".into()))?;
        if row.version != *version {
            return Err(DomainError::Conflict("所选政策版本已改变；请重新读取和预览".into()));
        }
        validation::candidate(row, tenant).map_err(|_| {
            DomainError::PreconditionFailed("所选签名政策不能通过当前编译或依赖格式校验；请先核对政策".into())
        })?;
        for guard in validation::guards(Some(row), tenant) {
            guards.insert((guard.kind, guard.id), guard);
        }
        agents.extend(row.scope_agent_ids.iter().copied());
        policies.push(row.clone());
    }
    // Reserve the cloud configuration and signed registry guards as well as all distinct dependencies.
    if guards.len() > 30 || agents.len() > 500 {
        return Err(DomainError::PreconditionFailed(
            "政策的完整依赖超出32项配置或500个Agent聚合上限；请缩小选择，不会截断政策".into(),
        ));
    }
    Ok(TrustedPolicySelection {
        policies,
        guards: guards.into_values().collect(),
        agent_ids: agents.into_iter().collect(),
    })
}

pub(crate) fn validate_publication_dependencies(
    tenant: TenantId,
    selected: &TrustedPolicySelection,
    values: &BTreeMap<(String, Id), Option<Value>>,
    assets: &BTreeMap<Id, Asset>,
) -> DomainResult<Vec<PublicationDependencyEvidence>> {
    let mut evidence = BTreeMap::new();
    for policy in &selected.policies {
        validation::dependencies(policy, tenant, values)?;
        if let Some(id) = policy.quota_id {
            let key = (crate::quota_definitions::KIND.to_owned(), tenant_record_id(tenant));
            let payload = values.get(&key).and_then(Option::as_ref).cloned().ok_or_else(missing)?;
            let row = crate::quota_definitions::parse_versioned_registry(payload, id)?.ok_or_else(missing)?;
            evidence.insert(("quota", id), quota_publication_evidence(&row)?);
        }
        if let Some(id) = policy.degrade_endpoint_id {
            let key = (crate::model_gateway::ENDPOINT_KIND.to_owned(), id);
            let payload = values.get(&key).and_then(Option::as_ref).ok_or_else(missing)?;
            let row: crate::model_gateway::StoredEndpoint = serde_json::from_value(payload.clone())?;
            evidence.insert(("model-endpoint", id), item("model-endpoint", id, positive(row.version), payload)?);
        }
    }
    for id in &selected.agent_ids {
        let asset = assets.get(id);
        validation::agent(tenant, *id, asset)?;
        let value = serde_json::to_value(asset.ok_or_else(missing)?)?;
        evidence.insert(("agent", *id), item("agent", *id, None, &value)?);
    }
    Ok(evidence.into_values().collect())
}

pub(crate) fn quota_publication_evidence(
    row: &crate::quota_definitions::VersionedQuota,
) -> DomainResult<PublicationDependencyEvidence> {
    item("quota", row.quota.id, positive(row.version), &serde_json::to_value(row)?)
}

fn item(kind: &str, id: Id, version: Option<u64>, value: &Value) -> DomainResult<PublicationDependencyEvidence> {
    Ok(PublicationDependencyEvidence {
        kind: kind.into(),
        id,
        version,
        fingerprint: hex::encode(Sha256::digest(serde_json::to_vec(&ordered(value.clone()))?)),
    })
}
fn ordered(value: Value) -> Value {
    match value {
        Value::Object(values) => {
            let mut values = values.into_iter().collect::<Vec<_>>();
            values.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(values.into_iter().map(|(key, value)| (key, ordered(value))).collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(ordered).collect()),
        other => other,
    }
}
fn positive(version: u64) -> Option<u64> {
    (version > 0).then_some(version)
}
fn missing() -> DomainError {
    DomainError::PreconditionFailed("所选政策的完整依赖缺失或失效；请重新核对".into())
}

#[cfg(test)]
mod tests;
