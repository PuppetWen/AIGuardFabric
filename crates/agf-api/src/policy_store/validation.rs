//! Dependency identities are checked against current tenant-owned configuration and live assets.
use super::*;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, PolicyAction},
};
use agf_storage::configuration::ConfigurationGuard;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) type GuardValues = BTreeMap<(String, Id), Option<Value>>;

pub(super) fn guards(policy: Option<&Policy>, tenant: TenantId) -> Vec<ConfigurationGuard<'static>> {
    let Some(policy) = policy else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    if policy.quota_id.is_some() {
        keys.push(ConfigurationGuard {
            kind: crate::quota_definitions::KIND,
            id: crate::model_routes::tenant_record_id(tenant),
        });
    }
    if let Some(id) = policy.degrade_endpoint_id {
        keys.push(ConfigurationGuard { kind: crate::model_gateway::ENDPOINT_KIND, id });
    }
    keys.sort_by_key(|key| (key.kind, key.id));
    keys
}

pub(super) fn candidate(policy: &Policy, tenant: TenantId) -> DomainResult<()> {
    if policy.tenant_id != tenant || policy.id.is_nil() {
        return Err(DomainError::TenantViolation { tenant: tenant.to_string(), resource: "policy".into() });
    }
    if policy.name.trim().is_empty()
        || policy.name.len() > 128
        || policy.name.chars().any(char::is_control)
        || policy.source.len() > 65536
    {
        return Err(DomainError::Validation("策略名称不能为空、含控制字符或超过128字节；源码不能超过64KiB".into()));
    }
    if policy.scope_agent_ids.len() > 2000
        || policy.scope_agent_ids.iter().any(Id::is_nil)
        || policy.scope_agent_ids.iter().copied().collect::<BTreeSet<_>>().len() != policy.scope_agent_ids.len()
    {
        return Err(DomainError::Validation("策略Agent范围最多2000个唯一非空UUID".into()));
    }
    if policy.quota_id.is_some_and(|id| id.is_nil()) || policy.degrade_endpoint_id.is_some_and(|id| id.is_nil()) {
        return Err(DomainError::Validation("关联配额和降级端点不能使用空UUID".into()));
    }
    if policy.action == PolicyAction::Degrade && policy.degrade_endpoint_id.is_none() {
        return Err(DomainError::Validation("降级策略必须选择目标模型端点".into()));
    }
    RuntimeEngine::in_memory(vec![policy.clone()], Vec::new(), EngineConfig::default())?;
    Ok(())
}

pub(super) async fn preflight(state: &AppState, tenant: TenantId, policy: Option<&Policy>) -> DomainResult<()> {
    let Some(policy) = policy else {
        return Ok(());
    };
    candidate(policy, tenant)?;
    if let Some(id) = policy.quota_id {
        if !crate::quota_definitions::contains(state, tenant, id).await? {
            return Err(unavailable("配额"));
        }
    }
    let mut values = GuardValues::new();
    for key in guards(Some(policy), tenant) {
        values.insert((key.kind.into(), key.id), state.configurations.get::<Value>(tenant, key.kind, key.id).await?);
    }
    dependencies(policy, tenant, &values)?;
    for id in &policy.scope_agent_ids {
        agent(tenant, *id, state.store.asset_get_durable(tenant, *id).await?.as_ref())?;
    }
    Ok(())
}

pub(super) fn dependencies(policy: &Policy, tenant: TenantId, values: &GuardValues) -> DomainResult<()> {
    if let Some(id) = policy.quota_id {
        let key = (crate::quota_definitions::KIND.to_owned(), crate::model_routes::tenant_record_id(tenant));
        let payload = values.get(&key).and_then(Option::as_ref).cloned().ok_or_else(|| unavailable("配额"))?;
        let row =
            crate::quota_definitions::parse_versioned_registry(payload, id)?.ok_or_else(|| unavailable("配额"))?;
        if (row.quota.tenant_id, row.quota.id) != (tenant, id) || !row.quota.enabled {
            return Err(unavailable("配额"));
        }
    }
    if let Some(id) = policy.degrade_endpoint_id {
        let key = (crate::model_gateway::ENDPOINT_KIND.to_owned(), id);
        let payload = values.get(&key).and_then(Option::as_ref).cloned().ok_or_else(|| unavailable("降级模型端点"))?;
        let row: crate::model_gateway::StoredEndpoint = serde_json::from_value(payload)?;
        if (row.endpoint.tenant_id, row.endpoint.id) != (tenant, id) || !row.endpoint.enabled {
            return Err(unavailable("降级模型端点"));
        }
    }
    Ok(())
}

pub(super) fn agent(tenant: TenantId, id: Id, value: Option<&Asset>) -> DomainResult<()> {
    if !value.is_some_and(|asset| {
        (asset.tenant_id, asset.id) == (tenant, id) && asset.kind == AssetKind::Agent && asset.is_live()
    }) {
        return Err(unavailable("Agent资产"));
    }
    Ok(())
}
fn unavailable(name: &str) -> DomainError {
    DomainError::Validation(format!("关联{name}不存在、未启用、已归档或不属于当前租户；当前策略保持不变"))
}
