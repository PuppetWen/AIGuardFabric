//! 配额定义与计数同样持久化，重启后保持规则 ID，避免因 ID 变化重置用量。
use crate::{model_routes::tenant_record_id, state::AppState};
use agf_core::{
    audit::AuditLog,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    quota::Quota,
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub(crate) const KIND: &str = "quota-definitions";
#[derive(Debug, Default, Serialize, Deserialize)]
struct Registry {
    initialized: bool,
    entries: BTreeMap<String, Quota>,
    /// Existing definitions without this field begin at version zero.
    #[serde(default)]
    versions: BTreeMap<String, u64>,
}

/// Read the locked registry without initialization or another configuration transaction.
pub(crate) fn parse_locked(payload: Option<serde_json::Value>, tenant: TenantId) -> DomainResult<Vec<Quota>> {
    let registry: Registry = payload.map(serde_json::from_value).transpose()?.unwrap_or_default();
    if registry.entries.len() > 100
        || registry.entries.values().any(|quota| quota.tenant_id != tenant || quota.id.is_nil())
    {
        return Err(DomainError::PreconditionFailed("Atomic gateway quota registry exceeds its trusted bound".into()));
    }
    Ok(registry.entries.into_values().collect())
}

/// API view: keep the existing quota fields and add a per-definition version.
#[derive(Debug, Clone, Serialize)]
pub struct VersionedQuota {
    #[serde(flatten)]
    pub quota: Quota,
    pub version: u64,
}

/// Inspect a locked registry payload when another configuration depends on a quota revision.
pub(crate) fn parse_versioned_registry(payload: serde_json::Value, id: Id) -> DomainResult<Option<VersionedQuota>> {
    let rows: Registry = serde_json::from_value(payload)?;
    Ok(rows.entries.into_values().find(|quota| quota.id == id).map(|quota| {
        let version = rows.versions.get(&quota.name).copied().unwrap_or(0);
        VersionedQuota { quota, version }
    }))
}

async fn registry(state: &AppState, tenant: TenantId) -> DomainResult<Registry> {
    if let Some(rows) = state.configurations.get::<Registry>(tenant, KIND, tenant_record_id(tenant)).await? {
        return Ok(rows);
    }
    let original = state.store.quota_list(tenant)?;
    let rows = state
        .configurations
        .mutate::<Registry, _>(tenant, KIND, tenant_record_id(tenant), |registry| {
            if !registry.initialized {
                registry.entries = original.into_iter().map(|row| (row.name.clone(), row)).collect();
                registry.initialized = true;
            }
            Ok(())
        })
        .await?;
    Ok(rows)
}

pub async fn list(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Quota>> {
    Ok(registry(state, tenant).await?.entries.into_values().collect())
}

pub async fn list_versioned(state: &AppState, tenant: TenantId) -> DomainResult<Vec<VersionedQuota>> {
    let rows = registry(state, tenant).await?;
    Ok(rows
        .entries
        .into_values()
        .map(|quota| {
            let version = rows.versions.get(&quota.name).copied().unwrap_or(0);
            VersionedQuota { quota, version }
        })
        .collect())
}

/// Internal seed/init callers remain unconditional; their writes also advance the version.
pub async fn save(state: &AppState, tenant: TenantId, quota: Quota) -> DomainResult<Quota> {
    Ok(save_inner(state, tenant, quota, None, None).await?.quota)
}

/// Conditional API updates commit their success audit in the same database transaction.
pub async fn save_audited(
    state: &AppState,
    tenant: TenantId,
    quota: Quota,
    expected_version: Option<u64>,
    audit: AuditLog,
) -> DomainResult<VersionedQuota> {
    save_inner(state, tenant, quota, expected_version, Some(audit)).await
}

async fn save_inner(
    state: &AppState,
    tenant: TenantId,
    mut quota: Quota,
    expected_version: Option<u64>,
    audit: Option<AuditLog>,
) -> DomainResult<VersionedQuota> {
    // Initialize inside this mutation, so a failed first audited save creates no configuration.
    let original = state.store.quota_list(tenant)?;
    let name = quota.name.clone();
    let apply = |registry: &mut Registry| {
        if !registry.initialized {
            registry.entries = original.into_iter().map(|row| (row.name.clone(), row)).collect();
            registry.initialized = true;
        }
        let previous = registry.entries.get(&name);
        let version = registry.versions.get(&name).copied().unwrap_or(0);
        if audit.is_some() {
            let expected = match (previous, expected_version) {
                (Some(_), None) => {
                    return Err(DomainError::Validation("编辑配额须提供 expected_version，请先重新读取配置".into()));
                }
                (None, None) => 0,
                (_, Some(value)) => value,
            };
            if expected != version {
                return Err(DomainError::Conflict("配额已被其他人修改，请重新读取后合并变更".into()));
            }
        }
        let next = version.checked_add(1).ok_or_else(|| DomainError::Conflict("配额版本已达上限".into()))?;
        if let Some(existing) = previous {
            quota.id = existing.id;
            quota.created_at = existing.created_at;
        } else {
            quota.id = deterministic_id("agf.quota", &format!("{tenant}:{name}"));
        }
        quota.tenant_id = tenant;
        quota.updated_at = Timestamp::now();
        registry.entries.insert(name.clone(), quota);
        registry.versions.insert(name.clone(), next);
        Ok(())
    };
    let key = tenant_record_id(tenant);
    let (rows, sealed) = if let Some(entry) = audit.as_ref() {
        state.configurations.mutate_audited(tenant, KIND, key, entry.clone(), apply).await?
    } else {
        (state.configurations.mutate(tenant, KIND, key, apply).await?, None)
    };
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的配额审计内存投影刷新失败");
        }
    } else if let Some(entry) = audit {
        state.store.audit_append_durable(entry).await?;
    }
    let quota = rows.entries.get(&name).cloned().ok_or_else(|| DomainError::Internal("配额未保存".into()))?;
    let version = rows.versions.get(&name).copied().unwrap_or(0);
    let saved = VersionedQuota { quota, version };
    if let Err(error) = state.store.quota_upsert(tenant, saved.quota.clone()) {
        tracing::warn!(%error, "已提交的配额内存投影刷新失败");
    }
    Ok(saved)
}

pub async fn contains(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<bool> {
    let payload = match state.configurations.get::<serde_json::Value>(tenant, KIND, tenant_record_id(tenant)).await? {
        Some(value) => value,
        None => serde_json::to_value(registry(state, tenant).await?)?,
    };
    Ok(parse_versioned_registry(payload, id)?.is_some_and(|row| row.quota.enabled))
}
