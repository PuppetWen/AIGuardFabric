//! Offline PrivateLink publication uses ConfigStore -> ApiStore lock order, with no await or reverse call.
use super::*;

/// Only PrivateLink observation attributes and observation times are platform-owned here.
pub(crate) fn merge_observation(existing: Option<Asset>, observed: &Asset) -> DomainResult<Asset> {
    let Some(mut current) = existing else {
        return Ok(observed.clone());
    };
    let same_tenant = current.tenant_id == observed.tenant_id;
    let same_identity = current.id == observed.id && current.fingerprint == observed.fingerprint;
    if !same_tenant || !same_identity || current.deleted_at.is_some() {
        return Err(DomainError::Conflict(
            "PrivateLink 指纹对应的资产已删除或使用其他主键；请核对资产后重新盘点".into(),
        ));
    }
    for (key, value) in &observed.attributes {
        if !key.starts_with("privatelink_") {
            return Err(DomainError::Validation("PrivateLink 盘点只能更新来源观察字段".into()));
        }
        current.attributes.insert(key.clone(), value.clone());
    }
    if observed.attributes.get("privatelink_observed").and_then(serde_json::Value::as_bool) == Some(true) {
        current.last_seen_at = observed.last_seen_at;
    }
    current.updated_at = observed.updated_at;
    Ok(current)
}

impl ApiStore {
    /// Called synchronously under the offline configuration mutex. Prepare all candidates
    /// and seal the audit before changing any asset, then only infallible inserts remain.
    pub(crate) fn publish_privatelink_discovery_offline(
        &self,
        observations: &[Asset],
        mut audit: AuditLog,
    ) -> DomainResult<AuditLog> {
        if self.database.is_some() {
            return Err(DomainError::PreconditionFailed("PrivateLink 离线发布不能用于数据库模式".into()));
        }
        let mut memory = self.lock()?;
        let mut candidates = BTreeMap::new();
        for observed in observations {
            if observed.tenant_id != audit.tenant_id {
                return Err(DomainError::TenantViolation {
                    tenant: audit.tenant_id.to_string(),
                    resource: observed.id.to_string(),
                });
            }
            let mut matching = memory
                .assets
                .values()
                .filter(|asset| asset.tenant_id == audit.tenant_id && asset.fingerprint == observed.fingerprint);
            let existing = matching.next().cloned();
            if matching.next().is_some() {
                return Err(DomainError::Conflict("PrivateLink 来源指纹对应多个资产；请先核对台账".into()));
            }
            if observed.attributes.get("privatelink_observed").and_then(serde_json::Value::as_bool) == Some(false)
                && existing.is_none()
            {
                continue;
            }
            if existing.is_none()
                && memory.changes.iter().any(|change| {
                    (change.tenant_id, change.asset_id) == (audit.tenant_id, observed.id)
                        && change.change_kind == agf_core::asset::ChangeKind::Removed
                })
            {
                return Err(DomainError::Conflict(
                    "PrivateLink 资产已由用户删除；请先显式恢复，整批原台账保持不变".into(),
                ));
            }
            if memory
                .assets
                .get(&(audit.tenant_id, observed.id))
                .is_some_and(|asset| asset.fingerprint != observed.fingerprint)
            {
                return Err(DomainError::Conflict("PrivateLink 资产编号对应其他指纹".into()));
            }
            let merged = merge_observation(existing, observed)?;
            if candidates.insert(merged.id, merged).is_some() {
                return Err(DomainError::Conflict("PrivateLink 发布批次包含重复资产".into()));
            }
        }
        let last = memory.audits.get(&audit.tenant_id).and_then(|chain| chain.last());
        audit.sequence = last
            .map_or(Some(1), |entry| entry.sequence.checked_add(1))
            .ok_or_else(|| DomainError::PreconditionFailed("审计序列达到上限".into()))?;
        audit.prev_hash = last.map_or_else(|| GENESIS_HASH.into(), |entry| entry.entry_hash.clone());
        audit.entry_hash.clear();
        audit.seal();
        if !audit.verify() {
            return Err(DomainError::Crypto("PrivateLink 审计候选无法校验".into()));
        }
        for asset in candidates.into_values() {
            memory.assets.insert((asset.tenant_id, asset.id), asset);
        }
        memory.audits.entry(audit.tenant_id).or_default().push(audit.clone());
        Ok(audit)
    }
}
