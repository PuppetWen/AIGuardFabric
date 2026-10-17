use super::*;

pub(super) fn identity(policy: &ModelRoutePolicy, tenant: TenantId, id: Id) -> DomainResult<()> {
    if id.is_nil() || policy.id != id || policy.tenant_id != tenant {
        return Err(corrupt());
    }
    Ok(())
}

pub(super) fn candidate(policy: &ModelRoutePolicy, tenant: TenantId, expected: u64) -> DomainResult<()> {
    identity(policy, tenant, policy.id)?;
    if expected.checked_add(1) != Some(policy.version) {
        return Err(DomainError::Conflict("模型路由版本无效，请重新加载".into()));
    }
    if policy.enabled
        && (policy.name.len() > 128
            || policy.fallback_endpoint_ids.len() > 32
            || !policy.budget_cny_per_day.is_finite()
            || !(0.0..=1_000_000.0).contains(&policy.budget_cny_per_day)
            || policy.weights.values().any(|v| !v.is_finite() || !(0.0..=1_000_000.0).contains(v)))
    {
        return Err(DomainError::Validation("模型路由名称、端点数量或金额权重超过有效范围".into()));
    }
    Ok(())
}

pub(super) fn keys(policy: &ModelRoutePolicy) -> DomainResult<Vec<(String, Id)>> {
    if !policy.enabled {
        return Ok(Vec::new());
    }
    let mut keys = Vec::new();
    for raw in std::iter::once(&policy.primary_endpoint_id).chain(&policy.fallback_endpoint_ids) {
        let id = Id::parse(raw).map_err(|_| DomainError::Validation("路由端点须为已配置的 UUID".into()))?;
        if id.is_nil() || id.to_string() != *raw {
            return Err(DomainError::Validation("路由端点须为已配置的规范 UUID".into()));
        }
        keys.push((crate::model_gateway::ENDPOINT_KIND.into(), id));
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

pub(super) fn references(policy: &ModelRoutePolicy, rows: &Rows) -> DomainResult<()> {
    let mut total = 0usize;
    for key in keys(policy)? {
        let value = rows
            .get(&key)
            .and_then(Option::as_ref)
            .ok_or_else(|| DomainError::Validation("路由端点尚未配置，请先在模型接入配置中添加".into()))?;
        let bytes = serde_json::to_vec(value)?.len();
        total = total.checked_add(bytes).ok_or_else(corrupt)?;
        if bytes > 1024 * 1024 || total > MAX_BATCH_BYTES {
            return Err(DomainError::PreconditionFailed("路由端点证据超过读取预算".into()));
        }
        let row: StoredEndpoint = serde_json::from_value(value.clone()).map_err(|_| corrupt())?;
        if row.endpoint.id != key.1 || row.endpoint.tenant_id != policy.tenant_id {
            return Err(corrupt());
        }
        // Preserve the existing rule: an enabled route may reference a configured disabled endpoint.
        // Runtime dispatch still applies endpoint eligibility; this save does not contact a provider.
    }
    Ok(())
}
