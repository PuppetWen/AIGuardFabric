//! 持久化选路策略：显式路由 ID，或 auto 使用首条已启用策略。
use crate::{
    model_gateway::{ENDPOINT_KIND, StoredEndpoint},
    state::AppState,
    store::ModelRoutePolicy,
};
use agf_aigw::{gateway::CallContext, router::RoutingStrategy};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};

pub const KIND: &str = "model-route-policy";

pub(crate) mod publication;

pub async fn list(state: &AppState, tenant: TenantId) -> DomainResult<Vec<ModelRoutePolicy>> {
    let mut rows = state.store.route_policy_list(tenant)?;
    for stored in state.configurations.list::<ModelRoutePolicy>(tenant, KIND).await? {
        rows.retain(|row| row.id != stored.id);
        rows.push(stored);
    }
    Ok(rows)
}

pub async fn resolve(
    state: &AppState,
    tenant: TenantId,
    model: &mut String,
    context: &mut CallContext,
) -> DomainResult<Option<ModelRoutePolicy>> {
    let rows = state.configurations.list::<ModelRoutePolicy>(tenant, KIND).await?;
    let policy = if model.is_empty() {
        rows.into_iter().find(|row| row.enabled)
    } else {
        rows.into_iter().find(|row| row.id.to_string() == *model)
    };
    if let Some(policy) = &policy {
        if !policy.enabled {
            return Err(DomainError::Config("选路策略已停用".into()));
        }
        model.clear();
        context.strategy = match policy.strategy.as_str() {
            "cost-first" => RoutingStrategy::CostFirst,
            _ => RoutingStrategy::LatencyFirst,
        };
    }
    Ok(policy)
}

pub async fn validate(state: &AppState, tenant: TenantId, policy: &ModelRoutePolicy) -> DomainResult<()> {
    if policy.tenant_id != tenant || policy.name.len() > 128 || policy.fallback_endpoint_ids.len() > 32 {
        return Err(DomainError::Validation("策略租户、名称或端点数量不合法".into()));
    }
    let endpoints: Vec<StoredEndpoint> = state.configurations.list(tenant, ENDPOINT_KIND).await?;
    for id in std::iter::once(&policy.primary_endpoint_id).chain(&policy.fallback_endpoint_ids) {
        if !endpoints.iter().any(|record| record.endpoint.id.to_string() == *id) {
            return Err(DomainError::Validation(format!("端点 {id} 尚未配置，请先在模型接入配置中添加")));
        }
    }
    if !policy.budget_cny_per_day.is_finite() || policy.budget_cny_per_day > 1_000_000.0 {
        return Err(DomainError::Validation("预算超过有效范围".into()));
    }
    if policy.weights.values().any(|weight| !weight.is_finite() || *weight < 0.0 || *weight > 1_000_000.0) {
        return Err(DomainError::Validation("端点权重必须为 0–1000000".into()));
    }
    Ok(())
}

pub async fn apply(
    state: &AppState,
    tenant: TenantId,
    records: &mut Vec<StoredEndpoint>,
    policy: &ModelRoutePolicy,
) -> DomainResult<()> {
    let mut ids = vec![policy.primary_endpoint_id.clone()];
    for id in &policy.fallback_endpoint_ids {
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    if policy.strategy == "weighted" {
        let next = state
            .configurations
            .mutate::<u64, _>(tenant, "route-sequence", policy.id, |n| {
                *n = n.wrapping_add(1);
                Ok(())
            })
            .await?;
        let weights: Vec<f64> = ids.iter().map(|id| policy.weights.get(id).copied().unwrap_or(1.0)).collect();
        let total: f64 = weights.iter().sum();
        if total <= 0.0 {
            return Err(DomainError::Config("至少一个端点权重应大于 0".into()));
        }
        // 对 UUID 哈希取均匀分布，独立请求按权重分摊；零权重不作为主端点。
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(format!("{}:{next}", policy.id));
        let number = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        let mut cursor = f64::from(number) / (f64::from(u32::MAX) + 1.0) * total;
        let mut chosen = 0;
        for (index, weight) in weights.iter().enumerate() {
            if cursor < *weight {
                chosen = index;
                break;
            }
            cursor -= weight;
        }
        let first = ids.remove(chosen);
        ids.insert(0, first);
    }
    records.retain(|row| ids.contains(&row.endpoint.id.to_string()));
    for record in records {
        record.endpoint.priority =
            u32::try_from(ids.iter().position(|id| *id == record.endpoint.id.to_string()).unwrap_or(ids.len()))
                .unwrap_or(u32::MAX);
    }
    Ok(())
}

pub fn tenant_record_id(tenant: TenantId) -> Id {
    Id::from_uuid(tenant.as_uuid())
}
