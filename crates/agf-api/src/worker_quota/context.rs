use super::contract::{Binding, CloudLimit};
use crate::{agentteams_audit::binding::Context, quota_definitions::VersionedQuota, state::AppState};
use agf_core::{
    enums::{AssetKind, PolicyAction, QuotaDimension, QuotaScope},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    quota::QuotaWindow,
};
use serde_json::Value;

#[derive(Debug, Clone)]
pub(super) struct Resolved {
    pub cloud: Context,
    pub worker: String,
    pub asset: Id,
    pub quota: VersionedQuota,
}

pub(super) fn supported(quota: &VersionedQuota, asset: Id) -> bool {
    let rule = &quota.quota;
    rule.enabled
        && rule.scope == QuotaScope::Agent
        && rule.target_id == Some(asset)
        && rule.dimension == QuotaDimension::Tokens
        && rule.window == QuotaWindow::Day
        && rule.on_exceed == PolicyAction::Deny
        && rule.limit > 0
}

pub(super) async fn inventory(state: &AppState, tenant: TenantId) -> DomainResult<Option<Context>> {
    let context = crate::agentteams_audit::binding::context(state, tenant).await?;
    if context.as_ref().is_some_and(|context| context.snapshot.mocked != (state.config.mock_mode || context.cloud.mock))
    {
        return Err(super::stale());
    }
    Ok(context)
}

pub(super) async fn resolve(state: &AppState, tenant: TenantId, asset: Id, quota: Id) -> DomainResult<Resolved> {
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Err(DomainError::Forbidden("租户已停用".into()));
    }
    let cloud = inventory(state, tenant).await?.ok_or_else(super::stale)?;
    let worker = cloud.snapshot.assets.iter().find(|(_, id)| **id == asset).map(|(name, _)| name.clone());
    let worker = worker.ok_or_else(super::stale)?;
    if worker.is_empty() || worker.len() > 512 || worker.chars().any(char::is_control) {
        return Err(super::stale());
    }
    if state
        .store
        .asset_get_durable(tenant, asset)
        .await?
        .is_none_or(|row| row.kind != AssetKind::Agent || !row.is_live())
    {
        return Err(super::stale());
    }
    let quota = crate::quota_definitions::list_versioned(state, tenant)
        .await?
        .into_iter()
        .find(|row| row.quota.id == quota && supported(row, asset))
        .ok_or_else(|| {
            DomainError::PreconditionFailed("请选择该 Worker 专属、已启用的 Agent/Token/每日/拒绝配额".into())
        })?;
    Ok(Resolved { cloud, worker, asset, quota })
}

pub(super) fn current(binding: &Binding, resolved: &Resolved) -> bool {
    binding.enabled
        && binding.asset_id == resolved.asset
        && binding.worker_name == resolved.worker
        && binding.scope_id == resolved.cloud.scope_id
        && binding.cloud_id == resolved.cloud.cloud.id
        && binding.cloud_version == resolved.cloud.cloud.version
        && binding.mocked == resolved.cloud.snapshot.mocked
        && binding.quota_id == resolved.quota.quota.id
}

pub(super) fn limit(body: &Value, resolved: &Resolved) -> DomainResult<CloudLimit> {
    let data = &body["Data"];
    if data["Name"] != resolved.worker || data["InstanceId"] != resolved.cloud.snapshot.instance_id {
        return Err(DomainError::Parse("云 Worker 响应身份与已绑定实例不符".into()));
    }
    let config = &data["LimitConfig"];
    let missing =
        || DomainError::PreconditionFailed("云 Worker 尚未返回完整限制；请先在云端配置 Token/每日限制".into());
    Ok(CloudLimit {
        usage_limit: config["UsageLimit"].as_i64().filter(|value| *value > 0).ok_or_else(missing)?,
        limit_type: config["LimitType"].as_str().filter(|value| value.len() <= 32).ok_or_else(missing)?.into(),
        period_type: config["PeriodType"].as_str().filter(|value| value.len() <= 32).ok_or_else(missing)?.into(),
        rule_status: config["RuleStatus"].as_str().filter(|value| value.len() <= 32).map(str::to_owned),
        used_amount: config["UsedAmount"].as_u64(),
        over_limit: config["OverLimit"].as_bool(),
    })
}

pub(super) fn same_config(left: &CloudLimit, right: &CloudLimit) -> bool {
    left.usage_limit == right.usage_limit
        && left.limit_type == right.limit_type
        && left.period_type == right.period_type
}
