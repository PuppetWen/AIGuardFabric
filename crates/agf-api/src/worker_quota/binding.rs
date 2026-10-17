use super::{
    context,
    contract::{BindInput, Binding, Observation, Operation},
    store,
};
use crate::{Principal, quota_definitions::VersionedQuota, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde_json::{Value, json};

pub(super) async fn load(state: &AppState, tenant: TenantId, asset: Id) -> DomainResult<Binding> {
    state.configurations.get(tenant, super::KIND, asset).await?.ok_or_else(super::stale)
}

pub(super) async fn list(state: &AppState, principal: &Principal) -> DomainResult<Value> {
    let tenant = principal.tenant;
    let inventory = match context::inventory(state, tenant).await {
        Ok(value) => value,
        Err(DomainError::Conflict(_)) => None,
        Err(error) => return Err(error),
    };
    let cloud_version =
        crate::cloud_store::load(state, tenant, crate::cloud_inventory::NAME).await?.map_or(0, |cloud| cloud.version);
    let quotas = crate::quota_definitions::list_versioned(state, tenant).await?;
    let bindings: Vec<Binding> = state.configurations.list(tenant, super::KIND).await?;
    let workers: Vec<_> = inventory
        .as_ref()
        .into_iter()
        .flat_map(|ctx| &ctx.snapshot.assets)
        .map(|(name, asset)| json!({"assetId":asset,"name":name}))
        .collect();
    let rules: Vec<_> = quotas
        .iter()
        .map(|row| {
            json!({"id":row.quota.id,"name":row.quota.name,
        "version":row.version,"targetId":row.quota.target_id,"scope":row.quota.scope.as_str(),
        "dimension":row.quota.dimension.as_str(),"window":row.quota.window.as_str(),
        "limit":row.quota.limit,"enabled":row.quota.enabled,"onExceed":row.quota.on_exceed.as_str()})
        })
        .collect();
    let mut items = Vec::new();
    for row in bindings {
        items.push(dto(state, tenant, &row, &quotas).await?);
    }
    Ok(json!({"inventoryAvailable":inventory.is_some(),"cloudVersion":cloud_version,
        "mocked":inventory.as_ref().map(|ctx|ctx.snapshot.mocked),"workers":workers,"quotas":rules,"items":items,
        "canWrite":principal.require(state,"alicloud","write").is_ok() && principal.require(state,"quotas","write").is_ok()}))
}

pub(super) async fn save(state: &AppState, principal: &Principal, asset: Id, input: BindInput) -> DomainResult<Value> {
    if asset.is_nil() || input.quota_id.is_nil() {
        return Err(super::stale());
    }
    let resolved = if input.enabled {
        let row = context::resolve(state, principal.tenant, asset, input.quota_id).await?;
        if row.quota.version != input.quota_version {
            return Err(super::stale());
        }
        Some(row)
    } else {
        None
    };
    let audit = store::audit(
        principal,
        asset,
        if input.enabled {
            "绑定已盘点 Worker 与平台专属 Token 每日拒绝规则；云配额尚未核对"
        } else {
            "停用 Worker 云配额同步绑定；平台配额规则仍独立执行"
        },
        true,
    );
    let commit =
        store::Commit { asset, expected: input.expected_version, resolved: resolved.as_ref(), audit, operation: None };
    let row = store::modify(state, principal, commit, |row| {
        let version = input.expected_version.checked_add(1).ok_or_else(super::stale)?;
        if let Some(resolved) = &resolved {
            *row = Binding {
                version,
                asset_id: asset,
                worker_name: resolved.worker.clone(),
                scope_id: resolved.cloud.scope_id,
                cloud_id: resolved.cloud.cloud.id,
                cloud_version: resolved.cloud.cloud.version,
                mocked: resolved.cloud.snapshot.mocked,
                quota_id: input.quota_id,
                enabled: true,
                bound_at: Timestamp::now(),
                drift: row.drift.clone(),
                ..Binding::default()
            };
        } else {
            if row.version == 0 || row.asset_id != asset {
                return Err(super::stale());
            }
            row.version = version;
            row.enabled = false;
            row.active = None;
            if let Some(observation) = &mut row.observation {
                observation.preview_usable = false;
            }
        }
        Ok(())
    })
    .await?;
    let quotas = crate::quota_definitions::list_versioned(state, principal.tenant).await?;
    dto(state, principal.tenant, &row, &quotas).await
}

pub(super) async fn dto(
    state: &AppState,
    tenant: TenantId,
    row: &Binding,
    quotas: &[VersionedQuota],
) -> DomainResult<Value> {
    let quota = quotas.iter().find(|quota| quota.quota.id == row.quota_id);
    let resolved = match context::resolve(state, tenant, row.asset_id, row.quota_id).await {
        Ok(resolved) => Some(resolved),
        Err(
            DomainError::Conflict(_)
            | DomainError::PreconditionFailed(_)
            | DomainError::NotFound { .. }
            | DomainError::Forbidden(_),
        ) => None,
        Err(error) => return Err(error),
    };
    let valid = resolved.as_ref().is_some_and(|resolved| context::current(row, resolved));
    let operation = if let Some(id) = row.last_operation {
        state.configurations.get::<Operation>(tenant, super::RUNS, id).await?
    } else {
        None
    };
    let now = Timestamp::now();
    let busy = row.active.as_ref().is_some_and(|active| active.expires_at > now);
    let fresh = row.observation.as_ref().filter(|observation| {
        let same_binding_revision = observation.binding_version == row.version;
        valid
            && (observation.preview_usable
                || operation.as_ref().is_some_and(|run| {
                    run.status == "verified"
                        && run.observation.as_ref().is_some_and(|readback| readback.id == observation.id)
                }))
            && same_binding_revision
            && observation.cloud_version == row.cloud_version
            && quota.is_some_and(|quota| quota.version == observation.quota_version)
            && now.since_secs(&observation.observed_at) <= 300
    });
    let state_name = if !row.enabled {
        "disabled"
    } else if !valid {
        "stale"
    } else if let Some(observation) = fresh {
        if observation.cloud.limit_type == "token"
            && observation.cloud.period_type == "day"
            && quota.is_some_and(|quota| quota.quota.limit == observation.cloud.usage_limit)
        {
            "in-sync"
        } else {
            "drift"
        }
    } else {
        "unverified"
    };
    Ok(json!({"assetId":row.asset_id,"workerName":row.worker_name,"version":row.version,
        "quotaId":row.quota_id,"quotaVersion":quota.map(|quota|quota.version),"quotaName":quota.map(|quota|&quota.quota.name),
        "platformLimit":quota.map(|quota|quota.quota.limit),"cloudVersion":row.cloud_version,"scopeId":row.scope_id,
        "enabled":row.enabled,"mocked":row.mocked,"state":state_name,"boundAt":row.bound_at,
        "busy":busy,"canObserve":valid && !busy,"leaseExpiresAt":row.active.as_ref().map(|active|active.expires_at),
        "observation":row.observation.as_ref().map(observation_dto),"lastOperation":operation.as_ref().map(operation_dto),
        "driftAlertId":row.drift.as_ref().map(|drift|drift.alert_id)}))
}

pub(super) fn observation_dto(row: &Observation) -> Value {
    json!({"id":row.id,"observedAt":row.observed_at,"quotaVersion":row.quota_version,
        "cloudVersion":row.cloud_version,"bindingVersion":row.binding_version,"mocked":row.mocked,
        "previewUsable":row.preview_usable,"usageLimit":row.cloud.usage_limit,"limitType":row.cloud.limit_type,
        "periodType":row.cloud.period_type,"ruleStatus":row.cloud.rule_status,"usedAmount":row.cloud.used_amount,
        "overLimit":row.cloud.over_limit})
}

pub(super) fn operation_dto(row: &Operation) -> Value {
    let expired = row.finished_at.is_none() && Timestamp::now().since_secs(&row.started_at) >= 120;
    json!({"id":row.id,"requestId":row.request_id,"status":if expired {"uncertain"} else {&row.status},
        "startedAt":row.started_at,"finishedAt":row.finished_at,"mocked":row.mocked,"changed":row.changed,"error":row.error})
}
