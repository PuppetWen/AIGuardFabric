use super::{
    binding, cloud,
    context::{self, Resolved},
    contract::{Active, Binding, Observation, ObserveInput, Operation, SyncInput},
    store,
};
use crate::{Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    time::Timestamp,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) async fn verified(
    state: &AppState,
    principal: &Principal,
    asset: Id,
    binding_version: u64,
    quota_version: u64,
    cloud_version: u64,
) -> DomainResult<(Binding, Resolved)> {
    let binding = binding::load(state, principal.tenant, asset).await?;
    let resolved = context::resolve(state, principal.tenant, asset, binding.quota_id).await?;
    if !context::current(&binding, &resolved)
        || binding.version != binding_version
        || resolved.quota.version != quota_version
        || resolved.cloud.cloud.version != cloud_version
    {
        return Err(super::stale());
    }
    Ok((binding, resolved))
}

pub(super) async fn observe(
    state: &AppState,
    principal: &Principal,
    asset: Id,
    input: ObserveInput,
) -> DomainResult<Value> {
    if input.request_id.is_nil() {
        return Err(super::stale());
    }
    let (before, resolved) = verified(
        state,
        principal,
        asset,
        input.expected_binding_version,
        input.expected_quota_version,
        input.configuration_version,
    )
    .await?;
    idle(&before)?;
    confirm(&resolved, input.confirm_live)?;
    let audit = store::audit(principal, asset, "开始只读核对云限制；旧差异预览不再可用", true);
    let commit = store::Commit { asset, expected: before.version, resolved: Some(&resolved), audit, operation: None };
    store::modify(state, principal, commit, |row| {
        idle(row)?;
        if row.used_previews.contains_key(&input.request_id) {
            return Err(super::stale());
        }
        row.observation_request_id = Some(input.request_id);
        row.observation = None;
        Ok(())
    })
    .await?;
    let (value, observed_at) =
        cloud::read(state, principal, &resolved, input.request_id, "observe", input.confirm_live).await?;
    if Timestamp::now().since_secs(&observed_at) > 300 {
        return Err(super::stale());
    }
    let observation = Observation {
        id: input.request_id,
        observed_at,
        quota_version: input.expected_quota_version,
        cloud_version: input.configuration_version,
        binding_version: input.expected_binding_version,
        mocked: resolved.cloud.snapshot.mocked,
        preview_usable: true,
        cloud: value,
    };
    let (_, current) = verified(
        state,
        principal,
        asset,
        input.expected_binding_version,
        input.expected_quota_version,
        input.configuration_version,
    )
    .await?;
    let audit = store::audit(principal, asset, "只读核对 Worker 云限制；尚未下发或证明云端配额执行", true);
    let commit = store::Commit { asset, expected: before.version, resolved: Some(&current), audit, operation: None };
    let saved = store::modify(state, principal, commit, |row| {
        idle(row)?;
        if row.used_previews.contains_key(&observation.id) {
            return Err(super::stale());
        }
        if row.observation_request_id != Some(observation.id) {
            return Err(super::stale());
        }
        row.observation_request_id = None;
        row.observation = Some(observation.clone());
        Ok(())
    })
    .await?;
    let quotas = crate::quota_definitions::list_versioned(state, principal.tenant).await?;
    Ok(json!({"binding":binding::dto(state,principal.tenant,&saved,&quotas).await?,
        "observation":binding::observation_dto(&observation)}))
}

pub(super) fn idle(binding: &Binding) -> DomainResult<()> {
    if binding.active.as_ref().is_some_and(|active| active.expires_at > Timestamp::now()) {
        return Err(DomainError::Conflict("该 Worker 正在同步；请等待回读或核对超时回执，禁止并行重试".into()));
    }
    Ok(())
}

fn confirm(resolved: &Resolved, live: bool) -> DomainResult<()> {
    if !resolved.cloud.snapshot.mocked && !live {
        return Err(DomainError::PreconditionFailed("请明确确认实际云调用；平台与云端为独立配额周期和计量".into()));
    }
    Ok(())
}

pub(super) async fn sync(state: &AppState, principal: &Principal, asset: Id, input: SyncInput) -> DomainResult<Value> {
    if input.request_id.is_nil() || input.preview_id.is_nil() {
        return Err(super::stale());
    }
    let id = deterministic_id("agf.worker-quota.run", &format!("{}:{asset}:{}", principal.tenant, input.request_id));
    let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&input)?));
    if let Some(prior) = state.configurations.get::<Operation>(principal.tenant, super::RUNS, id).await? {
        return cached(state, principal, asset, prior, &hash).await;
    }
    let (binding, resolved) = verified(
        state,
        principal,
        asset,
        input.expected_binding_version,
        input.expected_quota_version,
        input.configuration_version,
    )
    .await?;
    idle(&binding)?;
    confirm(&resolved, input.confirm_live)?;
    let confirmed_preview = preview(&binding, &resolved, &input)?;
    let mut run = Operation {
        id,
        request_id: input.request_id,
        request_hash: hash.clone(),
        status: "started".into(),
        started_at: Timestamp::now(),
        finished_at: None,
        mocked: resolved.cloud.snapshot.mocked,
        changed: false,
        error: None,
        observation: None,
    };
    let mut claimed = false;
    let prior = state
        .configurations
        .mutate::<Option<Operation>, _>(principal.tenant, super::RUNS, id, |row| {
            if let Some(prior) = row {
                if prior.request_hash != hash {
                    return Err(super::stale());
                }
            } else {
                *row = Some(run.clone());
                claimed = true;
            }
            Ok(())
        })
        .await?;
    if !claimed {
        return cached(state, principal, asset, prior.ok_or_else(super::stale)?, &hash).await;
    }
    let audit = store::audit(principal, asset, "开始显式 Worker 配额对账；仅领取操作，未声明云写入成功", true);
    let commit = store::Commit { asset, expected: binding.version, resolved: Some(&resolved), audit, operation: None };
    let claim = store::modify(state, principal, commit, |row| {
        idle(row)?;
        preview(row, &resolved, &input)?;
        row.used_previews.retain(|_, at| Timestamp::now().since_secs(at) <= 300);
        if row.used_previews.len() >= 1000 {
            return Err(DomainError::PreconditionFailed("该Worker近期操作过多，请稍后核对云状态".into()));
        }
        row.used_previews.insert(input.preview_id, Timestamp::now());
        row.observation.as_mut().ok_or_else(super::stale)?.preview_usable = false;
        row.last_operation = Some(id);
        row.active = Some(Active { run_id: id, expires_at: run.started_at.offset_secs(120) });
        Ok(())
    })
    .await;
    if let Err(error) = claim {
        run.status = "failed".into();
        run.error = Some(error.to_string());
        run.finished_at = Some(Timestamp::now());
        persist_run(state, principal, &mut run).await?;
        return Err(error);
    }
    let remaining = 110_i64.saturating_sub(Timestamp::now().since_secs(&run.started_at)).max(0) as u64;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(remaining),
        super::reconcile::execute(state, principal, &resolved, &input, &confirmed_preview, &mut run),
    )
    .await;
    if result.is_err() {
        run.status = "uncertain".into();
        run.error = Some("整个同步超过执行期限；远端可能已收到更新，请重新观察，不重放本次写入".into());
    }
    finish(state, principal, asset, &input, &mut run).await?;
    reply(state, principal, asset, &run).await
}

fn preview(binding: &Binding, resolved: &Resolved, input: &SyncInput) -> DomainResult<Observation> {
    let preview = binding.observation.as_ref().ok_or_else(super::stale)?;
    if !preview.preview_usable
        || binding.used_previews.contains_key(&preview.id)
        || preview.id != input.preview_id
        || preview.binding_version != binding.version
        || preview.quota_version != resolved.quota.version
        || preview.cloud_version != resolved.cloud.cloud.version
        || Timestamp::now().since_secs(&preview.observed_at) > 300
        || preview.mocked != resolved.cloud.snapshot.mocked
    {
        return Err(DomainError::Conflict("云差异预览已使用、过期或版本已改变；请重新读取后显式确认".into()));
    }
    if preview.cloud.limit_type != "token" || preview.cloud.period_type != "day" {
        return Err(DomainError::PreconditionFailed(
            "本期只同步单 Worker 的正整数 token/day 限制；其它周期请在云端核对".into(),
        ));
    }
    Ok(preview.clone())
}

async fn cached(state: &AppState, principal: &Principal, asset: Id, run: Operation, hash: &str) -> DomainResult<Value> {
    if run.request_hash != hash {
        return Err(DomainError::Conflict("同一同步编号不能用于不同参数".into()));
    }
    if run.finished_at.is_none() {
        return Err(DomainError::Conflict("该请求曾在执行中或被中断；请核对云状态并重新观察，不得重放写操作".into()));
    }
    reply(state, principal, asset, &run).await
}

async fn finish(
    state: &AppState,
    principal: &Principal,
    asset: Id,
    input: &SyncInput,
    run: &mut Operation,
) -> DomainResult<()> {
    run.finished_at = Some(Timestamp::now());
    let checked = verified(
        state,
        principal,
        asset,
        input.expected_binding_version,
        input.expected_quota_version,
        input.configuration_version,
    )
    .await;
    let resolved = match checked {
        Ok((_, resolved)) => resolved,
        Err(error) => {
            run.status = super::reconcile::classification(&error).into();
            run.error = Some("操作期间无法确认绑定、资源或平台规则；云端结果须重新核对".into());
            persist_run(state, principal, run).await?;
            return Ok(());
        }
    };
    let success = run.status == "verified";
    let audit = store::audit(
        principal,
        asset,
        if success {
            "Worker 云限制已回读核对；平台与云计量仍独立"
        } else {
            "Worker 配额同步未确认；须重新观察，禁止自动重放"
        },
        success,
    );
    let commit = store::Commit {
        asset,
        expected: input.expected_binding_version,
        resolved: Some(&resolved),
        audit,
        operation: Some(run),
    };
    let result = store::modify(state, principal, commit, |row| {
        if row.active.as_ref().is_none_or(|active| active.run_id != run.id) {
            return Err(super::stale());
        }
        row.active = None;
        if success {
            row.observation.clone_from(&run.observation);
        }
        Ok(())
    })
    .await;
    if let Err(error) = result {
        run.status = if matches!(
            error,
            DomainError::Conflict(_) | DomainError::PreconditionFailed(_) | DomainError::Forbidden(_)
        ) {
            "superseded"
        } else {
            "uncertain"
        }
        .into();
        run.error = Some("结果发布未完成或版本已变；请核对回执并重新观察，不自动重放云写入".into());
        persist_run(state, principal, run).await?;
    }
    Ok(())
}

async fn persist_run(state: &AppState, principal: &Principal, run: &mut Operation) -> DomainResult<()> {
    let saved = state
        .configurations
        .mutate::<Option<Operation>, _>(principal.tenant, super::RUNS, run.id, |row| {
            if let Some(prior) = row {
                if prior.request_hash != run.request_hash {
                    return Err(super::stale());
                }
                if prior.finished_at.is_some() {
                    return Ok(());
                }
            }
            *row = Some(run.clone());
            Ok(())
        })
        .await?;
    *run = saved.ok_or_else(super::stale)?;
    Ok(())
}

async fn reply(state: &AppState, principal: &Principal, asset: Id, run: &Operation) -> DomainResult<Value> {
    let row = binding::load(state, principal.tenant, asset).await?;
    let quotas = crate::quota_definitions::list_versioned(state, principal.tenant).await?;
    Ok(
        json!({"binding":binding::dto(state,principal.tenant,&row,&quotas).await?,"operation":binding::operation_dto(run)}),
    )
}
