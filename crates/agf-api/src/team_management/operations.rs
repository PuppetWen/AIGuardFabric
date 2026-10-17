//! Consume one preview once; disconnected callers recover its durable operation by request ID.
use super::{
    cloud, context,
    contract::{Active, CloudWrite, InventoryPublish, Operation, Readback, SafeError},
    input::{ApplyInput, Change},
    observe, projection, publication, store, validation,
    write_guard::Guard,
};
use crate::{Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    time::Timestamp,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};

pub(super) async fn get(state: &AppState, principal: &Principal, id: Id) -> DomainResult<Value> {
    let op = store::operation(state, principal.tenant, id).await?;
    let row = store::get(state, principal.tenant, op.record_id).await?;
    let ctx = context::available(state, principal.tenant).await?;
    Ok(projection::operation(&op, &row, ctx.as_ref().map(|ctx| &ctx.scope)))
}
pub(super) async fn apply(state: &AppState, principal: &Principal, input: ApplyInput) -> DomainResult<Value> {
    if !input.confirm_apply || input.request_id.is_nil() {
        return Err(DomainError::PreconditionFailed("请明确确认预览并提供新的请求编号".into()));
    }
    let hash = validation::hash(&input)?;
    let id = deterministic_id("agf.team-management.operation", &format!("{}:{}", principal.tenant, input.request_id));
    match store::operation(state, principal.tenant, id).await {
        Ok(prior) => {
            if prior.request_hash != hash {
                return Err(DomainError::Conflict("同一请求编号不能用于不同确认".into()));
            }
            return get(state, principal, id).await;
        }
        Err(DomainError::NotFound { .. }) => {}
        Err(error) => return Err(error),
    }
    let preview = store::preview(state, principal.tenant, input.preview_id).await?;
    context::confirm(&preview.scope, input.confirm_live)?;
    let ctx = match context::checked(state, principal, &preview.scope, input.confirm_live).await {
        Ok(ctx) => ctx,
        Err(DomainError::Conflict(_) | DomainError::PreconditionFailed(_)) => return Err(super::stale()),
        Err(error) => return Err(error),
    };
    if input.configuration_version != ctx.scope.configuration_version
        || ctx.scope.inventory_at != preview.scope.inventory_at
        || input.expected_state_version != preview.state_version
        || preview.expires_at <= Timestamp::now()
    {
        return Err(super::stale());
    }
    let now = Timestamp::now();
    let op = Operation {
        id,
        record_id: preview.record_id,
        resource_version: preview.state_version.checked_add(1).ok_or_else(super::stale)?,
        request_id: input.request_id,
        request_hash: hash,
        preview_id: preview.id,
        scope: preview.scope.clone(),
        change: preview.change.clone(),
        status: "started".into(),
        started_at: now,
        finished_at: None,
        lease_expires_at: now.offset_secs(120),
        cloud_write: CloudWrite {
            status: "not_started".into(),
            receipt_id: None,
            provider_request_id: None,
            provider_code: None,
            http_status: None,
        },
        readback: Readback {
            status: "pending".into(),
            observed_at: None,
            resource_state: "unknown".into(),
            matched_fields: Vec::new(),
            conflict_fields: Vec::new(),
        },
        inventory_publish: InventoryPublish { status: "not_started".into(), checked_at: None, error_code: None },
        safe_error: None,
        recovery_request: None,
        recoveries: BTreeMap::new(),
    };
    let actor_state = state.clone();
    let actor_principal = principal.clone();
    // Claim and execution share one detached actor, including the commit/return cancellation window.
    tokio::spawn(async move {
        let state = &actor_state;
        let principal = &actor_principal;
        let mut op = op;
        let mut claimed = false;
        store::modify(
            state,
            principal,
            &ctx.scope,
            preview.change.team(),
            "确认团队变更：一次性预览、操作回执和租约原子领取",
            |row| {
                if let Some(prior) = row.operations.get(&id) {
                    if prior.request_hash != op.request_hash {
                        return Err(super::stale());
                    }
                    return Ok(());
                }
                store::idle(row)?;
                if row.version != preview.state_version || row.unresolved_delete.is_some() {
                    return Err(super::stale());
                }
                let current = row
                    .previews
                    .get_mut(&preview.id)
                    .filter(|preview| preview.consumed_at.is_none() && preview.expires_at > Timestamp::now())
                    .ok_or_else(super::stale)?;
                current.consumed_at = Some(now);
                op.lease_expires_at = Timestamp::now().offset_secs(120);
                row.version = op.resource_version;
                row.scope = Some(ctx.scope.clone());
                row.desired = Some(preview.change.clone());
                row.active = Some(Active {
                    run: id,
                    claim: input.request_id,
                    authorized_at: op.started_at,
                    expires_at: op.lease_expires_at,
                });
                if matches!(preview.change, Change::Delete { .. }) {
                    row.unresolved_delete = Some(id);
                }
                row.operations.insert(id, op.clone());
                claimed = true;
                Ok(())
            },
        )
        .await?;
        if claimed {
            let flow = execute(state, principal, &preview, &op, input.confirm_live);
            match tokio::time::timeout(Duration::from_secs(110), flow).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => finish_error(state, principal, &op, input.request_id, error).await?,
                Err(_) => {
                    finish_error(
                        state,
                        principal,
                        &op,
                        input.request_id,
                        DomainError::Timeout("操作期限届满，云结果需重新观察".into()),
                    )
                    .await?;
                }
            }
        }
        Ok::<(), DomainError>(())
    })
    .await
    .map_err(|_| DomainError::Internal("团队操作执行任务中断，请恢复回执".into()))??;
    get(state, principal, id).await
}
async fn execute(
    state: &AppState,
    principal: &Principal,
    preview: &super::contract::Preview,
    op: &Operation,
    live: bool,
) -> DomainResult<()> {
    let guard = Guard { state, principal, preview, run: op.id, live };
    crate::cloud_runtime::WritePrecondition::validate(&guard).await?;
    store::modify(state, principal, &op.scope, op.change.team(), "准备发送已确认团队变更", |row| {
        store::owns(row, op.id, op.request_id)?;
        row.operations.get_mut(&op.id).ok_or_else(super::stale)?.cloud_write.status = "attempting".into();
        Ok(())
    })
    .await?;
    let result = cloud::write(
        state,
        principal,
        &op.scope,
        op.id,
        op.change.cloud_action(),
        parameters(&op.change, op.id),
        live,
        &guard,
    )
    .await?;
    let status = result["status"].as_str().unwrap_or("uncertain");
    let succeeded = status == "succeeded";
    store::modify(
        state,
        principal,
        &op.scope,
        op.change.team(),
        "记录云端团队变更接收结果；接收不等于完成",
        |row| {
            store::owns(row, op.id, op.request_id)?;
            let current = row.operations.get_mut(&op.id).ok_or_else(super::stale)?;
            current.cloud_write.status = if succeeded {
                "accepted"
            } else if status == "failed" {
                "rejected"
            } else {
                "unknown"
            }
            .into();
            current.cloud_write.receipt_id = serde_json::from_value(result["id"].clone()).ok();
            current.cloud_write.provider_request_id = result["receipt"]["response"]["RequestId"]
                .as_str()
                .filter(|id| id.len() <= 256 && !id.chars().any(char::is_control))
                .map(str::to_owned);
            if !succeeded {
                current.status = if status == "failed" { "failed" } else { "uncertain" }.into();
                current.finished_at = Some(Timestamp::now());
                current.safe_error = Some(SafeError {
                    code: if status == "failed" { "cloud-rejected" } else { "cloud-result-unknown" }.into(),
                    message: "云端未确认变更完成，请查看回执并重新观察；不会自动重发".into(),
                });
                row.active = None;
                if status == "failed" && row.unresolved_delete == Some(op.id) {
                    row.unresolved_delete = None;
                }
            }
            Ok(())
        },
    )
    .await?;
    if !succeeded {
        return Ok(());
    }
    observe::readback(state, principal, op, &op.scope, op.request_id, live).await?;
    let saved = store::operation(state, principal.tenant, op.id).await?;
    if matches!(saved.readback.status.as_str(), "matched" | "absent") {
        publication::run(state, principal, &saved, &op.scope, op.request_id, live).await?;
    } else {
        store::modify(state, principal, &op.scope, op.change.team(), "异步变更仍待云端观察", |row| {
            store::owns(row, op.id, op.request_id)?;
            row.active = None;
            Ok(())
        })
        .await?;
    }
    Ok(())
}
pub(super) fn parameters(change: &Change, run: Id) -> Value {
    let mut params = json!({"Name":change.team()});
    if !matches!(change, Change::Delete { .. }) {
        params["ClientToken"] = json!(run.to_string());
    }
    if let Some(description) = change.description() {
        params["Description"] = json!(description);
    }
    if let Some(names) = change.members() {
        params["TeamMembers"] = json!(names.iter().map(|name| json!({"Name":name})).collect::<Vec<_>>());
    }
    if let Some(admin) = change.admin() {
        params["AdminName"] = json!(admin);
    }
    params
}
pub(super) async fn finish_error(
    state: &AppState,
    principal: &Principal,
    op: &Operation,
    claim: Id,
    error: DomainError,
) -> DomainResult<()> {
    let ctx = context::load(state, principal.tenant).await?;
    if !context::same_target(&ctx.scope, &op.scope) {
        return Err(super::stale());
    }
    store::modify(
        state,
        principal,
        &ctx.scope,
        op.change.team(),
        "操作未完成；保留回执和未知删除状态，禁止重发",
        |row| {
            if row.active.as_ref().is_none_or(|lease| lease.run != op.id || lease.claim != claim) {
                return Ok(());
            }
            let current = row.operations.get_mut(&op.id).ok_or_else(super::stale)?;
            let attempted = current.cloud_write.status != "not_started";
            current.status = if attempted { "uncertain" } else { "failed" }.into();
            current.finished_at = Some(Timestamp::now());
            if current.cloud_write.status == "attempting" {
                current.cloud_write.status = "unknown".into();
            }
            if current.inventory_publish.status == "not_started"
                && matches!(current.readback.status.as_str(), "matched" | "absent")
            {
                current.inventory_publish.status = "failed".into();
                current.inventory_publish.error_code = Some(error.code().into());
            }
            current.safe_error = Some(SafeError {
                code: error.code().into(),
                message: "操作未完成。请刷新回执，重新观察云端状态或只重试台账发布；不会自动重发云写入".into(),
            });
            row.active = None;
            if !attempted && row.unresolved_delete == Some(op.id) {
                row.unresolved_delete = None;
            }
            Ok(())
        },
    )
    .await?;
    Ok(())
}
