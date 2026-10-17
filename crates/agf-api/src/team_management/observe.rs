//! Recovery reads or publishes only; it never resends the original cloud write.
use super::{
    cloud, context,
    contract::{Active, Operation, Scope},
    input::{Change, RecoveryInput},
    operations, publication, store, validation,
};
use crate::{Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use serde_json::Value;
use std::time::Duration;

pub(super) async fn recover(
    state: &AppState,
    principal: &Principal,
    id: Id,
    input: RecoveryInput,
    publish: bool,
) -> DomainResult<Value> {
    if input.request_id.is_nil() {
        return Err(DomainError::Validation("恢复请求编号不能为nil".into()));
    }
    let op = store::operation(state, principal.tenant, id).await?;
    let ctx = context::load(state, principal.tenant).await?;
    if ctx.scope.configuration_version != input.configuration_version || !context::same_target(&ctx.scope, &op.scope) {
        return Err(super::stale());
    }
    context::confirm(&ctx.scope, input.confirm_live)?;
    let hash = validation::hash(&(id, publish, &input))?;
    let authorized_at = Timestamp::now();
    let mut claimed = false;
    store::modify(
        state,
        principal,
        &ctx.scope,
        op.change.team(),
        if publish { "领取只重试台账发布" } else { "领取只读云端恢复观察" },
        |row| {
            let current = row.operations.get(&id).ok_or_else(super::stale)?;
            if let Some(prior) = current.recoveries.get(&input.request_id) {
                if prior != &hash {
                    return Err(super::stale());
                }
                return Ok(());
            }
            store::idle(row)?;
            if row.version != op.resource_version {
                return Err(DomainError::Conflict("该回执已被较新的团队操作替代，只能读取历史回执".into()));
            }
            if current.recoveries.len() >= 100 {
                return Err(DomainError::PreconditionFailed("恢复回执已达100条上限；已有回执保持可读".into()));
            }
            if publish && !matches!(current.readback.status.as_str(), "matched" | "absent") {
                return Err(DomainError::PreconditionFailed("先重新观察并确认云端结果，再只重试台账发布".into()));
            }
            if publish && current.inventory_publish.status == "published" {
                return Ok(());
            }
            let expires = Timestamp::now().offset_secs(120);
            let current = row.operations.get_mut(&id).ok_or_else(super::stale)?;
            current.recoveries.insert(input.request_id, hash.clone());
            current.recovery_request = Some(input.request_id);
            current.lease_expires_at = expires;
            row.active = Some(Active { run: id, claim: input.request_id, authorized_at, expires_at: expires });
            claimed = true;
            Ok(())
        },
    )
    .await?;
    if claimed {
        let state = state.clone();
        let principal = principal.clone();
        tokio::spawn(async move {
            let flow = async {
                if publish {
                    publication::run(&state, &principal, &op, &ctx.scope, input.request_id, input.confirm_live)
                        .await
                        .map(|_| ())
                } else {
                    readback(&state, &principal, &op, &ctx.scope, input.request_id, input.confirm_live).await?;
                    store::modify(
                        &state,
                        &principal,
                        &ctx.scope,
                        op.change.team(),
                        "只读恢复观察完成；未重发云变更",
                        |row| {
                            store::owns(row, id, input.request_id)?;
                            row.active = None;
                            Ok(())
                        },
                    )
                    .await?;
                    Ok(())
                }
            };
            let result = tokio::time::timeout(Duration::from_secs(110), flow).await;
            let error = match result {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error),
                Err(_) => Some(DomainError::Timeout("恢复观察超时".into())),
            };
            if let Some(error) = error {
                let _ = operations::finish_error(&state, &principal, &op, input.request_id, error).await;
            }
        })
        .await
        .map_err(|_| DomainError::Internal("恢复执行任务中断，请刷新回执".into()))?;
    }
    operations::get(state, principal, id).await
}
pub(super) async fn readback(
    state: &AppState,
    principal: &Principal,
    op: &Operation,
    scope: &Scope,
    claim: Id,
    live: bool,
) -> DomainResult<()> {
    context::checked(state, principal, scope, live).await?;
    let row = store::get(state, principal.tenant, op.record_id).await?;
    store::owns(&row, op.id, claim)?;
    let authorized_at = row.active.as_ref().ok_or_else(super::stale)?.authorized_at;
    context::authority(state, principal, false, authorized_at).await?;
    let observed = cloud::team(state, principal, scope, claim, "readback-team", op.change.team(), live).await?;
    context::checked(state, principal, scope, live).await?;
    context::authority(state, principal, false, authorized_at).await?;
    let matched = validation::matches(&op.change, observed.as_ref());
    let deleting = matches!(op.change, Change::Delete { .. })
        && observed
            .as_ref()
            .is_some_and(|team| team.status.as_deref().is_some_and(|status| status.eq_ignore_ascii_case("deleting")));
    store::modify(
        state,
        principal,
        scope,
        op.change.team(),
        "记录团队云端只读核验；完整台账发布单独确认",
        |row| {
            store::owns(row, op.id, claim)?;
            let current = row.operations.get_mut(&op.id).ok_or_else(super::stale)?;
            current.readback.status = if matched {
                if observed.is_none() { "absent" } else { "matched" }
            } else if deleting {
                "deleting"
            } else {
                "mismatch"
            }
            .into();
            current.readback.resource_state = if observed.is_some() { "present" } else { "absent" }.into();
            current.readback.observed_at = Some(Timestamp::now());
            current.readback.matched_fields = if matched { fields(&op.change) } else { Vec::new() };
            current.readback.conflict_fields = if !matched && !deleting { fields(&op.change) } else { Vec::new() };
            current.status = if deleting {
                "deleting"
            } else if matched && current.inventory_publish.status == "published" {
                "verified"
            } else {
                "uncertain"
            }
            .into();
            current.safe_error = None;
            row.observed = observed.clone();
            // Only structured absence (or a definite original rejection) releases pending deletion.
            if matched && matches!(op.change, Change::Delete { .. }) && row.unresolved_delete == Some(op.id) {
                row.unresolved_delete = None;
            }
            Ok(())
        },
    )
    .await?;
    Ok(())
}
fn fields(change: &Change) -> Vec<String> {
    if matches!(change, Change::Delete { .. }) {
        return vec!["resourceAbsent".into()];
    }
    let mut fields = vec!["name".into()];
    if change.description().is_some() {
        fields.push("description".into());
    }
    if change.members().is_some() {
        fields.push("memberNames".into());
    }
    if change.admin().is_some() {
        fields.push("adminName".into());
    }
    fields
}
