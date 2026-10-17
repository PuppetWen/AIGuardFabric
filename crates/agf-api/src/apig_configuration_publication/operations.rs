//! Request replay reads the permanent fact. Only an unclaimed, current preview can dispatch.
use super::{
    authority::Submission,
    claim, content, context, dispatch,
    input::ApplyInput,
    preview,
    records::{DETAIL, Detail, DetailRecord, FACT, Fact, FactOutcome, Purpose, Status},
    util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use std::sync::Arc;

pub(super) async fn apply(state: &AppState, submission: Arc<Submission>, input: ApplyInput) -> DomainResult<Fact> {
    let request = input.request_id;
    let result =
        tokio::time::timeout_at(submission.deadline, Box::pin(apply_inner(state, submission.clone(), input))).await;
    match result {
        Ok(result) => result,
        Err(_) => load(state, submission.principal.tenant, request)
            .await?
            .ok_or_else(|| DomainError::Timeout("总预算在领取前结束；没有云派发，请明确重新读取".into())),
    }
}

async fn apply_inner(state: &AppState, submission: Arc<Submission>, input: ApplyInput) -> DomainResult<Fact> {
    input.validate()?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let hash = util::request_hash(&input)?;
    if let Some(fact) = state.configurations.get::<Fact>(tenant, FACT, util::fact_id(tenant, input.request_id)).await? {
        util::match_fact(&fact, tenant, input.request_id, Purpose::Operation, &hash)?;
        receipt(&fact)?;
        return Ok(fact);
    }
    let prepared = preview::load(state, tenant, input.preview_id).await?.ok_or_else(util::stale)?;
    let current = context::current(state, tenant, Some(prepared.scope.target.configuration_version)).await?;
    if current != prepared.scope {
        return Err(util::stale());
    }
    context::confirm(&current, input.confirm_live)?;
    let content = preview::validate_content(state, tenant, &prepared)?;
    let (fact, fresh) = Box::pin(claim::claim(state, &submission, &input, &hash, &prepared, &content)).await?;
    if fresh {
        Box::pin(dispatch::run(state.clone(), submission, fact.clone(), prepared, content)).await?;
    }
    load(state, tenant, input.request_id).await?.ok_or_else(util::corrupt)
}

pub(super) async fn load(state: &AppState, tenant: TenantId, request: Id) -> DomainResult<Option<Fact>> {
    let fact = state.configurations.get::<Fact>(tenant, FACT, util::fact_id(tenant, request)).await?;
    if let Some(fact) = &fact {
        if fact.tenant != tenant || fact.request_id != request || fact.scope.tenant != tenant {
            return Err(util::corrupt());
        }
        if fact.purpose != Purpose::Operation {
            return Err(DomainError::NotFound { entity: "apig-configuration-operation", id: request.to_string() });
        }
        let FactOutcome::Operation { receipt } = &fact.outcome else {
            return Err(util::corrupt());
        };
        if receipt.request_id != request || receipt.preview_id.is_nil() {
            return Err(util::corrupt());
        }
    }
    Ok(fact)
}

pub(super) async fn detail(state: &AppState, tenant: TenantId, request: Id) -> DomainResult<Option<Detail>> {
    let detail = match detail_record(state, tenant, request).await? {
        Some(DetailRecord::Content { data }) => Some(*data),
        Some(DetailRecord::Archived { .. }) | None => None,
    };
    if let Some(detail) = &detail {
        if (detail.tenant, detail.request_id) != (tenant, request) {
            return Err(util::corrupt());
        }
        preview::validate_content(state, tenant, &detail.prepared)?;
    }
    Ok(detail)
}

pub(super) async fn detail_record(
    state: &AppState,
    tenant: TenantId,
    request: Id,
) -> DomainResult<Option<DetailRecord>> {
    let row = state.configurations.get::<DetailRecord>(tenant, DETAIL, record_id(tenant, request)).await?;
    if let Some(DetailRecord::Archived { marker }) = &row {
        if (marker.tenant, marker.request_id) != (tenant, request)
            || marker.archived_at > agf_core::time::Timestamp::now().offset_secs(5)
            || matches!(marker.original_status, Status::Started | Status::Archived)
        {
            return Err(util::corrupt());
        }
    }
    Ok(row)
}

pub(super) async fn history_content(
    state: &AppState,
    tenant: TenantId,
    request: Id,
    scope: &super::contract::Scope,
) -> DomainResult<content::Content> {
    let fact = load(state, tenant, request).await?.ok_or_else(util::stale)?;
    let FactOutcome::Operation { receipt } = fact.outcome else {
        return Err(util::corrupt());
    };
    if fact.scope.target.target_scope_id != scope.target.target_scope_id
        || receipt.status != Status::Verified
        || receipt.local_publication != super::records::PublicationStatus::Published
        || receipt.archived_at.is_some()
    {
        return Err(DomainError::PreconditionFailed(
            "回滚仅恢复同来源目标的已验证历史公开配置，保留新观察中的私密内容及其他环境".into(),
        ));
    }
    let detail = detail(state, tenant, request)
        .await?
        .ok_or_else(|| DomainError::PreconditionFailed("此历史正文已明确归档，不再可回滚".into()))?;
    preview::validate_content(state, tenant, &detail.prepared)
}

pub(super) fn record_id(tenant: TenantId, request: Id) -> Id {
    util::content_id(tenant, request, "operation")
}
pub(super) fn receipt(fact: &Fact) -> DomainResult<&super::records::Operation> {
    let FactOutcome::Operation { receipt } = &fact.outcome else {
        return Err(util::corrupt());
    };
    Ok(receipt)
}
pub(super) fn receipt_mut(fact: &mut Fact) -> DomainResult<&mut super::records::Operation> {
    let FactOutcome::Operation { receipt } = &mut fact.outcome else {
        return Err(util::corrupt());
    };
    Ok(receipt)
}
