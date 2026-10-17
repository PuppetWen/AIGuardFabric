//! Recovery publishes original encrypted facts locally. It never resolves cloud credentials or sends requests.
use super::{
    authority::Submission,
    completion, context,
    input::ObserveInput,
    observation, operations,
    records::{PublicationStatus, ReadStatus, Status, WriteStatus},
    util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use std::sync::Arc;

pub(super) async fn local(state: &AppState, submission: Arc<Submission>, id: Id) -> DomainResult<super::records::Fact> {
    submission.authorize(state).await?;
    let fact = operations::load(state, submission.principal.tenant, id)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "mse-publication-operation", id: id.to_string() })?;
    let receipt = operations::receipt(&fact)?;
    if receipt.local_publication == PublicationStatus::Published {
        return Ok(fact);
    }
    let owned = state.clone();
    tokio::spawn(async move {
        if completion::pending(&owned, &fact).await?.is_none() {
            let prior = operations::receipt(&fact)?;
            if prior.status != Status::Started || prior.lease_expires_at > Timestamp::now() {
                return Err(DomainError::PreconditionFailed(
                    "没有可信待恢复回执，且领取尚未过期；不允许轮询或重发云写入".into(),
                ));
            }
            let mut unknown = prior.clone();
            unknown.status = Status::Uncertain;
            unknown.cloud_write = WriteStatus::Unknown;
            unknown.readback = ReadStatus::Unavailable;
            unknown.finished_at = Some(Timestamp::now());
            unknown.safe_reason =
                Some("过期started缺少可信结果，已纯本地固定为Unknown；当前内容不能证明原写送达，旧请求可能迟到".into());
            completion::stage(&owned, &fact, &unknown).await?;
        }
        Box::pin(completion::publish(&owned, &submission, &fact, None)).await
    })
    .await
    .map_err(|_| DomainError::Internal("纯本地回执恢复任务中断；禁止重发远端请求".into()))?
}

/// Return a new read observation. Original write phases/status remain untouched.
pub(super) async fn observe(
    state: &AppState,
    submission: Arc<Submission>,
    id: Id,
    input: ObserveInput,
) -> DomainResult<super::records::Observation> {
    input.validate()?;
    submission.authorize(state).await?;
    let fact = operations::load(state, submission.principal.tenant, id)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "mse-publication-operation", id: id.to_string() })?;
    let current = context::current(state, submission.principal.tenant, Some(input.configuration_version)).await?;
    if current.target.target_scope_id != fact.scope.target.target_scope_id {
        return Err(util::stale());
    }
    context::confirm(&current, input.confirm_live)?;
    Box::pin(observation::observe_original(state, submission, input, Some(id))).await
}
