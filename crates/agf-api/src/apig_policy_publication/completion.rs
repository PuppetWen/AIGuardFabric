//! Owned completion stages known outcomes independently of actor/config changes after cloud delivery.
use super::{
    audit,
    authority::Submission,
    dependencies, operations,
    records::*,
    sql::key,
    store::{self, Decision, Mutation},
    util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    policy::Policy,
    time::Timestamp,
};
use agf_storage::configuration::{ConditionalMutation, ConfigurationGuard, MutationDecision};
use std::sync::Arc;

pub(super) fn preflight(state: &AppState, fact: &Fact) -> DomainResult<()> {
    let mut receipt = operations::receipt(fact)?.clone();
    receipt.status = Status::Uncertain;
    receipt.cloud_write = WriteStatus::Unknown;
    receipt.provider_request_id = None;
    receipt.readback = ReadStatus::Unavailable;
    receipt.finished_at = Some(Timestamp::now());
    receipt.safe_reason = Some("x".repeat(512));
    let pending = encoded(state, fact, &receipt)?;
    util::bound(&pending, 64 * 1024)?;
    Ok(())
}

pub(super) async fn pending(state: &AppState, fact: &Fact) -> DomainResult<Option<Completion>> {
    if operations::receipt(fact)?.local_publication == PublicationStatus::Published {
        return Ok(None);
    }
    state
        .configurations
        .get::<Pending>(fact.tenant, PENDING, record_id(fact.tenant, fact.request_id))
        .await?
        .map(|stored| decoded(state, fact, &stored))
        .transpose()
}

pub(super) async fn stage(state: &AppState, fact: &Fact, receipt: &Operation) -> DomainResult<()> {
    let encoded = encoded(state, fact, receipt)?;
    let id = record_id(fact.tenant, fact.request_id);
    let fact_key = util::fact_id(fact.tenant, fact.request_id);
    state
        .configurations
        .mutate_conditional_audited::<Option<Pending>, _, _>(
            fact.tenant,
            ConditionalMutation { kind: PENDING, id, guard: Some(ConfigurationGuard { kind: FACT, id: fact_key }) },
            |prior, stored| {
                let prior: Fact = prior.map(serde_json::from_value).transpose()?.ok_or_else(util::corrupt)?;
                matches(&prior, fact, receipt)?;
                if operations::receipt(&prior)?.local_publication == PublicationStatus::Published {
                    return Ok(MutationDecision::Unchanged);
                }
                if let Some(stored) = stored {
                    decoded(state, &prior, stored)?;
                    return Ok(MutationDecision::Unchanged);
                }
                *stored = Some(encoded);
                Ok(MutationDecision::Write(None))
            },
            |_| Err(DomainError::Internal("回执暂存不能提前成功审计".into())),
        )
        .await?;
    Ok(())
}

/// No provider, STS, credential resolution or cloud configuration is needed for explicit recovery.
pub(super) async fn publish(
    state: &AppState,
    submission: &Submission,
    fact: &Fact,
    automatic: Option<(&Prepared, &[Policy])>,
) -> DomainResult<Fact> {
    let completion =
        pending(state, fact).await?.ok_or_else(|| DomainError::PreconditionFailed("尚无可信本地待发布回执".into()))?;
    let selected = if let Some((prepared, source)) = automatic {
        Some(dependencies::prepare(state, &prepared.scope, &prepared.fence.policies, source).await?.0)
    } else {
        None
    };
    let risk_key = util::risk_id(fact.tenant, fact.scope.target.write_resource_id);
    let related = [
        key(FACT, util::fact_id(fact.tenant, fact.request_id)),
        key(PENDING, record_id(fact.tenant, fact.request_id)),
        key(STATE, risk_key),
    ];
    let (scope, fence, source) = automatic
        .map_or((None, None, &[][..]), |(prepared, source)| (Some(&prepared.scope), Some(&prepared.fence), source));
    store::mutate(
        state,
        Mutation { submission, scope, selection: selected.as_ref(), fence, source, related: &related },
        |main, snapshot| {
            let mut prior: Fact = util::read(&snapshot.related, FACT, util::fact_id(fact.tenant, fact.request_id))?
                .ok_or_else(util::corrupt)?;
            matches(&prior, fact, &completion.receipt)?;
            if operations::receipt(&prior)?.local_publication == PublicationStatus::Published {
                return Ok(Decision::Unchanged);
            }
            let stored: Pending = util::read(&snapshot.related, PENDING, record_id(fact.tenant, fact.request_id))?
                .ok_or_else(util::corrupt)?;
            let checked = decoded(state, &prior, &stored)?;
            let mut receipt = checked.receipt;
            receipt.local_publication = PublicationStatus::Published;
            let mut writes = Values::new();
            if receipt.cloud_write == WriteStatus::Unknown {
                let existing: Option<Risk> = util::read(&snapshot.related, STATE, risk_key)?;
                let marker = match existing {
                    Some(mut marker) => {
                        if (marker.tenant, marker.scope_id) != (fact.tenant, fact.scope.target.write_resource_id) {
                            return Err(util::corrupt());
                        }
                        marker.unknown_count = marker.unknown_count.checked_add(1).ok_or_else(util::capacity)?;
                        if receipt.lease_expires_at >= marker.lease_expires_at {
                            marker.latest_unknown = fact.request_id;
                            marker.lease_expires_at = receipt.lease_expires_at;
                        }
                        marker
                    }
                    None => Risk {
                        tenant: fact.tenant,
                        scope_id: fact.scope.target.write_resource_id,
                        latest_unknown: fact.request_id,
                        unknown_count: 1,
                        lease_expires_at: receipt.lease_expires_at,
                    },
                };
                util::put(&mut writes, STATE, risk_key, &marker)?;
            }
            let audit = audit::terminal(&prior, &receipt);
            prior.outcome = FactOutcome::Operation { receipt: Box::new(receipt) };
            util::put(&mut writes, FACT, util::fact_id(fact.tenant, fact.request_id), &prior)?;
            if main.active.as_ref().is_some_and(|active| active.request_id == fact.request_id) {
                main.active = None;
            }
            util::bump(main)?;
            Ok(Decision::Write { related: writes, audit: Box::new(audit) })
        },
    )
    .await?;
    let published = operations::load(state, fact.tenant, fact.request_id).await?.ok_or_else(util::corrupt)?;
    if let Err(error) = state.configurations.delete(fact.tenant, PENDING, record_id(fact.tenant, fact.request_id)).await
    {
        tracing::warn!(%error, "已提交的APIG终态暂存清理失败；永久领取和终态不删除");
    }
    Ok(published)
}

pub(super) async fn finish(
    state: AppState,
    submission: Arc<Submission>,
    fact: Fact,
    receipt: Operation,
    prepared: Prepared,
    source: Vec<Policy>,
) -> DomainResult<()> {
    tokio::spawn(async move {
        stage(&state, &fact, &receipt).await?;
        if let Err(error) = Box::pin(publish(&state, &submission, &fact, Some((&prepared, &source)))).await {
            tracing::warn!(%error, "APIG原调用结果已加密暂存；当前授权或来源改变，请显式恢复本地发布，不能重发");
        }
        Ok(())
    })
    .await
    .map_err(|_| DomainError::Internal("APIG本地回执完成任务中断；仅恢复本地记录，禁止重发".into()))?
}

fn encoded(state: &AppState, fact: &Fact, receipt: &Operation) -> DomainResult<Pending> {
    matches(fact, fact, receipt)?;
    validate_terminal(receipt)?;
    let mut receipt = receipt.clone();
    receipt.local_publication = PublicationStatus::PendingAudit;
    let text = serde_json::to_string(&Completion { receipt })?;
    let pending = Pending {
        tenant: fact.tenant,
        request_id: fact.request_id,
        request_hash: fact.request_hash.clone(),
        completion_hash: util::hash(text.as_bytes()),
        completion: util::encrypt_content(state, fact.tenant, record_id(fact.tenant, fact.request_id), &text)?,
    };
    util::bound(&pending, 64 * 1024)?;
    Ok(pending)
}
fn decoded(state: &AppState, fact: &Fact, pending: &Pending) -> DomainResult<Completion> {
    let same_owner = pending.tenant == fact.tenant;
    let same_request = pending.request_id == fact.request_id;
    let same_hash = pending.request_hash == fact.request_hash;
    if !same_owner || !same_request || !same_hash {
        return Err(util::corrupt());
    }
    let text = util::decrypt_content(
        state,
        fact.tenant,
        record_id(fact.tenant, fact.request_id),
        &pending.completion,
        &pending.completion_hash,
    )?;
    let completion: Completion = serde_json::from_str(&text)?;
    matches(fact, fact, &completion.receipt)?;
    validate_terminal(&completion.receipt)?;
    if completion.receipt.local_publication != PublicationStatus::PendingAudit {
        return Err(util::corrupt());
    }
    Ok(completion)
}
fn validate_terminal(receipt: &Operation) -> DomainResult<()> {
    let finished = receipt.finished_at.ok_or_else(util::corrupt)?;
    let valid_phase = match receipt.status {
        Status::Verified => receipt.cloud_write == WriteStatus::Accepted && receipt.readback == ReadStatus::Matched,
        Status::Conflict => receipt.cloud_write == WriteStatus::NotAttempted,
        Status::Failed => receipt.cloud_write == WriteStatus::NotAttempted,
        Status::Uncertain => matches!(receipt.cloud_write, WriteStatus::Accepted | WriteStatus::Unknown),
        Status::Started | Status::Superseded | Status::Archived => false,
    };
    if !valid_phase
        || (receipt.cloud_write == WriteStatus::Accepted) != receipt.provider_request_id.is_some()
        || receipt
            .provider_request_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 256 || id.trim() != id || id.chars().any(char::is_control))
        || receipt.original_status.is_some()
        || receipt.archived_at.is_some()
        || finished < receipt.started_at
        || finished > Timestamp::now().offset_secs(5)
        || receipt.safe_reason.as_ref().is_some_and(|reason| reason.len() > 512)
        || (receipt.readback == ReadStatus::Matched && receipt.cloud_write != WriteStatus::Accepted)
    {
        return Err(util::corrupt());
    }
    Ok(())
}
fn matches(prior: &Fact, original: &Fact, candidate: &Operation) -> DomainResult<()> {
    util::match_fact(prior, original.tenant, original.request_id, Purpose::Operation, &original.request_hash)?;
    let claimed = operations::receipt(prior)?;
    let same_claim = (claimed.request_id, claimed.preview_id, claimed.action, claimed.source_publication_id)
        == (candidate.request_id, candidate.preview_id, candidate.action, candidate.source_publication_id);
    let same_time = (claimed.submitted_at, claimed.started_at, claimed.lease_expires_at)
        == (candidate.submitted_at, candidate.started_at, candidate.lease_expires_at);
    if prior.scope != original.scope
        || !same_claim
        || !same_time
        || claimed.desired_hash != candidate.desired_hash
        || claimed.desired_bytes != candidate.desired_bytes
        || claimed.source_policy_versions != candidate.source_policy_versions
    {
        return Err(util::corrupt());
    }
    Ok(())
}
pub(super) fn record_id(tenant: TenantId, request: Id) -> Id {
    util::content_id(tenant, request, "pending")
}
