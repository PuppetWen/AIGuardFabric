use super::super::{authority::Submission, util};
use super::{
    codec,
    model::{Known, Operation, State, Uncertain},
    mutation,
};
use crate::state::AppState;
use agf_alicloud::schedulerx3::managed_jobs::{Readback, WriteEvidence, WriteStatus};
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};

pub(super) async fn recover(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Operation> {
    submission.authorize(state).await?;
    let row = super::views::load_operation(state, submission.principal.tenant, id).await?;
    if row.state == State::Complete {
        return Ok(row);
    }
    if super::staging::read(state, &row).await?.is_none() {
        if row.expires_at > Timestamp::now() {
            return Err(DomainError::PreconditionFailed("原领取尚未过期，且没有封存结果；不能恢复或重发".into()));
        }
        super::staging::persist(
            state,
            &row,
            WriteEvidence {
                attempted: true,
                status: WriteStatus::Unknown,
                provider_request_id: None,
                authority_current: false,
                original_deadline_current: false,
            },
            Readback::Unknown,
        )
        .await?;
    }
    finish(state, submission, &row).await
}
pub(super) async fn finish(state: &AppState, submission: &Submission, original: &Operation) -> DomainResult<Operation> {
    let tenant = original.tenant;
    let id = original.request_id;
    let operation_key = codec::key(tenant, id, super::model::OPERATION);
    let pending_key = codec::key(tenant, id, super::model::PENDING);
    mutation::apply(
        state,
        mutation::options(submission, None, vec![operation_key.clone(), pending_key.clone()]),
        |values| {
            let mut row: Operation =
                codec::snapshot(state, tenant, values, &operation_key)?.ok_or_else(util::corrupt)?;
            codec::operation(&row, tenant, id)?;
            if row.claim_id != original.claim_id || row.input_hash != original.input_hash {
                return Err(super::conflict());
            }
            if row.state == State::Complete {
                return Ok((row, None));
            }
            let known: Known = codec::snapshot(state, tenant, values, &pending_key)?.ok_or_else(util::corrupt)?;
            codec::known(&known, &row)?;
            let mut journal = mutation::journal(state, tenant, values)?;
            if journal.active.as_ref().is_none_or(|active| (active.request_id, active.claim_id) != (id, row.claim_id)) {
                return Err(util::corrupt());
            }
            let old = row.detail_bytes;
            row.state = State::Complete;
            row.finished_at = Some(Timestamp::now());
            row.write = Some(known.write);
            row.readback = known.readback;
            row.job_id = known.job_id;
            journal.active = None;
            if row.write.as_ref().is_some_and(|write| write.status == WriteStatus::Unknown) {
                journal.unknown.retain(|item| item.resource != super::model::RiskIdentity::of(&row.target));
                journal.unknown.push(Uncertain {
                    resource: super::model::RiskIdentity::of(&row.target),
                    request_id: id,
                    scope_id: row.target.scope_id,
                    expires_at: row.expires_at,
                });
            }
            let mut writes = super::super::records::Values::new();
            mutation::operation(state, &mut writes, &mut row)?;
            mutation::account(&mut journal, old, row.detail_bytes)?;
            writes.insert(pending_key, None);
            codec::operation(&row, tenant, id)?;
            let outcome = if row.write.as_ref().is_some_and(|write| write.status == WriteStatus::Accepted) {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            };
            let plan = mutation::finish(
                state,
                submission,
                &mut journal,
                writes,
                id,
                AuditAction::Execute,
                outcome,
                "纯本地结束原单次修改与唯一审计；未知不会升级为成功，没有再次调用 provider",
            )?;
            Ok((row, Some(plan)))
        },
    )
    .await
}
