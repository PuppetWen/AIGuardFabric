use super::super::{
    authority::Submission,
    binding, eligibility, proof,
    records::{BindingRecord, Values},
    safe::SafeSnapshot,
    util,
};
use super::{
    codec, current,
    model::{Operation, State},
    mutation,
};
use crate::state::AppState;
use agf_alicloud::schedulerx3::native_observation::CurrentGuard;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};

pub(super) async fn observe(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Operation> {
    submission.authorize(state).await?;
    let row = super::views::load_operation(state, submission.principal.tenant, id).await?;
    if row.state != State::Complete || row.archived_at.is_some() {
        return Err(DomainError::PreconditionFailed("先本地结束原领取；已归档正文不能再作原差异比较".into()));
    }
    let guard = current::ReadGuard { state, submission, row: &row };
    guard.validate().await?;
    let target = &row.target;
    let data = if target.mocked {
        super::mock::load(state, target).await?
    } else {
        let native = target.native();
        let data = Box::pin(crate::cloud_runtime::execute_scheduler_observation(
            state,
            crate::cloud_runtime::SchedulerObservationInvocation {
                tenant: row.tenant,
                configuration_version: target.configuration_version,
                payload_fingerprint: &target.fingerprint,
                scope: &native,
                guard: &guard,
                deadline: submission.deadline,
            },
        ))
        .await?;
        SafeSnapshot::parse(target, serde_json::to_value(data)?)?
    };
    guard.validate().await?;
    let key = codec::key(row.tenant, id, super::model::OPERATION);
    let binding_key = util::binding_key(row.tenant);
    mutation::apply(
        state,
        mutation::options(submission, Some(target), vec![key.clone(), binding_key.clone()]),
        |values| {
            let mut current: Operation = codec::snapshot(state, row.tenant, values, &key)?.ok_or_else(util::corrupt)?;
            codec::operation(&current, row.tenant, id)?;
            if current.state != State::Complete
                || current.archived_at.is_some()
                || current.claim_id != row.claim_id
                || current.input_hash != row.input_hash
            {
                return Err(util::stale());
            }
            let mut journal = mutation::journal(state, row.tenant, values)?;
            let mut bindings: BindingRecord = util::read(values, &binding_key)?.unwrap_or_default();
            binding::validate(&bindings, row.tenant)?;
            proof::restore(state, &bindings, row.tenant)?;
            let refresh = bindings.adoption_version > 0 && bindings.target.as_ref() == Some(target);
            let mut writes = Values::new();
            if refresh {
                eligibility::refresh(&mut bindings, &data, target, id, Timestamp::now())?;
                proof::seal_qualification(state, &mut bindings, row.tenant)?;
                binding::validate(&bindings, row.tenant)?;
                util::put(&mut writes, binding_key, &bindings)?;
            }
            let old = current.detail_bytes;
            current.readback = super::plan::readback(current.preview.as_deref().ok_or_else(util::corrupt)?, &data);
            current.readback_at = Some(Timestamp::now());
            current.readback_fingerprint = Some(data.fingerprint().into());
            // Current matches do not change the immutable Accepted/Rejected/Unknown write evidence.
            mutation::operation(state, &mut writes, &mut current)?;
            mutation::account(&mut journal, old, current.detail_bytes)?;
            let plan = mutation::finish(
                state,
                submission,
                &mut journal,
                writes,
                id,
                AuditAction::Read,
                AuditOutcome::Success,
                "独立只读回看原受管差异并核负面资格；不升级原写入结果、不自动重新采用",
            )?;
            Ok((current, Some(plan)))
        },
    )
    .await
}
