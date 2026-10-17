use super::super::{
    authority::Submission,
    claim,
    records::{BindingRecord, Values},
    store::{self, Mutation, Plan},
    util,
};
use super::{
    current, evidence, identity,
    model::{Fact, State},
};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};

pub(super) async fn consume(
    state: &AppState,
    submission: &Submission,
    id: Id,
    claim_id: Id,
) -> DomainResult<(Fact, bool)> {
    let row = super::views::load(state, submission.principal.tenant, id).await?;
    current::owner(state, submission, &row.context.owner).await?;
    if row.claim_id != claim_id || claim_id.is_nil() {
        return Err(current::conflict());
    }
    if row.state != State::Admitted {
        return Ok((row, false));
    }
    let key = identity::fact_key(id);
    let binding_key = util::binding_key(row.context.tenant);
    let remaining = row.start_expires_at.unix_millis() - Timestamp::now().unix_millis();
    if remaining <= 0 {
        return Err(current::unqualified());
    }
    let start_deadline =
        submission.deadline.min(tokio::time::Instant::now() + std::time::Duration::from_millis(remaining as u64));
    super::super::authority::bounded(
        start_deadline,
        Box::pin(store::mutate(
            state,
            Mutation {
                submission,
                source: Some(&row.context.target),
                main: key.clone(),
                declared: vec![util::state_key(row.context.tenant), binding_key.clone(), key.clone()],
            },
            |snapshot| {
                let mut stored: Fact = util::read(snapshot, &key)?.ok_or_else(util::corrupt)?;
                evidence::verify_fact(state, &stored)?;
                current::owner_locked(state, submission, &stored.context.owner)?;
                if stored.claim_id != claim_id {
                    return Err(current::conflict());
                }
                if stored.state != State::Admitted {
                    return Ok(((stored, false), None));
                }
                let binding: BindingRecord = util::read(snapshot, &binding_key)?.ok_or_else(current::unqualified)?;
                current::fence(state, &binding, &stored.context)?;
                let now = Timestamp::now();
                if now >= stored.start_expires_at {
                    return Err(DomainError::PreconditionFailed(
                        "原 Callback 启动租约已过期；该分片不可重新领取".into(),
                    ));
                }
                stored.started_at = Some(now);
                stored.execution_expires_at = Some(now.offset_secs(300));
                stored.state = State::Running;
                stored.validate(row.context.tenant, id)?;
                evidence::seal_fact(state, &mut stored)?;
                let mut writes = Values::new();
                util::put(&mut writes, key, &stored)?;
                Ok((
                    (stored, true),
                    Some(Plan {
                        writes,
                        audit: Box::new(claim::audit(
                            submission,
                            id,
                            "scheduler-native-callback-start",
                            AuditAction::Execute,
                            AuditOutcome::Success,
                            "一次性消耗原准入启动权；丢失响应不得重新开始业务",
                        )),
                    }),
                ))
            },
        )),
    )
    .await
}
