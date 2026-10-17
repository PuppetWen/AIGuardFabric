use super::super::{
    authority::Submission,
    claim,
    records::Values,
    store::{self, Mutation, Plan},
    util,
};
use super::{current, dependencies, evidence, identity, input::CompleteInput, model::*, staging};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::Id,
};
use std::sync::Arc;

pub(super) async fn complete(
    state: &AppState,
    submission: Arc<Submission>,
    id: Id,
    input: CompleteInput,
) -> DomainResult<Fact> {
    input.outcome.validate()?;
    let row = super::super::authority::bounded(
        submission.deadline,
        Box::pin(async {
            let row = super::views::load(state, submission.principal.tenant, id).await?;
            current::owner(state, &submission, &row.context.owner).await?;
            Ok(row)
        }),
    )
    .await?;
    if input.claim_id.is_nil() || row.claim_id != input.claim_id {
        return Err(current::conflict());
    }
    if row.started_at.is_none() {
        return Err(current::unqualified());
    }
    let state = state.clone();
    // Only known, already supplied local data is owned. A canceled caller cannot respawn a handler.
    tokio::spawn(async move {
        let known = staging::persist(&state, &submission, &row, input.outcome).await?;
        match publish(&state, &submission, &row, &known).await {
            Ok(row) => Ok(row),
            Err(error) => {
                tracing::warn!(code = error.code(), "Callback 已知结果的终态审计尚未出版；仅允许相同结果本地恢复");
                Ok(row)
            }
        }
    })
    .await
    .map_err(|_| DomainError::Internal("Callback 本地结果任务中断；原事实不重派".into()))?
}
async fn publish(state: &AppState, submission: &Submission, row: &Fact, known: &staging::Known) -> DomainResult<Fact> {
    let tenant = row.context.tenant;
    let key = identity::fact_key(row.id);
    let batch_key = identity::batch_key(row.batch_id);
    let pending_key = identity::pending_key(row.id);
    let progress_key = identity::progress_key(tenant, &row.context.kind);
    store::mutate(
        state,
        Mutation {
            submission,
            source: None,
            main: key.clone(),
            declared: vec![
                util::state_key(tenant),
                key.clone(),
                batch_key.clone(),
                pending_key.clone(),
                progress_key.clone(),
            ],
        },
        |snapshot| {
            let mut fact: Fact = util::read(snapshot, &key)?.ok_or_else(util::corrupt)?;
            if fact.context.tenant != tenant || fact.id != row.id {
                return Err(util::corrupt());
            }
            evidence::verify_fact(state, &fact)?;
            current::owner_locked(state, submission, &fact.context.owner)?;
            let pending: Pending = util::read(snapshot, &pending_key)?.ok_or_else(util::corrupt)?;
            let saved = staging::decode(state, &fact, &pending)?;
            if saved.outcome != known.outcome || !staging::same_original(&saved.original, &known.original)? {
                return Err(current::conflict());
            }
            if fact.state != State::Running {
                if fact.outcome.as_ref() != Some(&saved.outcome) {
                    return Err(util::corrupt());
                }
                return Ok((fact, None));
            }
            let mut batch: Batch = util::read(snapshot, &batch_key)?.ok_or_else(util::corrupt)?;
            batch.validate(tenant)?;
            if batch.context != fact.context {
                return Err(util::corrupt());
            }
            let prior_batch = batch.clone();
            let partition = batch.partitions.get_mut(&fact.partition_index).ok_or_else(util::corrupt)?;
            if (partition.fact_id, partition.claim_id) != (fact.id, fact.claim_id) || partition.terminal.is_some() {
                return Err(util::corrupt());
            }
            let hash = identity::outcome_hash(&saved.outcome)?;
            partition.terminal = Some(Terminal {
                ok: saved.outcome.ok,
                skipped: saved.outcome.skipped,
                degraded: saved.outcome.degraded,
                outcome_hash: hash.clone(),
                finished_at: saved.staged_at,
            });
            batch.validate(tenant)?;
            fact.state = if saved.outcome.ok { State::Succeeded } else { State::Failed };
            fact.finished_at = Some(saved.staged_at);
            fact.outcome = Some(saved.outcome);
            fact.outcome_hash = Some(hash);
            fact.validate(tenant, row.id)?;
            evidence::seal_fact(state, &mut fact)?;
            let mut writes = Values::new();
            util::put(&mut writes, key, &fact)?;
            util::put(&mut writes, batch_key, &batch)?;
            if let Some(progress) = util::read::<Progress>(snapshot, &progress_key)? {
                dependencies::validate_progress(state, &progress, tenant, &fact.context.kind)?;
                if progress.batch.id == batch.id {
                    if progress.batch != prior_batch {
                        return Err(util::corrupt());
                    }
                    let progress = evidence::seal(state, tenant, &fact.context.kind, batch)?;
                    util::put(&mut writes, progress_key, &progress)?;
                }
            } else {
                return Err(util::corrupt());
            }
            let audit = claim::audit(
                submission,
                fact.id,
                "scheduler-native-callback-execution",
                AuditAction::Execute,
                if fact.state == State::Succeeded { AuditOutcome::Success } else { AuditOutcome::Failure },
                "出版原已知 Callback 结果；不证明外部效果恰好一次或新的执行授权",
            );
            Ok((fact, Some(Plan { writes, audit: Box::new(audit) })))
        },
    )
    .await
}
