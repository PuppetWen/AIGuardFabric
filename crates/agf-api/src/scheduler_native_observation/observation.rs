use super::{
    authority::Submission,
    binding, claim, eligibility,
    input::ObserveInput,
    proof, provider,
    records::{BindingRecord, BodyRecord, Fact, Journal, StoredBody, Values},
    safe::SafeSnapshot,
    scope::{self, SourceTarget},
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use std::sync::Arc;

pub(super) async fn observe(state: &AppState, submission: Arc<Submission>, input: ObserveInput) -> DomainResult<Fact> {
    super::authority::bounded(submission.deadline, Box::pin(observe_inner(state, submission, input))).await
}
async fn observe_inner(state: &AppState, submission: Arc<Submission>, input: ObserveInput) -> DomainResult<Fact> {
    if input.request_id.is_nil() || input.configuration_version == 0 {
        return Err(DomainError::Validation("观察需要 UUID 和正配置版本".into()));
    }
    submission.authorize(state).await?;
    super::job_management::require_vacant(state, submission.principal.tenant, input.request_id).await?;
    if let Some(old) = claim::fact(state, submission.principal.tenant, input.request_id).await? {
        claim::replay(&old, super::records::Purpose::Observe, &claim::hash(super::records::Purpose::Observe, &input)?)?;
        return Ok(old);
    }
    let target = scope::current(state, submission.principal.tenant).await?.ok_or_else(util::stale)?;
    if target.configuration_version != input.configuration_version {
        return Err(util::stale());
    }
    if target.transport_mode == "live" && !input.confirm_live {
        return Err(DomainError::PreconditionFailed("真实云观察需要明确 confirm_live".into()));
    }
    let (row, created) = claim::observe(state, &submission, &target, &input).await?;
    if !created {
        return Ok(row);
    }
    let mut cancellation =
        Cancellation { state: state.clone(), submission: submission.clone(), row: row.clone(), armed: true };
    if input.initialize_mock_fixture {
        provider::seed(state, &submission, &target).await?;
    }
    let guard = provider::Guard { state, submission: &submission, target: &target, row: &row };
    let data = match Box::pin(provider::read(state, &guard)).await {
        Ok(data) => data,
        Err(error) => {
            finish_failure(state, &submission, &row, "观察未能获得可信完整结果").await?;
            cancellation.armed = false;
            return Err(error);
        }
    };
    // Only local terminal publication is owned. Cancellation never spawns another provider read.
    let state_owned = state.clone();
    let submission_owned = submission.clone();
    let row_owned = row.clone();
    let task =
        tokio::spawn(async move { finish_success(&state_owned, &submission_owned, &row_owned, &target, data).await });
    cancellation.armed = false;
    task.await.map_err(|_| DomainError::Internal("Scheduler 本地观察出版任务中断；永久领取仍保留".into()))?
}
struct Cancellation {
    state: AppState,
    submission: Arc<Submission>,
    row: Fact,
    armed: bool,
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let state = self.state.clone();
        let submission = self.submission.clone();
        let row = self.row.clone();
        tokio::spawn(async move {
            if let Err(error) =
                finish_failure(&state, &submission, &row, "原请求已取消；只结束本地领取，不重派云读取").await
            {
                tracing::warn!(code = error.code(), "Scheduler 取消后的本地结束未出版；可在租约过期后显式归档");
            }
        });
    }
}
async fn finish_success(
    state: &AppState,
    submission: &Submission,
    row: &Fact,
    target: &SourceTarget,
    data: SafeSnapshot,
) -> DomainResult<Fact> {
    let tenant = row.tenant;
    let state_key = util::state_key(tenant);
    let fact_key = util::fact_key(tenant, row.request_id);
    let body_key = util::body_key(tenant, row.request_id);
    let binding_key = util::binding_key(tenant);
    let (secret, hash) = util::encrypt_json(state, tenant, body_key.1, data.value())?;
    let body = BodyRecord::Content(Box::new(StoredBody {
        tenant,
        request_id: row.request_id,
        target: target.clone(),
        app_id: data.app_id().into(),
        hash,
        secret,
    }));
    let bytes = util::bound(&body, 4 * 1024 * 1024)?;
    store::mutate(
        state,
        Mutation {
            submission,
            source: Some(target),
            main: body_key.clone(),
            declared: vec![state_key.clone(), fact_key.clone(), body_key.clone(), binding_key.clone()],
        },
        |snapshot| {
            let mut journal: Journal = util::read(snapshot, &state_key)?.unwrap_or_default();
            let mut current: Fact = util::read(snapshot, &fact_key)?.ok_or_else(util::corrupt)?;
            claim::validate(&current, tenant, row.request_id)?;
            if !claim::owns(&journal, &current)
                || !journal.observations.contains(&row.request_id)
                || current.claim_id != row.claim_id
            {
                return Err(util::stale());
            }
            if snapshot.get(&body_key).and_then(Option::as_ref).is_some() {
                return Err(util::corrupt());
            }
            current.status = "observed".into();
            current.finished_at = Some(Timestamp::now());
            current.total = Some(data.total());
            current.app_id = Some(data.app_id().into());
            current.fingerprint = Some(data.fingerprint().into());
            current.body_bytes = bytes;
            let mut bindings: BindingRecord = util::read(snapshot, &binding_key)?.unwrap_or_default();
            binding::validate(&bindings, tenant)?;
            proof::restore(state, &bindings, tenant)?;
            let refresh_binding = bindings.adoption_version > 0 && bindings.target.as_ref() == Some(target);
            let qualification_changes = eligibility::refresh(
                &mut bindings,
                &data,
                target,
                row.request_id,
                current.finished_at.ok_or_else(util::corrupt)?,
            )?;
            if refresh_binding {
                proof::seal_qualification(state, &mut bindings, tenant)?;
                binding::validate(&bindings, tenant)?;
            }
            journal.stored_bytes = journal.stored_bytes.checked_add(bytes).ok_or_else(util::capacity)?;
            journal.latest = Some(row.request_id);
            journal.active = None;
            store::bump(&mut journal, tenant)?;
            let mut writes = Values::new();
            util::put(&mut writes, state_key, &journal)?;
            util::put(&mut writes, fact_key, &current)?;
            util::put(&mut writes, body_key, &body)?;
            if refresh_binding {
                util::put(&mut writes, binding_key, &bindings)?;
            }
            let mut audit = claim::audit(
                submission,
                row.request_id,
                "scheduler-native-observation",
                AuditAction::Read,
                AuditOutcome::Success,
                "按契约完成全部页；同事务核对已采用资格，不证明强快照、HTTP配置或回调执行",
            );
            audit.after = Some(serde_json::json!({
                "bindingVersion":bindings.version,"adoptionVersion":bindings.adoption_version,
                "qualificationChanges":qualification_changes
            }));
            Ok((current, Some(Plan { writes, audit: Box::new(audit) })))
        },
    )
    .await
}
async fn finish_failure(state: &AppState, submission: &Submission, row: &Fact, note: &str) -> DomainResult<()> {
    let state_key = util::state_key(row.tenant);
    let fact_key = util::fact_key(row.tenant, row.request_id);
    store::mutate(
        state,
        Mutation {
            submission,
            source: None,
            main: state_key.clone(),
            declared: vec![state_key.clone(), fact_key.clone()],
        },
        |snapshot| {
            let mut current: Fact = util::read(snapshot, &fact_key)?.ok_or_else(util::corrupt)?;
            claim::validate(&current, row.tenant, row.request_id)?;
            if current.status != "reading" || current.claim_id != row.claim_id {
                return Ok(((), None));
            }
            let mut journal: Journal = util::read(snapshot, &state_key)?.unwrap_or_default();
            if !journal.observations.contains(&row.request_id) {
                return Ok(((), None));
            }
            current.status = "failed".into();
            current.finished_at = Some(Timestamp::now());
            current.reason = Some(note.into());
            if journal.active.as_ref().is_some_and(|active| active.claim_id == row.claim_id) {
                journal.active = None;
            }
            store::bump(&mut journal, row.tenant)?;
            let mut writes = Values::new();
            util::put(&mut writes, state_key, &journal)?;
            util::put(&mut writes, fact_key, &current)?;
            Ok((
                (),
                Some(Plan {
                    writes,
                    audit: Box::new(claim::audit(
                        submission,
                        row.request_id,
                        "scheduler-native-observation",
                        AuditAction::Read,
                        AuditOutcome::Failure,
                        note,
                    )),
                }),
            ))
        },
    )
    .await
}
pub(super) fn decode(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    row: &BodyRecord,
    fact: &Fact,
) -> DomainResult<SafeSnapshot> {
    match row {
        BodyRecord::Content(content) => {
            if (content.tenant, content.request_id) != (tenant, id)
                || fact.target.as_ref() != Some(&content.target)
                || fact.app_id.as_ref() != Some(&content.app_id)
                || fact.status != "observed"
                || fact.body_bytes != util::bound(row, 4 * 1024 * 1024)?
            {
                return Err(util::corrupt());
            }
            let data = SafeSnapshot::parse(
                &content.target,
                util::decrypt_json(state, tenant, util::body_key(tenant, id).1, &content.secret, &content.hash)?,
            )?;
            if fact.fingerprint.as_deref() != Some(data.fingerprint()) || fact.total != Some(data.total()) {
                return Err(util::corrupt());
            }
            Ok(data)
        }
        BodyRecord::Archived { tenant: owner, request_id, .. } if (*owner, *request_id) == (tenant, id) => {
            Err(DomainError::PreconditionFailed("该观察正文已归档；请使用新 UUID 重新观察".into()))
        }
        BodyRecord::Archived { .. } => Err(util::corrupt()),
    }
}
