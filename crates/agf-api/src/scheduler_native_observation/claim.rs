use super::{
    authority::Submission,
    input::ObserveInput,
    records::{Active, Fact, Journal, Purpose, Values},
    scope::SourceTarget,
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};

pub(super) async fn fact(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Option<Fact>> {
    let row: Option<Fact> = store::get(state, tenant, &util::fact_key(tenant, id)).await?;
    if let Some(row) = &row {
        validate(row, tenant, id)?;
    }
    Ok(row)
}
pub(super) fn validate(row: &Fact, tenant: TenantId, id: Id) -> DomainResult<()> {
    if (row.tenant, row.request_id) != (tenant, id)
        || row.claim_id.is_nil()
        || !util::digest(&row.input_hash)
        || row.target.as_ref().is_some_and(|target| target.tenant != tenant)
        || !["reading", "observed", "failed", "interrupted", "configured"].contains(&row.status.as_str())
        || (row.status == "reading") != row.finished_at.is_none()
        || row.expires_at < row.started_at
        || row.submitted_at > row.started_at
    {
        return Err(util::corrupt());
    }
    if let Some(target) = &row.target {
        validate_target(target, tenant)?;
    }
    match row.purpose {
        Purpose::Observe => {
            if row.target.is_none()
                || row.binding_version.is_some()
                || row.binding_result.is_some()
                || row.status == "configured"
            {
                return Err(util::corrupt());
            }
            if row.status == "observed"
                && (row.total.is_none_or(|total| total > 2000)
                    || row.app_id.as_deref().is_none_or(|id| !util::positive_id(id))
                    || row.fingerprint.as_deref().is_none_or(|hash| !util::digest(hash))
                    || row.body_bytes == 0)
            {
                return Err(util::corrupt());
            }
        }
        Purpose::Replace | Purpose::Disable => {
            let binding = row.binding_result.as_ref().ok_or_else(util::corrupt)?;
            super::binding::validate(binding, tenant)?;
            if row.status != "configured"
                || row.binding_version != Some(binding.version)
                || binding.version == 0
                || row.target != binding.target
                || row.app_id != binding.app_id
                || row.fingerprint != binding.fingerprint
            {
                return Err(util::corrupt());
            }
        }
    }
    Ok(())
}
pub(super) fn validate_target(target: &SourceTarget, tenant: TenantId) -> DomainResult<()> {
    if target.tenant != tenant
        || target.configuration_id != util::main_id(tenant)
        || target.configuration_version == 0
        || target.scope_id.is_nil()
        || target.scope_id != super::scope::identity(target)?
        || !util::digest(&target.fingerprint)
        || !util::text(&target.region, 256)
        || !util::text(&target.cluster_id, 256)
        || !util::text(&target.app_name, 256)
        || target.account_identity_verified
        || target.configured_account_id.as_ref().is_some_and(|account| !util::text(account, 256))
        || super::scope::normalized_origin(&target.rpc_origin)? != target.rpc_origin
        || if target.mocked {
            target.transport_mode != "mock"
        } else {
            !matches!(target.transport_mode.as_str(), "live" | "loopback_test")
                || (target.transport_mode == "live") != target.rpc_origin.starts_with("https://")
        }
    {
        return Err(util::corrupt());
    }
    Ok(())
}
pub(super) fn hash<T: serde::Serialize>(purpose: Purpose, input: &T) -> DomainResult<String> {
    util::canonical_hash(&serde_json::json!({"purpose":purpose,"input":input}))
}
pub(super) fn replay(row: &Fact, purpose: Purpose, hash: &str) -> DomainResult<()> {
    if row.purpose != purpose || row.input_hash != hash {
        return Err(DomainError::Conflict("此请求编号已用于其他动作或参数；旧编号永久不重派".into()));
    }
    Ok(())
}
pub(super) fn audit(
    submission: &Submission,
    id: Id,
    kind: &str,
    action: AuditAction,
    outcome: AuditOutcome,
    note: &str,
) -> AuditLog {
    let mut entry = AppState::audit_entry(
        submission.principal.tenant,
        action,
        outcome,
        AppState::audit_actor(&submission.principal, "scheduler-native"),
        AuditTarget::new(kind, Some(id.to_string()), None),
        note,
    );
    entry.request_id = Some(id.to_string());
    entry
}
pub(super) async fn observe(
    state: &AppState,
    submission: &Submission,
    target: &SourceTarget,
    input: &ObserveInput,
) -> DomainResult<(Fact, bool)> {
    let tenant = submission.principal.tenant;
    let request_hash = hash(Purpose::Observe, input)?;
    let state_key = util::state_key(tenant);
    let fact_key = util::fact_key(tenant, input.request_id);
    let callback_key = super::callback_execution::request_key(tenant, input.request_id);
    let managed_key = super::job_management::request_key(tenant, input.request_id);
    store::mutate(
        state,
        Mutation {
            submission,
            source: Some(target),
            main: state_key.clone(),
            declared: vec![state_key.clone(), fact_key.clone(), callback_key.clone(), managed_key.clone()],
        },
        |snapshot| {
            super::job_management::vacant(snapshot, &managed_key)?;
            if snapshot.get(&callback_key).and_then(Option::as_ref).is_some() {
                return Err(DomainError::Conflict("此请求编号已永久用于 Callback 执行；不得改作观察".into()));
            }
            if let Some(prior) = util::read::<Fact>(snapshot, &fact_key)? {
                validate(&prior, tenant, input.request_id)?;
                replay(&prior, Purpose::Observe, &request_hash)?;
                return Ok(((prior, false), None));
            }
            let mut journal: Journal = util::read(snapshot, &state_key)?.unwrap_or_default();
            store::validate_journal(&journal, tenant)?;
            if journal.active.as_ref().is_some_and(|active| active.expires_at > Timestamp::now()) {
                return Err(DomainError::Conflict("已有 Scheduler 观察正在执行；请等待原领取结束".into()));
            }
            if journal.observations.len() >= super::MAX_RUNS {
                return Err(util::capacity());
            }
            store::bump(&mut journal, tenant)?;
            let now = Timestamp::now();
            let row = Fact {
                tenant,
                request_id: input.request_id,
                purpose: Purpose::Observe,
                input_hash: request_hash,
                target: Some(target.clone()),
                claim_id: Id::new(),
                generation: journal.generation,
                started_at: now,
                submitted_at: submission.submitted_at,
                expires_at: submission.submitted_at.offset_secs(120),
                status: "reading".into(),
                finished_at: None,
                reason: None,
                total: None,
                app_id: None,
                fingerprint: None,
                body_bytes: 0,
                binding_version: None,
                binding_result: None,
            };
            journal.active = Some(Active {
                request_id: row.request_id,
                claim_id: row.claim_id,
                generation: row.generation,
                expires_at: row.expires_at,
            });
            journal.observations.push(row.request_id);
            let mut writes = Values::new();
            util::put(&mut writes, state_key, &journal)?;
            util::put(&mut writes, fact_key, &row)?;
            Ok((
                (row.clone(), true),
                Some(Plan {
                    writes,
                    audit: Box::new(audit(
                        submission,
                        row.request_id,
                        "scheduler-native-read-claim",
                        AuditAction::Create,
                        AuditOutcome::Success,
                        "永久领取只读观察；不代表云数据或回调执行成功",
                    )),
                }),
            ))
        },
    )
    .await
}
pub(super) fn owns(journal: &Journal, row: &Fact) -> bool {
    journal.active.as_ref().is_some_and(|active| {
        (active.request_id, active.claim_id, active.generation) == (row.request_id, row.claim_id, row.generation)
            && active.expires_at > Timestamp::now()
    }) && row.status == "reading"
}
