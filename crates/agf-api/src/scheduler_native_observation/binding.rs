use super::{
    authority::Submission,
    claim, eligibility,
    input::BindingInput,
    observation, proof,
    records::{BindingRecord, BodyRecord, Fact, Journal, Purpose, Values},
    scope,
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::{DomainError, DomainResult},
    time::Timestamp,
};

pub(super) async fn save(
    state: &AppState,
    submission: &Submission,
    input: BindingInput,
) -> DomainResult<BindingRecord> {
    super::authority::bounded(submission.deadline, Box::pin(save_inner(state, submission, input))).await
}
async fn save_inner(state: &AppState, submission: &Submission, mut input: BindingInput) -> DomainResult<BindingRecord> {
    input.validate()?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let request = input.request();
    super::job_management::require_vacant(state, tenant, request).await?;
    let purpose = if matches!(&input, BindingInput::Replace { .. }) { Purpose::Replace } else { Purpose::Disable };
    let hash = claim::hash(purpose, &input)?;
    if let Some(old) = claim::fact(state, tenant, request).await? {
        claim::replay(&old, purpose, &hash)?;
        return old.binding_result.ok_or_else(util::corrupt);
    }
    let target = if let BindingInput::Replace { configuration_version, .. } = &input {
        let target = scope::current(state, tenant).await?.ok_or_else(util::stale)?;
        if target.configuration_version != *configuration_version {
            return Err(util::stale());
        }
        Some(target)
    } else {
        None
    };
    let state_key = util::state_key(tenant);
    let binding_key = util::binding_key(tenant);
    let fact_key = util::fact_key(tenant, request);
    let callback_key = super::callback_execution::request_key(tenant, request);
    let managed_key = super::job_management::request_key(tenant, request);
    let mut declared =
        vec![state_key.clone(), binding_key.clone(), fact_key.clone(), callback_key.clone(), managed_key.clone()];
    if let BindingInput::Replace { observation_id, .. } = &input {
        declared.push(util::body_key(tenant, *observation_id));
        declared.push(util::fact_key(tenant, *observation_id));
    }
    store::mutate(
        state,
        Mutation { submission, source: target.as_ref(), main: state_key.clone(), declared },
        |snapshot| {
            super::job_management::vacant(snapshot, &managed_key)?;
            if snapshot.get(&callback_key).and_then(Option::as_ref).is_some() {
                return Err(DomainError::Conflict("此请求编号已永久用于 Callback 执行；不得改作关联".into()));
            }
            if let Some(prior) = util::read::<Fact>(snapshot, &fact_key)? {
                claim::validate(&prior, tenant, request)?;
                claim::replay(&prior, purpose, &hash)?;
                return Ok((prior.binding_result.ok_or_else(util::corrupt)?, None));
            }
            let mut row: BindingRecord = util::read(snapshot, &binding_key)?.unwrap_or_default();
            validate(&row, tenant)?;
            proof::restore(state, &row, tenant)?;
            if row.version != input.version() {
                return Err(util::stale());
            }
            let mut journal: Journal = util::read(snapshot, &state_key)?.unwrap_or_default();
            let now = Timestamp::now();
            let next_version = row.version.checked_add(1).ok_or_else(util::capacity)?;
            row.tenant = Some(tenant);
            match &input {
                BindingInput::Replace { observation_id, bindings, .. } => {
                    let source = target.as_ref().ok_or_else(util::corrupt)?;
                    let fact: Fact =
                        util::read(snapshot, &util::fact_key(tenant, *observation_id))?.ok_or_else(util::stale)?;
                    claim::validate(&fact, tenant, *observation_id)?;
                    let body: BodyRecord =
                        util::read(snapshot, &util::body_key(tenant, *observation_id))?.ok_or_else(util::stale)?;
                    if journal.latest != Some(*observation_id)
                        || fact.target.as_ref() != Some(source)
                        || fact.finished_at.is_none_or(|at| at > now || at.offset_secs(300) < now)
                    {
                        return Err(util::stale());
                    }
                    let data = observation::decode(state, tenant, *observation_id, &body, &fact)?;
                    for selection in bindings {
                        let job =
                            data.jobs().iter().find(|job| job["id"] == selection.job_id).ok_or_else(util::stale)?;
                        if job["httpJob"] != true || job["enabled"] != true {
                            return Err(DomainError::PreconditionFailed(
                                "关联只能选择明确启用的 HTTP Job；未知或停用不具备执行资格".into(),
                            ));
                        }
                    }
                    row.target = Some(source.clone());
                    row.observation_id = Some(*observation_id);
                    row.app_id = Some(data.app_id().into());
                    row.fingerprint = Some(data.fingerprint().into());
                    row.verified_at = fact.finished_at;
                    row.items = bindings.clone();
                    row.enabled = !bindings.is_empty();
                    row.version = next_version;
                    row.adoption_version = next_version;
                    row.eligibility =
                        eligibility::adopt(&row, &data, *observation_id, fact.finished_at.ok_or_else(util::corrupt)?)?;
                    row.adopted_proofs = proof::seal(state, &row, tenant)?;
                }
                BindingInput::Disable { .. } => row.enabled = false,
            }
            row.version = next_version;
            proof::seal_qualification(state, &mut row, tenant)?;
            validate(&row, tenant)?;
            store::bump(&mut journal, tenant)?;
            let fact = Fact {
                tenant,
                request_id: request,
                purpose,
                input_hash: hash,
                target: row.target.clone(),
                claim_id: agf_core::ids::Id::new(),
                generation: journal.generation,
                started_at: now,
                submitted_at: submission.submitted_at,
                expires_at: now,
                status: "configured".into(),
                finished_at: Some(now),
                reason: None,
                total: None,
                app_id: row.app_id.clone(),
                fingerprint: row.fingerprint.clone(),
                body_bytes: 0,
                binding_version: Some(row.version),
                binding_result: Some(row.clone()),
            };
            let mut writes = Values::new();
            util::put(&mut writes, state_key, &journal)?;
            util::put(&mut writes, binding_key, &row)?;
            util::put(&mut writes, fact_key, &fact)?;
            Ok((
                row,
                Some(Plan {
                    writes,
                    audit: Box::new(claim::audit(
                        submission,
                        request,
                        "scheduler-native-bindings",
                        AuditAction::Configure,
                        AuditOutcome::Success,
                        "本地关联已保存；尚未保护回调领取或部署执行器",
                    )),
                }),
            ))
        },
    )
    .await
}
pub(super) fn validate(row: &BindingRecord, tenant: agf_core::ids::TenantId) -> DomainResult<()> {
    if row.tenant.is_some_and(|owner| owner != tenant)
        || row.items.len() > 6
        || row.target.as_ref().is_some_and(|target| target.tenant != tenant)
    {
        return Err(util::corrupt());
    }
    if row.version == 0 && (row.tenant.is_some() || row.target.is_some() || row.enabled || !row.items.is_empty()) {
        return Err(util::corrupt());
    }
    if row.version > 0 && row.tenant != Some(tenant) {
        return Err(util::corrupt());
    }
    if let Some(target) = &row.target {
        claim::validate_target(target, tenant)?;
        if row.observation_id.is_none_or(|id| id.is_nil())
            || row.app_id.as_deref().is_none_or(|id| !util::positive_id(id))
            || row.fingerprint.as_deref().is_none_or(|hash| !util::digest(hash))
            || row.verified_at.is_none()
        {
            return Err(util::corrupt());
        }
    } else if row.observation_id.is_some()
        || row.app_id.is_some()
        || row.fingerprint.is_some()
        || row.verified_at.is_some()
        || !row.items.is_empty()
    {
        return Err(util::corrupt());
    }
    let mut kinds = std::collections::BTreeSet::new();
    let mut jobs = std::collections::BTreeSet::new();
    for item in &row.items {
        if !super::KINDS.contains(&item.kind.as_str())
            || !util::positive_id(&item.job_id)
            || !kinds.insert(&item.kind)
            || !jobs.insert(&item.job_id)
        {
            return Err(util::corrupt());
        }
    }
    if row.enabled
        && (row.items.is_empty()
            || row.target.is_none()
            || row.app_id.as_deref().is_none_or(|id| !util::positive_id(id)))
    {
        return Err(util::corrupt());
    }
    proof::validate_record(row, tenant)
}
