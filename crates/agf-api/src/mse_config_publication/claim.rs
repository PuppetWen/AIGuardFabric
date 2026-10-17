//! Claim, preview consumption, active lease and dispatch intent audit commit before any provider call.
use super::{
    audit,
    authority::Submission,
    bundle::BundleContent,
    dependencies,
    input::ApplyInput,
    observation, operations,
    records::*,
    risk,
    sql::key,
    store::{self, Decision, Mutation},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use serde_json::json;

pub(super) async fn claim(
    state: &AppState,
    submission: &Submission,
    input: &ApplyInput,
    hash: &str,
    prepared: &Prepared,
    content: &BundleContent,
) -> DomainResult<(Fact, bool)> {
    let tenant = submission.principal.tenant;
    let (selection, fence) =
        dependencies::prepare(state, &prepared.scope, &prepared.fence.policies, &content.source_policies).await?;
    if fence.dependencies != prepared.fence.dependencies {
        return Err(util::stale());
    }
    let observed = observation::load(state, tenant, prepared.observation_id).await?.ok_or_else(util::stale)?;
    if prepared.acknowledge_unknown_operation_id.is_some() && !input.confirm_unknown_overlap {
        return Err(DomainError::PreconditionFailed(
            "此为新业务意图，旧请求仍可能迟到；请再次明确确认未知重叠风险，不能当作重试".into(),
        ));
    }
    let started_at = Timestamp::now();
    let receipt = Operation {
        request_id: input.request_id,
        preview_id: input.preview_id,
        action: prepared.action,
        source_publication_id: prepared.source_publication_id,
        submitted_at: submission.submitted_at,
        started_at,
        lease_expires_at: started_at.offset_secs(120),
        finished_at: None,
        status: Status::Started,
        original_status: None,
        archived_at: None,
        cloud_write: WriteStatus::NotAttempted,
        readback: ReadStatus::NotAttempted,
        readback_observed_at: None,
        readback_hash: None,
        local_publication: PublicationStatus::NotStaged,
        safe_reason: None,
        desired_hash: prepared.desired_hash.clone(),
        desired_bytes: prepared.desired_bytes,
        source_policy_versions: prepared.source_policy_versions.clone(),
        superseded_by: None,
    };
    let fact = Fact {
        tenant,
        request_id: input.request_id,
        purpose: Purpose::Operation,
        request_hash: hash.to_owned(),
        scope: prepared.scope.clone(),
        created_at: started_at,
        actor: AppState::audit_actor(&submission.principal, &submission.principal.display()),
        outcome: FactOutcome::Operation { receipt: Box::new(receipt) },
    };
    let detail = DetailRecord::Content {
        data: Box::new(Detail { tenant, request_id: input.request_id, prepared: prepared.clone() }),
    };
    util::bound(&detail, 1024 * 1024)?;
    super::completion::preflight(state, &fact)?;
    let mut related = vec![
        key(FACT, util::fact_id(tenant, input.request_id)),
        key(FACT, util::fact_id(tenant, input.preview_id)),
        key(PREVIEW, super::preview::record_id(tenant, input.preview_id)),
        key(DETAIL, operations::record_id(tenant, input.request_id)),
        key(STATE, util::risk_id(tenant, prepared.scope.target.target_scope_id)),
    ];
    if let Some(id) = prepared.acknowledge_unknown_operation_id {
        related.push(key(FACT, util::fact_id(tenant, id)));
    }
    let mut fresh = false;
    store::mutate(state, Mutation { submission, scope: Some(&prepared.scope), selection: Some(&selection), fence: Some(&prepared.fence), source: &content.source_policies, related: &related },
        |main, snapshot| {
            if let Some(prior) = util::read::<Fact>(&snapshot.related, FACT, util::fact_id(tenant, input.request_id))? {
                util::match_fact(&prior, tenant, input.request_id, Purpose::Operation, hash)?;
                return Ok(Decision::Unchanged);
            }
            if main.version != input.expected_state_version || prepared.state_version != main.version || prepared.expires_at <= Timestamp::now()
                || main.latest_observation != Some(prepared.observation_id) { return Err(util::stale()); }
            if main.operations.len() >= 128 { return Err(util::capacity()); }
            let locked: Prepared = util::read(&snapshot.related, PREVIEW, super::preview::record_id(tenant, input.preview_id))?.ok_or_else(util::stale)?;
            if serde_json::to_value(&locked)? != serde_json::to_value(prepared)? { return Err(util::stale()); }
            let mut prior: Fact = util::read(&snapshot.related, FACT, util::fact_id(tenant, input.preview_id))?.ok_or_else(util::stale)?;
            let FactOutcome::Prepared { consumed_by } = &mut prior.outcome else { return Err(util::corrupt()); };
            if consumed_by.is_some() { return Err(DomainError::Conflict("该预览已被消费，任何新UUID也不得再次发送".into())); }
            let marker: Option<Risk> = util::read(&snapshot.related, STATE, util::risk_id(tenant, prepared.scope.target.target_scope_id))?;
            risk::preview(main, marker.as_ref(), &observed, prepared.acknowledge_unknown_operation_id)?;
            *consumed_by = Some(input.request_id);
            let mut writes = Values::new();
            if let Some(id) = prepared.acknowledge_unknown_operation_id {
                let mut old: Fact = util::read(&snapshot.related, FACT, util::fact_id(tenant, id))?.ok_or_else(util::corrupt)?;
                if (old.tenant, old.request_id, old.purpose) != (tenant, id, Purpose::Operation)
                    || old.scope.target.target_scope_id != prepared.scope.target.target_scope_id { return Err(util::corrupt()); }
                let old_receipt = operations::receipt_mut(&mut old)?;
                if old_receipt.local_publication != PublicationStatus::Published || !(old_receipt.status == Status::Uncertain || old_receipt.original_status == Some(Status::Uncertain)) {
                    return Err(util::stale());
                }
                old_receipt.superseded_by = Some(input.request_id);
                util::put(&mut writes, FACT, util::fact_id(tenant, id), &old)?;
            }
            main.previews.retain(|id| *id != input.preview_id);
            main.operations.push(input.request_id);
            main.active = Some(Active { request_id: input.request_id, expires_at: operations::receipt(&fact)?.lease_expires_at });
            util::bump(main)?;
            util::put(&mut writes, FACT, util::fact_id(tenant, input.request_id), &fact)?;
            util::put(&mut writes, FACT, util::fact_id(tenant, input.preview_id), &prior)?;
            util::put(&mut writes, DETAIL, operations::record_id(tenant, input.request_id), &detail)?;
            writes.insert((PREVIEW.into(), super::preview::record_id(tenant, input.preview_id)), None);
            let audit = audit::entry(submission, input.request_id, "mse-config-publication-claim", AuditAction::Configure,
                json!({"previewId":input.preview_id,"targetScopeId":prepared.scope.target.target_scope_id,"contentHash":prepared.desired_hash,"phase":"claimed"}));
            fresh = true;
            Ok(Decision::Write { related: writes, audit: Box::new(audit) })
        }).await?;
    let stored = operations::load(state, tenant, input.request_id).await?.ok_or_else(util::corrupt)?;
    Ok((stored, fresh))
}
