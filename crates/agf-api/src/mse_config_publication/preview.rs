//! Previews copy exact trusted content and current fencing; no provider write or consumer reload occurs.
use super::{
    audit,
    authority::Submission,
    bundle, context, dependencies,
    input::{PreviewChange, PreviewInput},
    observation,
    records::{Action, FACT, Fact, FactOutcome, PREVIEW, Prepared, Purpose, Values},
    risk,
    sql::key,
    store::{self, Decision, Mutation},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde_json::json;

pub(super) async fn create(state: &AppState, submission: &Submission, input: PreviewInput) -> DomainResult<Prepared> {
    let input = input.normalize()?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let scope = context::current(state, tenant, Some(input.configuration_version)).await?;
    let hash = util::request_hash(&(&input, &scope))?;
    if let Some(fact) = state.configurations.get::<Fact>(tenant, FACT, util::fact_id(tenant, input.request_id)).await? {
        util::match_fact(&fact, tenant, input.request_id, Purpose::Preview, &hash)?;
        return load(state, tenant, input.request_id).await?.ok_or_else(|| {
            DomainError::Conflict("此预览编号已消费或过期清理；不能重新构建或重派，请明确创建新预览".into())
        });
    }
    let main = store::load(state, tenant).await?;
    if main.version != input.expected_state_version {
        return Err(util::stale());
    }
    let observed = observation::load(state, tenant, input.observation_id).await?.ok_or_else(util::stale)?;
    if main.latest_observation != Some(input.observation_id)
        || observed.scope != scope
        || observed.observed_at.age_secs() > 300
        || observed.started_at > observed.observed_at
        || observed.observed_at > Timestamp::now()
    {
        return Err(util::stale());
    }
    let risk_marker = risk::load(state, tenant, scope.target.target_scope_id).await?;
    risk::preview(&main, risk_marker.as_ref(), &observed, input.acknowledge_unknown_operation_id)?;
    let signer = crate::policy_store::signer(state)?;
    let (content, selected, fence, action, source_publication) = match &input.change {
        PreviewChange::Publish { policies } => {
            let (selected, fence) = dependencies::prepare(state, &scope, policies, &[]).await?;
            let content = bundle::generate(&scope, selected.policies.clone(), fence.dependencies.clone(), &signer)?;
            (content, selected, fence, Action::Publish, None)
        }
        PreviewChange::Rollback { publication_id } => {
            let content = super::operations::history_content(state, tenant, *publication_id, &scope).await?;
            let current = dependencies::current_versions(state, tenant, &content.source_policy_versions).await?;
            let (selected, fence) = dependencies::prepare(state, &scope, &current, &content.source_policies).await?;
            (content, selected, fence, Action::Rollback, Some(*publication_id))
        }
    };
    let baseline = util::decrypt_content(
        state,
        tenant,
        observation::record_id(tenant, observed.request_id),
        &observed.content,
        &observed.content_hash,
    )?;
    let now = Timestamp::now();
    let prepared = Prepared {
        tenant,
        request_id: input.request_id,
        scope: scope.clone(),
        state_version: main.version.checked_add(1).ok_or_else(util::capacity)?,
        created_at: now,
        expires_at: now.offset_secs(120),
        action,
        source_publication_id: source_publication,
        observation_id: observed.request_id,
        baseline_observed_at: observed.observed_at,
        baseline_md5: observed.content_md5.clone(),
        baseline_hash: observed.content_hash.clone(),
        baseline_bytes: observed.content_bytes,
        desired_hash: content.content_hash,
        desired_bytes: content.plaintext.len(),
        source_policy_versions: content.source_policy_versions,
        fence: fence.clone(),
        acknowledge_unknown_operation_id: input.acknowledge_unknown_operation_id,
        baseline: util::encrypt_content(state, tenant, body_id(tenant, input.request_id, "baseline"), &baseline)?,
        desired: util::encrypt_content(
            state,
            tenant,
            body_id(tenant, input.request_id, "desired"),
            &content.plaintext,
        )?,
    };
    util::bound(&prepared, 1024 * 1024)?;
    // Reserve predictable operation/detail/pending metadata before any future external write.
    util::bound(
        &super::records::Detail { tenant, request_id: input.request_id, prepared: prepared.clone() },
        1024 * 1024,
    )?;
    let fact = Fact {
        tenant,
        request_id: input.request_id,
        purpose: Purpose::Preview,
        request_hash: hash,
        scope: scope.clone(),
        created_at: now,
        actor: AppState::audit_actor(&submission.principal, &submission.principal.display()),
        outcome: FactOutcome::Prepared { consumed_by: None },
    };
    let mut related =
        vec![key(FACT, util::fact_id(tenant, input.request_id)), key(PREVIEW, record_id(tenant, input.request_id))];
    related.extend(main.previews.iter().map(|id| key(PREVIEW, record_id(tenant, *id))));
    related.push(key(super::records::STATE, util::risk_id(tenant, scope.target.target_scope_id)));
    store::mutate(state, Mutation { submission, scope: Some(&scope), selection: Some(&selected), fence: Some(&fence), source: &content.source_policies, related: &related },
        |candidate, snapshot| {
            if candidate.version != input.expected_state_version || candidate.latest_observation != Some(observed.request_id) { return Err(util::stale()); }
            let risk_marker = util::read(&snapshot.related, super::records::STATE, util::risk_id(tenant, scope.target.target_scope_id))?;
            risk::preview(candidate, risk_marker.as_ref(), &observed, input.acknowledge_unknown_operation_id)?;
            if util::read::<Fact>(&snapshot.related, FACT, util::fact_id(tenant, input.request_id))?.is_some() { return Err(util::stale()); }
            let mut writes = Values::new();
            let mut retained = Vec::new();
            for id in &candidate.previews {
                let row: Prepared = util::read(&snapshot.related, PREVIEW, record_id(tenant, *id))?.ok_or_else(util::corrupt)?;
                if row.expires_at <= now { writes.insert((PREVIEW.into(), record_id(tenant, *id)), None); } else { retained.push(*id); }
            }
            if retained.len() >= 32 { return Err(util::capacity()); }
            retained.push(input.request_id);
            candidate.previews = retained;
            util::bump(candidate)?;
            util::put(&mut writes, FACT, util::fact_id(tenant, input.request_id), &fact)?;
            util::put(&mut writes, PREVIEW, record_id(tenant, input.request_id), &prepared)?;
            let audit = audit::entry(submission, input.request_id, "mse-config-publication-preview", AuditAction::Configure,
                json!({"targetScopeId":scope.target.target_scope_id,"contentHash":prepared.desired_hash,"contentBytes":prepared.desired_bytes,"action":action}));
            Ok(Decision::Write { related: writes, audit: Box::new(audit) })
        }).await?;
    Ok(prepared)
}

pub(super) async fn load(state: &AppState, tenant: TenantId, request: Id) -> DomainResult<Option<Prepared>> {
    let row = state.configurations.get::<Prepared>(tenant, PREVIEW, record_id(tenant, request)).await?;
    if let Some(row) = &row {
        validate_content(state, tenant, row)?;
    }
    Ok(row)
}
pub(super) fn validate_content(
    state: &AppState,
    tenant: TenantId,
    prepared: &Prepared,
) -> DomainResult<bundle::BundleContent> {
    if (prepared.tenant, prepared.scope.tenant) != (tenant, tenant) || prepared.request_id.is_nil() {
        return Err(util::corrupt());
    }
    let baseline = util::decrypt_content(
        state,
        tenant,
        body_id(tenant, prepared.request_id, "baseline"),
        &prepared.baseline,
        &prepared.baseline_hash,
    )?;
    if baseline.len() != prepared.baseline_bytes
        || agf_alicloud::mse::config_cas::content_md5(&baseline) != prepared.baseline_md5
    {
        return Err(util::corrupt());
    }
    let desired = util::decrypt_content(
        state,
        tenant,
        body_id(tenant, prepared.request_id, "desired"),
        &prepared.desired,
        &prepared.desired_hash,
    )?;
    if desired.len() != prepared.desired_bytes {
        return Err(util::corrupt());
    }
    bundle::verify_history(&prepared.scope, &desired, &prepared.desired_hash, &crate::policy_store::signer(state)?)
}
pub(super) fn record_id(tenant: TenantId, request: Id) -> Id {
    util::content_id(tenant, request, "preview")
}
fn body_id(tenant: TenantId, request: Id, purpose: &str) -> Id {
    util::content_id(tenant, request, purpose)
}
