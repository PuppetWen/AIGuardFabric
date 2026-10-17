//! Previews copy exact trusted content and current fencing; no provider write or consumer reload occurs.
use super::{
    audit,
    authority::Submission,
    content, context,
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
    let risk_marker = risk::load(state, tenant, scope.target.write_resource_id).await?;
    risk::preview(&main, risk_marker.as_ref(), &observed, input.acknowledge_unknown_operation_id)?;
    let now = Timestamp::now();
    let baseline = observation::restore(state, &observed)?;
    let intent = match &input.change {
        PreviewChange::Content { .. } | PreviewChange::Models { .. } => {
            content::Intent { action: Action::Publish, source_publication_id: None, change: input.change.clone() }
        }
        PreviewChange::Rollback { publication_id } => {
            let history = super::operations::history_content(state, tenant, *publication_id, &scope).await?;
            content::Intent {
                action: Action::Rollback,
                source_publication_id: Some(*publication_id),
                change: content::rollback(&scope, &baseline, &history)?,
            }
        }
    };
    let action = intent.action;
    let source_publication = intent.source_publication_id;
    let proof = content::Proof {
        scope: scope.clone(),
        state_version: main.version.checked_add(1).ok_or_else(util::capacity)?,
        observation_id: observed.request_id,
        created_at: now,
        expires_at: now.offset_secs(120),
        baseline_observed_at: observed.observed_at,
        acknowledge_unknown_operation_id: input.acknowledge_unknown_operation_id,
    };
    let content = content::generate(&scope, &baseline, intent, proof)?;
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
        baseline_fingerprint: observed.fingerprint.clone(),
        baseline_config_hash: observed.config_hash.clone(),
        body_hash: content.package_hash.clone(),
        body_bytes: content.plaintext.len(),
        desired_hash: content::desired_hash(&content.update)?,
        desired_bytes: content::desired_bytes(&content.update)?,
        acknowledge_unknown_operation_id: input.acknowledge_unknown_operation_id,
        body: util::encrypt_content(state, tenant, content::body_id(tenant, input.request_id), &content.plaintext)?,
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
    related.push(key(super::records::STATE, util::risk_id(tenant, scope.target.write_resource_id)));
    store::mutate(state, Mutation { submission, scope: Some(&scope), related: &related },
        |candidate, snapshot| {
            if candidate.version != input.expected_state_version || candidate.latest_observation != Some(observed.request_id) { return Err(util::stale()); }
            let risk_marker = util::read(&snapshot.related, super::records::STATE, util::risk_id(tenant, scope.target.write_resource_id))?;
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
            let audit = audit::entry(submission, input.request_id, "apig-configuration-publication-preview", AuditAction::Configure,
                json!({"targetScopeId":scope.target.target_scope_id,"writeResourceId":scope.target.write_resource_id,"contentHash":prepared.desired_hash,"contentBytes":prepared.desired_bytes,"action":action}));
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
) -> DomainResult<content::Content> {
    content::restore(state, tenant, prepared)
}
pub(super) fn record_id(tenant: TenantId, request: Id) -> Id {
    util::content_id(tenant, request, "preview")
}
