use super::{
    authority::Authority,
    records::{self, Envelope, Fact},
    source,
    types::{Status, StepEvidence, hash},
};
use crate::{AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    enums::{EvidenceLevel, RiskDomain, Severity},
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    risk::{Evidence, Finding},
    time::Timestamp,
};

fn database(state: &AppState) -> DomainResult<&agf_storage::Store> {
    state.store.database().map(std::sync::Arc::as_ref).ok_or_else(|| {
        DomainError::PreconditionFailed(
            "Multi-target execution requires durable SQL; preview performs no writes".into(),
        )
    })
}
pub(super) async fn get(state: &AppState, tenant: agf_core::ids::TenantId, request: Id) -> DomainResult<Option<Fact>> {
    state
        .configurations
        .get::<Envelope>(tenant, super::KIND, records::id(tenant, request))
        .await?
        .map(|envelope| records::restore(state, tenant, request, envelope))
        .transpose()
}
pub(super) async fn current(state: &AppState, tx: &AssetTransaction<'_>, fact: &Fact) -> DomainResult<Fact> {
    let envelope = tx
        .configuration::<Envelope>(super::KIND, records::id(fact.tenant, fact.request_id))
        .await?
        .ok_or_else(records::corrupt)?;
    let current = records::restore(state, fact.tenant, fact.request_id, envelope)?;
    if (current.input_sha256.as_str(), current.owner.id, current.owner.kind, current.owner.identity_tenant)
        != (fact.input_sha256.as_str(), fact.owner.id, fact.owner.kind, fact.owner.identity_tenant)
    {
        return Err(records::corrupt());
    }
    Ok(current)
}
pub(super) async fn write(state: &AppState, tx: &AssetTransaction<'_>, fact: &Fact) -> DomainResult<()> {
    let value = serde_json::to_value(records::seal(state, fact)?)?;
    if serde_json::to_vec(&value)?.len() > 80 * 1024 {
        return Err(DomainError::PreconditionFailed("Sealed run exceeds storage budget".into()));
    }
    tx.configure(super::KIND, records::id(fact.tenant, fact.request_id), Some(value)).await
}
pub(super) async fn claim(state: &AppState, authority: &Authority, fact: Fact) -> DomainResult<(Fact, bool)> {
    let tenant = fact.tenant;
    let tx = AssetTransaction::begin(database(state)?, tenant).await?;
    tx.tenant_enabled().await?;
    authority.check(state).await?;
    source::locked(&tx, tenant, &fact.targets, true).await?;
    let capacity_id = crate::model_routes::tenant_record_id(tenant);
    tx.configuration_lock(super::CAPACITY_KIND, capacity_id).await?;
    tx.configuration_lock(super::KIND, records::id(tenant, fact.request_id)).await?;
    if let Some(envelope) = tx.configuration::<Envelope>(super::KIND, records::id(tenant, fact.request_id)).await? {
        let original = records::restore(state, tenant, fact.request_id, envelope)?;
        original.owns(&authority.principal)?;
        if original.input_sha256 != fact.input_sha256 {
            return Err(DomainError::Conflict("Request UUID belongs to another immutable topology/body".into()));
        }
        return Ok((original, false));
    }
    if tx.multi_target_uuid_reserved(records::id(tenant, fact.request_id)).await? {
        return Err(DomainError::Conflict(
            "Original UUID remains reserved even if its stored body is unavailable".into(),
        ));
    }
    super::history::admit(state, &tx, &fact).await?;
    write(state, &tx, &fact).await?;
    let audit = entry(
        authority,
        &fact,
        AuditAction::Configure,
        AuditOutcome::Success,
        "Reviewed finite topology claimed; outbound evidence is not yet complete",
    );
    tx.audit(audit).await?;
    authority.check(state).await?;
    source::locked(&tx, tenant, &fact.targets, true).await?;
    tx.commit(&state.store).await?;
    Ok((fact, true))
}
/// Internal safe progress only. It confers no dispatch grant and appends no success audit.
pub(super) async fn stage(
    state: &AppState,
    original: &Fact,
    evidence: StepEvidence,
    terminal: Option<Status>,
) -> DomainResult<Fact> {
    let tx = AssetTransaction::begin(database(state)?, original.tenant).await?;
    tx.configuration_lock(super::KIND, records::id(original.tenant, original.request_id)).await?;
    let mut next = current(state, &tx, original).await?;
    if next.status != Status::Running {
        return Ok(next);
    }
    if next.evidence.len() >= 3
        || next.known_terminal.is_some()
        || usize::from(evidence.step) != next.evidence.len()
        || evidence.profile_id != next.targets[next.evidence.len()].profile_id
    {
        return Err(DomainError::Conflict("Step evidence is ordered and cannot be replaced".into()));
    }
    next.evidence.push(evidence);
    next.known_terminal = terminal;
    next.bump()?;
    write(state, &tx, &next).await?;
    tx.commit(&state.store).await?;
    Ok(next)
}
pub(super) async fn finish(
    state: &AppState,
    authority: &Authority,
    original: &Fact,
    historic: bool,
    cancel: bool,
) -> DomainResult<Fact> {
    let tx = AssetTransaction::begin(database(state)?, original.tenant).await?;
    tx.tenant_enabled().await?;
    authority.check(state).await?;
    let source_current = source::locked(&tx, original.tenant, &original.targets, !historic).await?;
    tx.configuration_lock(super::KIND, records::id(original.tenant, original.request_id)).await?;
    let mut next = current(state, &tx, original).await?;
    next.owns(&authority.principal)?;
    if next.status != Status::Running {
        return Ok(next);
    }
    let terminal = if cancel {
        Status::Cancelled
    } else if let Some(status) = next.known_terminal {
        status
    } else if historic && next.deadline_at <= Timestamp::now() {
        Status::Failed
    } else {
        return Err(DomainError::PreconditionFailed(
            "Original dispatch is still in flight; no resumption or retry is permitted".into(),
        ));
    };
    next.status = terminal;
    next.known_terminal = None;
    next.source_current = Some(source_current);
    next.finished_at = Some(Timestamp::now());
    next.bump()?;
    let outcome = if terminal == Status::Completed { AuditOutcome::Success } else { AuditOutcome::Failure };
    let mut audit = entry(
        authority,
        &next,
        AuditAction::Execute,
        outcome,
        "Actual finite playbook evidence published; raw bodies omitted",
    );
    next.audit_id = Some(audit.id);
    let findings =
        if terminal == Status::Completed && next.evidence.len() == 3 && next.evidence.iter().all(|step| step.completed)
        {
            findings(&mut next)?
        } else {
            Vec::new()
        };
    tx.publish_multi_target_findings(&findings).await?;
    write(state, &tx, &next).await?;
    audit.after = Some(next.view());
    tx.audit(audit).await?;
    authority.check(state).await?;
    source::locked(&tx, next.tenant, &next.targets, !historic).await?;
    tx.commit(&state.store).await?;
    for finding in findings {
        if state.store.hydrate_finding(&finding).is_err() {
            tracing::warn!(finding_id=%finding.id,"Committed multi-target finding projection could not refresh");
        }
    }
    Ok(next)
}
fn entry(
    authority: &Authority,
    fact: &Fact,
    action: AuditAction,
    outcome: AuditOutcome,
    note: &str,
) -> agf_core::audit::AuditLog {
    let mut entry = AppState::audit_entry(
        fact.tenant,
        action,
        outcome,
        AppState::audit_actor(&authority.principal, "redteam-multi-target"),
        AuditTarget::new("redteam-multi-target", Some(fact.request_id.to_string()), None),
        note,
    );
    entry.request_id = Some(fact.request_id.to_string());
    entry
}
fn findings(fact: &mut Fact) -> DomainResult<Vec<Finding>> {
    let mut out = Vec::new();
    for evidence in &fact.evidence {
        if evidence.protected_canary_observed != Some(true) {
            continue;
        }
        let target = &fact.targets[usize::from(evidence.step)];
        let mut finding = Finding::new(
            fact.tenant,
            RiskDomain::PromptAttack,
            Severity::High,
            format!("asset:{}", target.asset_id),
            "Cross-target protected canary observed",
            "A configured protected canary occurred in an actual bounded response; review its provenance.",
            "Enforce data/instruction separation and restrict the configured read-only reference boundary; retest with a new reviewed intent.",
        );
        finding.id = deterministic_id(
            "agf.redteam.multi-target.finding",
            &format!("{}:{}:{}", fact.tenant, fact.request_id, evidence.step),
        );
        finding.asset_id = Some(target.asset_id);
        finding.evidence_level = EvidenceLevel::Partial;
        finding.source_origin =
            if target.transport_mode == "test-loopback" { "redteam-local-fixture" } else { "redteam-observed" }.into();
        finding.evidence_refs = vec![
            format!("redteam-multi-target:{}/steps/{}", fact.request_id, evidence.step),
            format!("tenant-audit:{}", fact.audit_id.ok_or_else(records::corrupt)?),
        ];
        finding.evidence.push(Evidence::new(
            "EV-MULTI-TARGET-1",
            "bounded-response",
            "Actual request/response/relay digest and explicit protected-canary oracle; no raw content",
            hash(evidence)?,
        ));
        finding.verify_note = Some(format!(
            "Original registered profile {} version {}; local_fixture={}; current defense was not inferred",
            target.profile_id,
            target.version,
            target.transport_mode == "test-loopback"
        ));
        fact.finding_ids.push(finding.id);
        out.push(finding);
    }
    Ok(out)
}
