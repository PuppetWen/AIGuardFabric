//! Fixed service-owned permission Failure. Callers cannot supply audit fields or a tenant identity.
use super::{
    authority::{self, Submission},
    records::*,
    reducer, sql, store,
};
use crate::{Principal, policy_store::AccessLease, state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    error::DomainResult,
    time::Timestamp,
};
use axum::http::HeaderMap;
use serde_json::json;
use std::collections::BTreeMap;

pub(crate) async fn permission(
    state: &AppState,
    principal: &Principal,
    headers: &HeaderMap,
    witness: Option<&crate::middleware::IdempotencyContext>,
) -> DomainResult<agf_core::ids::Id> {
    let window = witness.map(|row| row.gateway_window(principal)).transpose()?.flatten();
    let (now, deadline) = super::workflow::original_window(window)?;
    let attempt = AuthenticatedAttempt::capture(state, principal, headers, now, now.offset_secs(110))?;
    let lease = AccessLease::capture(state, principal, headers)?;
    let submission = Submission { principal, lease: lease.as_ref(), submitted_at: now, deadline };
    rejected(
        state,
        &submission,
        attempt,
        Rejection { stage: Stage::Authorization, reason: Reason::Permission, rule_ids: Vec::new() },
    )
    .await
}

pub(super) async fn rejected(
    state: &AppState,
    submission: &Submission<'_>,
    attempt: AuthenticatedAttempt,
    rejection: Rejection,
) -> DomainResult<agf_core::ids::Id> {
    let fact = attempt.into_fact(None);
    let id = fact.attempt;
    let pending = Pending {
        attempt: fact.attempt,
        origin: fact.origin.clone(),
        outcome: KnownOutcome {
            components: Vec::new(),
            semantic: None,
            evidence: Evidence::NotSent,
            usage: None,
            rejection: Some(rejection),
        },
    };
    tokio::time::timeout_at(submission.deadline, transaction(state, submission, fact, pending)).await.map_err(
        |_| agf_core::error::DomainError::Timeout("Authenticated permission failure publication timed out".into()),
    )??;
    Ok(id)
}

async fn transaction(state: &AppState, submission: &Submission<'_>, fact: Fact, pending: Pending) -> DomainResult<()> {
    let tenant = fact.origin.tenant;
    let id = fact.attempt;
    let tx = AssetTransaction::begin(authority::database(state)?, tenant).await?;
    tx.tenant_enabled().await?;
    submission.failure(state, &fact.origin).await?;
    for kind in [FACT, PENDING, REJECTION] {
        if store::read(&tx, kind, id).await?.is_some() {
            return Err(store::missing());
        }
    }
    let reducer::Decision::Write(candidate) =
        reducer::reduce(&fact, &pending, None, None, Timestamp::now().unix_secs())?
    else {
        return Err(store::missing());
    };
    let audit_id = reducer::audit_id(&fact);
    let hash = super::codec::hash(&pending.outcome)?;
    let writes = BTreeMap::from([
        ((FACT, id), store::encoded(state, tenant, id, FACT, &candidate.fact)?),
        ((PENDING, id), store::encoded(state, tenant, id, PENDING, &pending)?),
        (
            (REJECTION, id),
            serde_json::to_value(GatewayRejectionFact {
                tenant,
                attempt: id,
                actor: fact.origin.subject,
                rejection: pending.outcome.rejection.clone().ok_or_else(store::missing)?,
                audit_id,
                outcome_hash: hash.clone(),
            })?,
        ),
    ]);
    let mut audit = AppState::audit_entry(
        tenant,
        AuditAction::Execute,
        AuditOutcome::Failure,
        AppState::audit_actor(submission.principal, "gateway-authenticated-rejection"),
        AuditTarget::new("gateway-attempt", Some(id.to_string()), None),
        "",
    );
    audit.id = audit_id;
    audit.request_id = Some(id.to_string());
    audit.after = Some(json!({"attemptId":id,"outcomeHash":hash,"rejection":pending.outcome.rejection}));
    sql::budget(tenant, &writes, &audit)?;
    for ((kind, id), value) in writes {
        tx.configure(kind, id, Some(value)).await?;
    }
    tx.audit(audit).await?;
    submission.failure(state, &fact.origin).await?;
    tx.commit(&state.store).await
}
