//! A known safe outcome may outlive the HTTP caller. This owned task contains no provider future.
use super::{authority::Submission, codec, records::*, reducer, sql};
use crate::{Principal, policy_store::AccessLease, state::AppState};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use agf_storage::configuration::{ConditionalMutation, ConfigurationGuard, MutationDecision};

pub(super) fn spawn_known(
    state: AppState,
    principal: Principal,
    lease: Option<AccessLease>,
    submitted_at: Timestamp,
    headers: axum::http::HeaderMap,
    fact: Fact,
    pending: Pending,
) -> tokio::task::JoinHandle<DomainResult<bool>> {
    tokio::spawn(async move {
        // A bounded local publication window does not extend or grant provider execution.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(110);
        tokio::time::timeout_at(deadline, stage(&state, &fact, &pending))
            .await
            .map_err(|_| DomainError::Timeout("Known gateway result staging budget expired".into()))??;
        sql::publish_known(
            &state,
            &Submission { principal: &principal, lease: lease.as_ref(), submitted_at, deadline },
            fact.attempt,
            &headers,
        )
        .await
    })
}

pub(super) async fn stage(state: &AppState, fact: &Fact, pending: &Pending) -> DomainResult<()> {
    if fact.attempt != pending.attempt || fact.origin != pending.origin {
        return Err(corrupt());
    }
    reducer::validate(fact, pending)?;
    let tenant = fact.origin.tenant;
    let encoded = codec::encode(state, tenant, fact.attempt, PENDING, pending)?;
    state
        .configurations
        .mutate_conditional_audited::<Option<SecretMaterial>, _, _>(
            tenant,
            ConditionalMutation {
                kind: PENDING,
                id: fact.attempt,
                guard: Some(ConfigurationGuard { kind: FACT, id: fact.attempt }),
            },
            |original, current| {
                let original: SecretMaterial = serde_json::from_value(original.ok_or_else(corrupt)?)?;
                let claim: Fact = codec::decode(state, tenant, fact.attempt, FACT, &original)?;
                if claim.attempt != fact.attempt
                    || claim.origin != fact.origin
                    || claim.submitted_at != fact.submitted_at
                    || claim.execute_before != fact.execute_before
                    || claim.usage_id != fact.usage_id
                    || immutable_charge(&claim)? != immutable_charge(fact)?
                {
                    return Err(corrupt());
                }
                if let Phase::Settled { outcome_hash, .. } = &claim.phase {
                    if *outcome_hash != codec::hash(&pending.outcome)? {
                        return Err(conflict());
                    }
                    return Ok(MutationDecision::Unchanged);
                }
                if let Some(current) = current {
                    let original: Pending = codec::decode(state, tenant, fact.attempt, PENDING, current)?;
                    if original.attempt != claim.attempt
                        || original.origin != claim.origin
                        || codec::hash(&original)? != codec::hash(pending)?
                    {
                        return Err(conflict());
                    }
                    return Ok(MutationDecision::Unchanged);
                }
                *current = Some(encoded);
                Ok(MutationDecision::Write(None))
            },
            |_| Err(DomainError::Internal("Staging must not append a terminal audit".into())),
        )
        .await?;
    Ok(())
}

// Internal read-only building block, not an unauthenticated HTTP endpoint. A route must perform
// current original-subject authorization before calling it. No init, mutation, recovery or audit.
pub(super) async fn readonly_fact(
    state: &AppState,
    tenant: agf_core::ids::TenantId,
    attempt: agf_core::ids::Id,
) -> DomainResult<Option<Fact>> {
    state
        .configurations
        .get::<SecretMaterial>(tenant, FACT, attempt)
        .await?
        .map(|stored| {
            let fact: Fact = codec::decode(state, tenant, attempt, FACT, &stored)?;
            if fact.attempt != attempt || fact.origin.tenant != tenant {
                return Err(corrupt());
            }
            Ok(fact)
        })
        .transpose()
}

fn corrupt() -> DomainError {
    DomainError::Crypto("Known gateway result differs from its original authenticated claim".into())
}
fn conflict() -> DomainError {
    DomainError::Conflict("Gateway attempt already has a different known result".into())
}

fn immutable_charge(fact: &Fact) -> DomainResult<String> {
    codec::hash(&fact.charge.as_ref().map(|row| {
        (
            &row.gateway,
            &row.runtime,
            row.endpoint,
            &row.session,
            row.expires_at,
            &row.agent_safety,
            &row.embedding,
            &row.chats,
        )
    }))
}
