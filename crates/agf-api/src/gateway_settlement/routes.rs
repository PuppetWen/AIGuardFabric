//! GET is pure. Explicit recovery publishes existing encrypted facts; there is no replay endpoint.
use super::{authority::Submission, codec, records::*, sql, stage, store};
use crate::{
    Principal,
    error::ApiResult,
    policy_store::AccessLease,
    routes::{ApiJson, parse_id},
    state::AppState,
};
use agf_core::{credential::SecretMaterial, error::DomainError, time::Timestamp};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/gateway/attempts/by-idempotency-key", get(super::idempotency::by_header))
        .route("/gateway/attempts/{id}", get(receipt))
        .route("/gateway/attempts/{id}/recover", axum::routing::post(recover))
}

async fn receipt(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> ApiResult<Json<Value>> {
    let id = parse_id(&raw, "gateway-attempt")?;
    let fact = stage::readonly_fact(&state, principal.tenant, id)
        .await?
        .ok_or(DomainError::NotFound { entity: "gateway-attempt", id: raw })?;
    let lease = AccessLease::capture(&state, &principal, &headers)?;
    crate::policy_store::AuthenticatedRejection::capture(&principal, lease.as_ref(), Timestamp::now())?
        .recheck(&state)
        .await?;
    let current = crate::soar_workflow::Actor::from_principal(&principal)?
        .resolve_for(&state, principal.tenant, "models", "read")
        .await?;
    fact.origin.matches(&current)?;
    Ok(Json(view(&state, &fact).await?))
}

async fn recover(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(raw): Path<String>,
    ApiJson(_body): ApiJson<Empty>,
) -> ApiResult<Json<Value>> {
    let id = parse_id(&raw, "gateway-attempt")?;
    let lease = AccessLease::capture(&state, &principal, &headers)?;
    let submission = Submission {
        principal: &principal,
        lease: lease.as_ref(),
        submitted_at: Timestamp::now(),
        deadline: tokio::time::Instant::now() + Duration::from_secs(110),
    };
    sql::publish_known(&state, &submission, id, &headers).await?;
    let fact = stage::readonly_fact(&state, principal.tenant, id).await?.ok_or_else(store::missing)?;
    Ok(Json(view(&state, &fact).await?))
}

pub(super) async fn view(state: &AppState, fact: &Fact) -> agf_core::error::DomainResult<Value> {
    let pending = state
        .configurations
        .get::<SecretMaterial>(fact.origin.tenant, PENDING, fact.attempt)
        .await?
        .map(|row| codec::decode::<Pending>(state, fact.origin.tenant, fact.attempt, PENDING, &row))
        .transpose()?;
    if let Some(pending) = &pending {
        super::reducer::validate(fact, pending)?;
    }
    let audit_id = if let Phase::Settled { audit_id, .. } = fact.phase { Some(audit_id) } else { None };
    let state = if audit_id.is_some() {
        "settled"
    } else if fact.charge.as_ref().is_some_and(|row| row.state == ChargeState::Conservative) {
        "conservatively-settled"
    } else if pending.is_some() {
        "pending-audit"
    } else {
        "reserved"
    };
    Ok(json!({"attemptId":fact.attempt,"usageId":fact.usage_id,"state":state,
        "originalSubmittedAt":fact.submitted_at,"originalExecuteBefore":fact.execute_before,
        "chargeState":fact.charge.as_ref().map(|row|row.state),"auditId":audit_id,
        "outcomeEvidence":pending.as_ref().map(|row|row.outcome.evidence),
        "components":pending.as_ref().map(|row|row.outcome.components.iter().map(|component|json!({"usageId":component.usage_id,"evidence":component.evidence,"costMicro":component.usage.as_ref().map(|usage|usage.cost_micro)})).collect::<Vec<_>>()),
        "outcomeHash":pending.as_ref().map(|row|codec::hash(&row.outcome)).transpose()?,
        "mayExecute":false,"recoveryAvailable":pending.is_some() && audit_id.is_none()}))
}
