//! Only a server-authenticated attempt may create these facts; none are HTTP request DTOs.
use crate::{Principal, policy_store::AccessLease, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    model::UsageRecord,
    rbac::SubjectKind,
    time::Timestamp,
};
use axum::http::{HeaderMap, header};
use serde::{Deserialize, Serialize};

pub(super) const FACT: &str = "gateway-attempt-fact-v1";
pub(super) const PENDING: &str = "gateway-settlement-pending-v1";
pub(super) const GATEWAY: &str = "gateway-ledger";
pub(super) const RUNTIME: &str = "runtime-quota-ledger";
pub(super) const REJECTION: &str = "gateway-rejection-fact-v1";

// Not Deserialize and no caller-selected UUID constructor.
#[derive(Clone)]
pub(super) struct AuthenticatedAttempt {
    pub(super) id: Id,
    pub(super) origin: Origin,
    pub(super) submitted_at: Timestamp,
    pub(super) execute_before: Timestamp,
}

impl AuthenticatedAttempt {
    pub(super) fn capture(
        state: &AppState,
        principal: &Principal,
        headers: &HeaderMap,
        submitted_at: Timestamp,
        execute_before: Timestamp,
    ) -> DomainResult<Self> {
        if !valid_execution_window(submitted_at, execute_before) {
            return Err(DomainError::Validation(
                "Gateway attempt needs its bounded original server execution window".into(),
            ));
        }
        // Existing lease capture verifies original JWT subject/identity tenant/session and expiry.
        AccessLease::capture(state, principal, headers)?;
        let mut origin = Origin::capture(principal)?;
        if principal.subject_kind == SubjectKind::User {
            let raw = headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok()).ok_or_else(|| {
                DomainError::Unauthenticated("Gateway attempt lacks its original access token".into())
            })?;
            let token = agf_auth::claims::TokenIssuer::extract_bearer(raw)?;
            let claims = state.auth.issuer().verify(token)?;
            origin.token_expiry = Some(claims.exp);
            origin.issued_at_ms =
                Some(if claims.issued_at_ms > 0 { claims.issued_at_ms } else { claims.iat.saturating_mul(1000) });
        }
        Ok(Self { id: Id::new(), origin, submitted_at, execute_before })
    }

    // The quota owner calls this under the same reservation transaction, never from JSON input.
    pub(super) fn into_fact(self, charge: Option<ChargeSnapshot>) -> Fact {
        Fact {
            attempt: self.id,
            usage_id: usage_id(self.origin.tenant, self.id),
            origin: self.origin,
            submitted_at: self.submitted_at,
            execute_before: self.execute_before,
            charge,
            phase: Phase::AwaitingSettlement,
        }
    }
}

pub(super) fn valid_execution_window(submitted_at: Timestamp, execute_before: Timestamp) -> bool {
    execute_before
        .as_datetime()
        .signed_duration_since(submitted_at.as_datetime())
        .to_std()
        .is_ok_and(|window| !window.is_zero() && window <= std::time::Duration::from_secs(110))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Origin {
    pub(super) tenant: TenantId,
    pub(super) identity_tenant: TenantId,
    pub(super) subject: Id,
    pub(super) kind: SubjectKind,
    pub(super) bound_agent: Option<Id>,
    pub(super) session: Option<String>,
    pub(super) token_expiry: Option<i64>,
    pub(super) issued_at_ms: Option<i64>,
    pub(super) source_ip: Option<String>,
}

impl Origin {
    fn capture(principal: &Principal) -> DomainResult<Self> {
        let subject = principal
            .subject_id
            .filter(|id| !id.is_nil())
            .ok_or_else(|| DomainError::Unauthenticated("Gateway attempt requires an authenticated subject".into()))?;
        if principal.tenant.as_uuid().is_nil()
            || principal.identity_tenant.as_uuid().is_nil()
            || !matches!(principal.subject_kind, SubjectKind::User | SubjectKind::ApiKey)
            || principal.session_id.as_ref().is_some_and(|session| session.len() > 256)
            || principal.source_ip.as_ref().is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_err())
        {
            return Err(DomainError::Unauthenticated("Gateway attempt identity is invalid".into()));
        }
        Ok(Self {
            tenant: principal.tenant,
            identity_tenant: principal.identity_tenant,
            subject,
            kind: principal.subject_kind,
            bound_agent: principal.agent_id,
            session: principal.session_id.clone(),
            token_expiry: None,
            issued_at_ms: None,
            source_ip: principal.source_ip.clone(),
        })
    }

    pub(super) fn matches(&self, principal: &Principal) -> DomainResult<()> {
        let current = Self::capture(principal)?;
        if (self.tenant, self.identity_tenant, self.subject, self.kind, self.bound_agent)
            != (current.tenant, current.identity_tenant, current.subject, current.kind, current.bound_agent)
        {
            return Err(DomainError::Forbidden("Gateway attempt belongs to another identity or bound Agent".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ChargeSnapshot {
    #[serde(default)]
    pub(super) chats: Vec<super::chat_components::ChatAnchor>,
    #[serde(default)]
    pub(super) embedding: Option<super::components::EmbeddingAnchor>,
    pub(super) agent_safety: Option<super::agent::AgentSafety>,
    pub(super) endpoint: Id,
    pub(super) session: String,
    pub(super) gateway: crate::gateway_quota::settlement::Anchor,
    pub(super) runtime: crate::runtime_quota::settlement::Anchor,
    pub(super) gateway_charged: crate::gateway_quota::settlement::Charged,
    pub(super) runtime_charged: Vec<i64>,
    pub(super) expires_at: Timestamp,
    pub(super) state: ChargeState,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ChargeState {
    Reserved,
    Conservative,
    Actual,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Fact {
    pub(super) attempt: Id,
    pub(super) usage_id: Id,
    pub(super) origin: Origin,
    pub(super) submitted_at: Timestamp,
    pub(super) execute_before: Timestamp,
    pub(super) charge: Option<ChargeSnapshot>,
    pub(super) phase: Phase,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub(super) enum Phase {
    AwaitingSettlement,
    Settled { outcome_hash: String, audit_id: Id },
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct ActiveAttempts {
    pub(super) items: std::collections::BTreeMap<Id, Timestamp>,
}

pub(super) const ACTIVE: &str = "gateway-attempt-active-v1";
pub(super) fn usage_id(tenant: TenantId, attempt: Id) -> Id {
    agf_core::ids::deterministic_id("agf.gateway-usage.atomic.v1", &format!("{tenant}:{attempt}"))
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Evidence {
    NotSent,
    LocalReply,
    SentUsageKnown,
    SentUsagePartial,
    SentUsageUnknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Stage {
    Authorization,
    Wire,
    Agent,
    Classification,
    Containment,
    Policy,
    RequestScreen,
    Quota,
    Transport,
    ResponseScreen,
    Stream,
    Execution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Reason {
    Permission,
    InvalidInput,
    Denied,
    Quota,
    Provider,
    OutputLimit,
    Cancelled,
    Timeout,
    AuthorityChanged,
    SourceChanged,
    Configuration,
    Unavailable,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Rejection {
    pub(super) stage: Stage,
    pub(super) reason: Reason,
    pub(super) rule_ids: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct GatewayRejectionFact {
    pub(super) tenant: TenantId,
    pub(super) attempt: Id,
    pub(super) actor: Id,
    pub(super) rejection: Rejection,
    // Real audit lookup identity and authenticated outcome; never a fabricated chain position.
    pub(super) audit_id: Id,
    pub(super) outcome_hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct KnownOutcome {
    #[serde(default)]
    pub(super) components: Vec<super::components::ComponentOutcome>,
    pub(super) semantic: Option<super::semantic_plan::CacheResult>,
    pub(super) evidence: Evidence,
    pub(super) usage: Option<UsageRecord>,
    pub(super) rejection: Option<Rejection>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Pending {
    pub(super) attempt: Id,
    pub(super) origin: Origin,
    pub(super) outcome: KnownOutcome,
}
