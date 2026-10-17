//! Durable bounded chat-chain admission; all dispatches share the original execution window.
use super::{
    admission,
    authority::Submission,
    maintenance,
    records::*,
    source::{Capture, Source},
};
use crate::{Principal, policy_store::AccessLease, state::AppState, store::ModelRoutePolicy};
use agf_aigw::{
    AiGateway,
    gateway::{CallContext, DeferredCall, GatewayResponse, SettlementGuard},
    wire::ChatRequest,
};
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use axum::http::HeaderMap;
use std::{sync::Arc, time::Duration};

pub(crate) struct Preparation {
    attempt: AuthenticatedAttempt,
    lease: Option<AccessLease>,
    source: Capture,
    deadline: tokio::time::Instant,
    headers: HeaderMap,
    agent_safety: Option<super::agent::AgentSafety>,
}

pub(crate) async fn begin(
    state: &AppState,
    principal: &Principal,
    headers: &HeaderMap,
    agent: Option<agf_core::ids::Id>,
    witness: Option<&crate::middleware::IdempotencyContext>,
) -> DomainResult<Preparation> {
    let window = witness.map(|row| row.gateway_window(principal)).transpose()?.flatten();
    let (submitted_at, deadline) = original_window(window)?;
    tokio::time::timeout_at(deadline, begin_inner(state, principal, headers, submitted_at, deadline, agent))
        .await
        .map_err(|_| DomainError::Timeout("Model preparation exhausted its original execution budget".into()))?
}

pub(super) fn original_window(
    window: Option<(Timestamp, tokio::time::Instant)>,
) -> DomainResult<(Timestamp, tokio::time::Instant)> {
    let window = window.unwrap_or_else(|| (Timestamp::now(), tokio::time::Instant::now() + Duration::from_secs(110)));
    super::authority::budget(window.1)?;
    Ok(window)
}

async fn begin_inner(
    state: &AppState,
    principal: &Principal,
    headers: &HeaderMap,
    submitted_at: Timestamp,
    deadline: tokio::time::Instant,
    agent: Option<agf_core::ids::Id>,
) -> DomainResult<Preparation> {
    let attempt =
        AuthenticatedAttempt::capture(state, principal, headers, submitted_at, submitted_at.offset_secs(110))?;
    let lease = AccessLease::capture(state, principal, headers)?;
    let submission = Submission { principal, lease: lease.as_ref(), submitted_at, deadline };
    submission.models(state, &attempt.origin).await?;
    // Existing registry initialization stays at its existing owner boundary, before a provider permit.
    crate::policy_store::list(state, principal.tenant).await?;
    crate::quota_definitions::list(state, principal.tenant).await?;
    maintenance::due(state, principal.tenant).await?;
    let agent_safety = super::agent::AgentSafety::capture(state, principal.tenant, agent).await?;
    let source = Source::capture(state, principal.tenant).await?;
    Ok(Preparation { attempt, lease, source, deadline, headers: headers.clone(), agent_safety })
}

impl Preparation {
    pub(crate) async fn rejected(
        self,
        state: &AppState,
        principal: &Principal,
        error: &DomainError,
    ) -> DomainResult<agf_core::ids::Id> {
        let submission = Submission {
            principal,
            lease: self.lease.as_ref(),
            submitted_at: self.attempt.submitted_at,
            deadline: self.deadline,
        };
        let rejection = super::rejection::from_error(error, Evidence::NotSent);
        super::denial::rejected(state, &submission, self.attempt, rejection).await
    }
    pub(crate) const fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    pub(crate) fn require_request(&self, session: &str, model: &str) -> DomainResult<()> {
        super::limits::source(&self.source)?;
        super::limits::request(session, model)
    }
    pub(crate) fn require_components(count: usize) -> DomainResult<()> {
        super::limits::components(count)
    }
    pub(crate) fn raise_class(&self, hint: agf_core::enums::DataClass) -> agf_core::enums::DataClass {
        self.agent_safety.as_ref().map_or(hint, |safety| safety.raise_class(hint))
    }
}

pub(crate) struct Call {
    pub state: AppState,
    pub principal: Principal,
    pub gateway: Arc<AiGateway>,
    pub context: CallContext,
    pub request: ChatRequest,
    pub route: Option<ModelRoutePolicy>,
    pub preparation: Preparation,
    pub original_wire: Option<serde_json::Value>,
    pub idempotency: Option<crate::middleware::IdempotencyContext>,
}

pub(crate) struct AdmittedResult {
    pub(crate) attempt: agf_core::ids::Id,
    pub(crate) response: AdmittedResponse,
}
pub(crate) enum AdmittedResponse {
    Complete(Box<DomainResult<GatewayResponse>>),
    Stream(Box<DomainResult<super::stream::AdmittedStream>>),
}

pub(crate) async fn execute(input: Call) -> DomainResult<AdmittedResult> {
    let Call { state, principal, gateway, context, request, route, preparation, original_wire, idempotency } = input;
    let admission_key = idempotency
        .as_ref()
        .map(|witness| super::idempotency::Binding::capture(&state, &principal, &preparation.headers, witness))
        .transpose()?
        .flatten();
    let Preparation { attempt, lease, source, deadline, headers, agent_safety } = preparation;
    let Capture::Ready(source) = source else {
        return Err(DomainError::Config(
            "Protected gateway source exceeds durable settlement limits; no model request was started".into(),
        ));
    };
    tokio::time::timeout_at(deadline, source.current(&state))
        .await
        .map_err(|_| DomainError::Timeout("Model source verification exhausted original budget".into()))??;
    let submitted_at = attempt.submitted_at;
    let submission = Submission { principal: &principal, lease: lease.as_ref(), submitted_at, deadline };
    let (plan, chats) = super::chat_components::capture(&attempt, &context, &gateway, &request, route.as_ref())?;
    let semantic_wire = original_wire.as_ref().filter(|_| !request.stream && chats.len() == 1);
    let semantic = if let Some(original_wire) = semantic_wire {
        let prepared = crate::gateway_semantic_profile::prepare(
            &state,
            crate::gateway_semantic_profile::PreparationInput {
                principal: &principal,
                headers: &headers,
                agent_hint: context.agent_id,
                selected_chat_endpoint: plan.endpoint,
                request: &request,
                original_wire,
                client_data_class: context.data_class,
                policy_data_class: None,
                deadline,
            },
        );
        match tokio::time::timeout_at(deadline, prepared)
            .await
            .map_err(|_| DomainError::Timeout("Semantic preparation exhausted original model budget".into()))??
        {
            crate::gateway_semantic_profile::PlanResult::Prepared(plan) => Some(Arc::new(*plan)),
            crate::gateway_semantic_profile::PlanResult::Bypass(reason) => {
                tracing::debug!(?reason, "Semantic preparation bypass preserves the original chat path");
                None
            }
        }
    } else {
        None
    };
    let embedding = match semantic.as_ref().map(|plan| &plan.embedding) {
        Some(crate::gateway_semantic_profile::EmbeddingPlan::Live(live)) => {
            Some(super::components::EmbeddingAnchor::capture(&attempt, live)?)
        }
        _ => None,
    };
    let rejected_attempt = attempt.clone();
    let reserved = admission::reserve(
        &state,
        &submission,
        attempt,
        &source,
        admission::Input {
            key: admission_key.as_ref(),
            plan: &plan,
            embedding: embedding.as_ref(),
            chats: &chats,
            session: &context.session_id,
            semantic: None,
            agent_safety: agent_safety.as_ref(),
        },
    )
    .await;
    let fact = match reserved {
        Ok(fact) => fact,
        Err(error @ (DomainError::QuotaExceeded { .. } | DomainError::RateLimited(_))) => {
            // These typed refusals occur before the reservation commits. Storage/commit errors
            // are not reclassified, and this publisher never grants a provider dispatch.
            let rejection = super::rejection::from_error(&error, Evidence::NotSent);
            let id = super::denial::rejected(&state, &submission, rejected_attempt, rejection).await?;
            return Ok(AdmittedResult { attempt: id, response: AdmittedResponse::Complete(Box::new(Err(error))) });
        }
        Err(error) => return Err(error),
    };
    let fact = match fact {
        admission::Reservation::First(fact) => *fact,
        admission::Reservation::Duplicate(original) => {
            return Ok(AdmittedResult {
                attempt: original.attempt,
                response: AdmittedResponse::Complete(Box::new(Err(DomainError::Conflict(
                    "Request already admitted; read its original attempt; no model request was started".into(),
                )))),
            });
        }
    };
    let guard: Arc<dyn SettlementGuard> = Arc::new(Current {
        state: state.clone(),
        principal: principal.clone(),
        lease: lease.clone(),
        submitted_at,
        origin: fact.origin.clone(),
        agent_safety,
        source,
        deadline,
        semantic: semantic.clone(),
    });
    let admitted_id = fact.attempt;
    let deferred =
        match DeferredCall::new_chain(super::chat_components::deferred_anchors(&fact)?, deadline, guard.clone()) {
            Ok(deferred) => Arc::new(deferred),
            Err(error) => {
                return Ok(AdmittedResult {
                    attempt: admitted_id,
                    response: AdmittedResponse::Complete(Box::new(Err(error))),
                });
            }
        };
    let cancellation = super::execution::Cancellation::default();
    // Only a fully reserved attempt is owned; cancellation forbids any subsequent dispatch.
    let is_stream = request.stream;
    let run = super::execution::Run {
        state,
        principal,
        gateway,
        context,
        request,
        fact,
        lease,
        headers,
        submitted_at,
        semantic,
        deferred,
        guard,
        cancellation: cancellation.clone(),
    };
    if is_stream {
        let result = super::stream::start(run).await;
        return Ok(AdmittedResult { attempt: admitted_id, response: AdmittedResponse::Stream(Box::new(result)) });
    }
    let ticket = super::execution::CancelOnDrop(cancellation);
    let handle = tokio::spawn(super::execution::run(run));
    let result = handle
        .await
        .map_err(|_| DomainError::Internal("Owned settlement pipeline ended unexpectedly".into()))
        .and_then(|result| result.map(|(response, _)| response));
    drop(ticket);
    Ok(AdmittedResult { attempt: admitted_id, response: AdmittedResponse::Complete(Box::new(result)) })
}

struct Current {
    state: AppState,
    principal: Principal,
    lease: Option<AccessLease>,
    submitted_at: Timestamp,
    origin: Origin,
    source: Source,
    deadline: tokio::time::Instant,
    agent_safety: Option<super::agent::AgentSafety>,
    semantic: Option<Arc<crate::gateway_semantic_profile::PreparedSemantic>>,
}
#[async_trait::async_trait]
impl SettlementGuard for Current {
    async fn validate(&self) -> DomainResult<()> {
        tokio::time::timeout_at(self.deadline, async {
            let submission = Submission {
                principal: &self.principal,
                lease: self.lease.as_ref(),
                submitted_at: self.submitted_at,
                deadline: self.deadline,
            };
            let current = submission.current_models(&self.state, &self.origin).await?;
            if current.department != self.principal.department {
                return Err(DomainError::Conflict("Gateway original department scope changed".into()));
            }
            if let Some(safety) = &self.agent_safety {
                safety.current(&self.state).await?;
            }
            self.source.current(&self.state).await?;
            if let Some(plan) = &self.semantic {
                agf_storage::semantic_response_cache::SemanticReadAuthority::revalidate(&plan.authority, &plan.domain)
                    .await?;
            }
            submission.models(&self.state, &self.origin).await
        })
        .await
        .map_err(|_| DomainError::Timeout("Gateway delivery authority exhausted its original budget".into()))?
    }
}
