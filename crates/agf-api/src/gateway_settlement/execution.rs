//! An admitted owned pipeline cancels transport and never starts another component after caller loss.
use super::{components::ComponentOutcome, records::*, semantic_plan::CachePlan, stage, store};
use crate::{
    AppState, Principal,
    gateway_semantic_profile::{EmbeddingPlan, PreparedSemantic},
    policy_store::AccessLease,
};
use agf_aigw::{
    AiGateway,
    gateway::{CallContext, DeferredCall, GatewayResponse, SettlementGuard},
    provider::embedding::{EmbeddingCancellation, EmbeddingFailure, EmbeddingOutcome, EmbeddingReservation},
    wire::ChatRequest,
};
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use agf_storage::semantic_response_cache::{
    Lookup, SearchVector, SemanticReadAuthority, SemanticRepository, SqlRepository,
};
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct Cancellation {
    embedding: EmbeddingCancellation,
    signal: tokio::sync::watch::Sender<bool>,
}
impl Default for Cancellation {
    fn default() -> Self {
        let (signal, _) = tokio::sync::watch::channel(false);
        Self { embedding: EmbeddingCancellation::default(), signal }
    }
}
impl Cancellation {
    pub(super) fn cancel(&self) {
        self.embedding.cancel();
        self.signal.send_replace(true);
    }
    pub(super) fn check(&self) -> DomainResult<()> {
        if *self.signal.borrow() {
            Err(DomainError::Timeout("Model caller cancelled its admitted pipeline".into()))
        } else {
            Ok(())
        }
    }
    pub(super) async fn cancelled(&self) {
        let mut receiver = self.signal.subscribe();
        loop {
            if *receiver.borrow() {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}
pub(super) struct CancelOnDrop(pub(super) Cancellation);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(super) struct Run {
    pub(super) state: AppState,
    pub(super) principal: Principal,
    pub(super) gateway: Arc<AiGateway>,
    pub(super) context: CallContext,
    pub(super) request: ChatRequest,
    pub(super) fact: Fact,
    pub(super) lease: Option<AccessLease>,
    pub(super) headers: axum::http::HeaderMap,
    pub(super) submitted_at: Timestamp,
    pub(super) semantic: Option<Arc<PreparedSemantic>>,
    pub(super) deferred: Arc<DeferredCall>,
    pub(super) guard: Arc<dyn SettlementGuard>,
    pub(super) cancellation: Cancellation,
}

pub(super) async fn run(input: Run) -> DomainResult<(GatewayResponse, agf_core::ids::Id)> {
    let mut components = input
        .fact
        .charge
        .as_ref()
        .and_then(|charge| charge.embedding.as_ref())
        .map_or_else(Vec::new, |anchor| vec![anchor.not_sent()]);
    let mut cache = None;
    let result = pipeline(&input, &mut components, &mut cache).await;
    let chats = super::chat_components::snapshot(&input.deferred)?;
    let primary = chats.first().ok_or_else(store::missing)?;
    let usage = primary.usage.clone();
    let evidence = primary.evidence;
    components.extend(chats.iter().skip(1).cloned());
    let output_limit =
        result.as_ref().is_ok_and(|row| row.screening.response_rules.iter().any(|id| id == "gateway-output-limit"));
    let blocked = result.as_ref().is_ok_and(|row| row.screening.response_blocked);
    let mut rejection = super::rejection::known(&result, super::components::dispatch_evidence(evidence, &components))
        .unwrap_or_else(|_| {
            Some(Rejection { stage: Stage::Execution, reason: Reason::Configuration, rule_ids: Vec::new() })
        });
    if input.cancellation.check().is_err() {
        rejection = Some(Rejection { stage: Stage::Execution, reason: Reason::Cancelled, rule_ids: Vec::new() });
    } else if rejection.is_none()
        && std::iter::once(evidence)
            .chain(components.iter().map(|row| row.evidence))
            .any(|row| matches!(row, Evidence::SentUsageUnknown | Evidence::SentUsagePartial))
    {
        // A successful fallback does not turn an earlier unknown paid attempt into success.
        rejection = Some(Rejection { stage: Stage::Transport, reason: Reason::Provider, rule_ids: Vec::new() });
    }
    let pending = Pending {
        attempt: input.fact.attempt,
        origin: input.fact.origin.clone(),
        outcome: KnownOutcome {
            components,
            evidence,
            usage,
            rejection,
            semantic: if !output_limit && !blocked {
                cache
                    .as_ref()
                    .and_then(|plan| result.as_ref().ok().and_then(|row| plan.result(&input.fact, &row.response).ok()))
            } else {
                None
            },
        },
    };
    // After the known result there is no transport await before its owned publication is handed off.
    let task = stage::spawn_known(
        input.state.clone(),
        input.principal.clone(),
        input.lease.clone(),
        input.submitted_at,
        input.headers.clone(),
        input.fact.clone(),
        pending,
    );
    let published = task.await.map_err(|_| DomainError::Internal("Known settlement task ended unexpectedly".into()))?;
    if published.is_err() {
        return Err(DomainError::PreconditionFailed(format!(
            "Gateway attempt {} has known pending evidence; use local recovery",
            input.fact.attempt
        )));
    }
    input.cancellation.check()?;
    input.guard.validate().await?;
    if output_limit {
        return Err(DomainError::DependencyUnavailable {
            dependency: "model-provider".into(),
            cause: "Model output exceeded its admitted output limit".into(),
        });
    }
    let response = result.map_err(|error| match error {
        DomainError::Forbidden(_) | DomainError::Unauthenticated(_) => {
            DomainError::Forbidden("Original model authority is no longer valid".into())
        }
        DomainError::Conflict(_) | DomainError::PreconditionFailed(_) => {
            DomainError::Conflict("Original model source changed".into())
        }
        DomainError::Timeout(_) => {
            DomainError::Timeout("Model pipeline exhausted its original budget or was cancelled".into())
        }
        error @ DomainError::QuotaExceeded { .. } => error,
        _ => DomainError::DependencyUnavailable {
            dependency: "model-provider".into(),
            cause: "Model pipeline failed; immutable settlement evidence retained".into(),
        },
    })?;
    if !blocked {
        if let Err(error) = input.deferred.commit_cache(&input.gateway, input.fact.usage_id).await {
            tracing::warn!(%error, "Optional committed exact-cache publication skipped");
        }
    }
    input.guard.validate().await?;
    Ok((response, input.fact.attempt))
}

async fn pipeline(
    input: &Run,
    components: &mut [ComponentOutcome],
    cache: &mut Option<CachePlan>,
) -> DomainResult<GatewayResponse> {
    input.cancellation.check()?;
    input.guard.validate().await?;
    if let Some(plan) = &input.semantic {
        // The planner reserves envelope space before any paid embedding dispatch.
        if plan.cache_plan_max_bytes == 0 || plan.cache_plan_max_bytes > 24 * 1024 {
            return Err(store::missing());
        }
        let vector = match &plan.embedding {
            EmbeddingPlan::MockVector { vector, configured_cost_micro, provider_contacted } => {
                if *configured_cost_micro != 0 || *provider_contacted || !components.is_empty() {
                    return Err(store::missing());
                }
                Some(vector.clone())
            }
            EmbeddingPlan::Live(live) => {
                let anchor = input
                    .fact
                    .charge
                    .as_ref()
                    .and_then(|charge| charge.embedding.as_ref())
                    .ok_or_else(store::missing)?;
                input.cancellation.check()?;
                input.guard.validate().await?;
                let started = tokio::time::Instant::now();
                let observed = live
                    .client
                    .embed(
                        &live.input,
                        live.input_tokens_bound,
                        EmbeddingReservation { reserved_tokens: anchor.tokens, reserved_cost_micro: anchor.cost },
                        plan.deadline,
                        &input.cancellation.embedding,
                    )
                    .await;
                let component = components.first_mut().ok_or_else(store::missing)?;
                // If internal identity validation fails after entry, retain conservative dispatch evidence.
                component.evidence = if observed.dispatch == agf_aigw::provider::embedding::EmbeddingDispatch::NotSent {
                    Evidence::NotSent
                } else {
                    Evidence::SentUsageUnknown
                };
                *component = anchor.known(
                    &input.fact,
                    &observed,
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                )?;
                match observed.outcome {
                    EmbeddingOutcome::Vector(vector) => Some(vector.values().to_vec()),
                    EmbeddingOutcome::Failed(EmbeddingFailure::UsageOverReservation) => {
                        return Err(DomainError::QuotaExceeded {
                            scope: "embedding-component".into(),
                            dimension: "tokens".into(),
                            used: i64::try_from(
                                component.usage.as_ref().map_or(anchor.tokens, |usage| usage.prompt_tokens),
                            )
                            .map_err(|_| store::missing())?,
                            limit: i64::try_from(anchor.tokens).map_err(|_| store::missing())?,
                        });
                    }
                    EmbeddingOutcome::Failed(_) => None,
                }
            }
        };
        // A paid/vector failure may retain actual usage while falling back to the original chat.
        input.cancellation.check()?;
        input.guard.validate().await?;
        if let Some(vector) = vector {
            plan.authority.revalidate(&plan.domain).await?;
            let prepared = CachePlan::capture(
                plan.evidence.clone(),
                vector.clone(),
                plan.ttl_seconds,
                plan.domain.digest().into(),
            )?;
            let repository = SqlRepository::new(
                super::authority::database(&input.state)?.db().clone(),
                plan.authority.issuer(),
                crate::model_gateway::cipher(&input.state)?,
            );
            // Equal scores remain ambiguous; the small fixed gap never picks an arbitrary tie.
            let search = SearchVector::new(vector, plan.threshold, 0.000_001)?;
            let lookup = tokio::select! {
                biased;
                () = input.cancellation.cancelled() => return Err(DomainError::Timeout("Semantic lookup cancelled".into())),
                result = tokio::time::timeout_at(plan.deadline, repository.lookup(&plan.domain, &search, &plan.authority)) => result.map_err(|_| DomainError::Timeout("Semantic lookup exhausted original budget".into()))??,
            };
            plan.authority.revalidate(&plan.domain).await?;
            input.guard.validate().await?;
            if let Lookup::Hit { response, .. } = lookup {
                let response = serde_json::from_value(response.canonical().clone())?;
                return tokio::select! {
                    biased;
                    () = input.cancellation.cancelled() => Err(DomainError::Timeout("Semantic delivery cancelled".into())),
                    result = input.gateway.chat_deferred_cached(input.context.clone(), input.request.clone(), response, &input.deferred) => result,
                };
            }
            *cache = Some(prepared);
        }
    }
    input.cancellation.check()?;
    input.guard.validate().await?;
    tokio::select! {
        biased;
        () = input.cancellation.cancelled() => Err(DomainError::Timeout("Model dispatch cancelled".into())),
        result = input.gateway.chat_deferred(input.context.clone(), input.request.clone(), &input.deferred) => result,
    }
}
