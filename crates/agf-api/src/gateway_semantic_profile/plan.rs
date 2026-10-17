use super::{
    KIND, budget,
    configuration::{Mode, Settings, StoredProfile, configured_cost},
    endpoint, mock,
    source::{self, Capture, Source},
    util,
};
use crate::{AppState, Principal, gateway_semantic::CurrentCallAuthority, model_gateway::StoredEndpoint};
use agf_aigw::{
    ChatRequest,
    provider::embedding::{EmbeddingClient, EmbeddingConfiguration},
    semantic::inspect_request,
};
use agf_core::{
    enums::DataClass,
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::configuration::BoundedConfigurationList;
use agf_storage::semantic_response_cache::{
    DomainIssuer, SemanticReadAuthority, ServerSemanticEvidence, TrustedSemanticDomain,
};
use async_trait::async_trait;
use axum::http::HeaderMap;
use serde_json::{Value, json};
use tokio::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BypassReason {
    Disabled,
    ProfileUnavailable,
    SourceBound,
    Classification,
    Ineligible,
    RouteChanged,
    TransportMode,
}
pub(crate) enum PlanResult {
    Bypass(BypassReason),
    Prepared(Box<PreparedSemantic>),
}

/// Service-resolved route and original wire; this is never a client request DTO.
pub(crate) struct PreparationInput<'a> {
    pub(crate) principal: &'a Principal,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) agent_hint: Option<Id>,
    pub(crate) selected_chat_endpoint: Id,
    pub(crate) request: &'a ChatRequest,
    pub(crate) original_wire: &'a Value,
    pub(crate) client_data_class: DataClass,
    /// Actual trusted policy/scanner result may only raise the profile and Agent floor.
    pub(crate) policy_data_class: Option<DataClass>,
    pub(crate) deadline: Instant,
}

/// Prepared client is inert until C commits its chat+embedding reservation and usage identity.
pub(crate) struct LiveEmbedding {
    pub(crate) configuration: EmbeddingConfiguration,
    pub(crate) client: EmbeddingClient,
    pub(crate) input: String,
    pub(crate) input_tokens_bound: u64,
    pub(crate) estimated_cost_micro: u64,
}
pub(crate) enum EmbeddingPlan {
    Live(Box<LiveEmbedding>),
    MockVector { vector: Vec<f32>, configured_cost_micro: u64, provider_contacted: bool },
}
impl std::fmt::Debug for EmbeddingPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EmbeddingPlan(<redacted>)")
    }
}

pub(crate) struct PreparedSemantic {
    pub(crate) authority: CompleteAuthority,
    pub(crate) domain: TrustedSemanticDomain,
    /// Original service evidence, before E replaces identity and appends actual Agent evidence.
    /// C may repeat the approved issuance procedure after authenticating its sealed package.
    pub(crate) evidence: ServerSemanticEvidence,
    pub(crate) embedding: EmbeddingPlan,
    pub(crate) threshold: f64,
    pub(crate) ttl_seconds: u32,
    pub(crate) cache_plan_max_bytes: usize,
    pub(crate) deadline: Instant,
}
impl std::fmt::Debug for PreparedSemantic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedSemantic(<redacted>)")
    }
}

/// The full collection guard complements E's original identity/lease and actual-record guards.
/// Reads and independent stores do not establish linearization against arbitrary new writers.
pub(crate) struct CompleteAuthority {
    state: AppState,
    call: CurrentCallAuthority,
    source: Source,
    deadline: Instant,
}
impl CompleteAuthority {
    pub(crate) fn issuer(&self) -> DomainIssuer {
        self.call.issuer()
    }
}
#[async_trait]
impl SemanticReadAuthority for CompleteAuthority {
    async fn revalidate(&self, domain: &TrustedSemanticDomain) -> DomainResult<()> {
        self.source.current(&self.state, self.deadline).await?;
        self.call.revalidate(domain).await?;
        self.source.current(&self.state, self.deadline).await?;
        self.call.revalidate(domain).await?;
        source::check_deadline(self.deadline)
    }
}

/// Prepare only. No network, Meter entry, Usage row, quota reserve or cache lookup occurs here.
pub(crate) async fn prepare(state: &AppState, input: PreparationInput<'_>) -> DomainResult<PlanResult> {
    let mut call =
        CurrentCallAuthority::capture(state, input.principal, input.headers, input.agent_hint, input.deadline).await?;
    let profiles = tokio::time::timeout_at(
        input.deadline,
        state.configurations.list_bounded::<Value>(input.principal.tenant, KIND, 1, 16 * 1024),
    )
    .await
    .map_err(|_| util::stale())??;
    let BoundedConfigurationList::Complete(profiles) = profiles else {
        return Ok(PlanResult::Bypass(BypassReason::ProfileUnavailable));
    };
    let Some(profile) = profiles.first() else {
        return Ok(PlanResult::Bypass(BypassReason::Disabled));
    };
    let initial: StoredProfile = serde_json::from_value(profile.clone()).map_err(|_| util::corrupt())?;
    initial.validate(input.principal.tenant)?;
    if !initial.enabled {
        return Ok(PlanResult::Bypass(BypassReason::Disabled));
    }
    let source = match Source::capture(state, input.principal.tenant, input.deadline).await? {
        Capture::Complete(source) => *source,
        Capture::TooMany | Capture::TooLarge => return Ok(PlanResult::Bypass(BypassReason::SourceBound)),
    };
    let Some(raw) = source.get(KIND, util::record_id(input.principal.tenant)) else {
        return Ok(PlanResult::Bypass(BypassReason::Disabled));
    };
    if raw != profile {
        return Err(util::stale());
    }
    let row: StoredProfile = serde_json::from_value(raw.clone()).map_err(|_| util::corrupt())?;
    row.validate(input.principal.tenant)?;
    if !row.enabled {
        return Ok(PlanResult::Bypass(BypassReason::Disabled));
    }
    let settings = row.settings.as_ref().ok_or_else(util::corrupt)?;
    if input.selected_chat_endpoint != settings.chat_endpoint_id || input.request.model != settings.chat_model {
        return Ok(PlanResult::Bypass(BypassReason::RouteChanged));
    }
    if state.config.mock_mode && settings.mode == Mode::Live {
        return Ok(PlanResult::Bypass(BypassReason::TransportMode));
    }
    let agent_class = call.agent_view().map(crate::gateway_semantic::AgentAuthorityView::data_class);
    let Some(data_class) = classify(settings, agent_class, input.client_data_class, input.policy_data_class) else {
        return Ok(PlanResult::Bypass(BypassReason::Classification));
    };
    let placement = settings.mode == Mode::MockVector;
    let Some(eligible) = inspect_request(input.request, input.original_wire, data_class, placement) else {
        return Ok(PlanResult::Bypass(BypassReason::Ineligible));
    };
    let parse = |id| -> DomainResult<StoredEndpoint> {
        serde_json::from_value(source.get(crate::model_gateway::ENDPOINT_KIND, id).cloned().ok_or_else(util::stale)?)
            .map_err(Into::into)
    };
    let chat = match parse(settings.chat_endpoint_id) {
        Ok(row) => row,
        Err(_) => return Ok(PlanResult::Bypass(BypassReason::ProfileUnavailable)),
    };
    let embedding = match parse(settings.embedding_endpoint_id) {
        Ok(row) => row,
        Err(_) => return Ok(PlanResult::Bypass(BypassReason::ProfileUnavailable)),
    };
    if endpoint::validate(state, input.principal.tenant, settings, &chat, &embedding).is_err() {
        return Ok(PlanResult::Bypass(BypassReason::ProfileUnavailable));
    }
    if !chat.endpoint.accepts_data_class(data_class) || !embedding.endpoint.accepts_data_class(data_class) {
        return Ok(PlanResult::Bypass(BypassReason::Classification));
    }
    let fences = match source.fences() {
        Ok(fences) => fences,
        Err(_) => return Ok(PlanResult::Bypass(BypassReason::SourceBound)),
    };
    let embedding_plan =
        match embedding_plan(state, input.principal.tenant, settings, &embedding, eligible.user_text())? {
            EmbeddingPreparation::Ready(plan) => plan,
            EmbeddingPreparation::Unavailable => return Ok(PlanResult::Bypass(BypassReason::ProfileUnavailable)),
        };
    source.current(state, input.deadline).await?;
    let evidence = ServerSemanticEvidence {
        tenant: input.principal.tenant,
        subject_id: input.principal.subject_id.ok_or_else(util::stale)?,
        subject_kind: String::new(),
        identity_tenant: input.principal.identity_tenant,
        session: None,
        agent_id: None,
        department: None,
        data_class,
        internal_placement_verified: placement,
        chat_endpoint: settings.chat_endpoint_id,
        chat_model: settings.chat_model.clone(),
        chat_model_revision: settings.chat_model_revision.clone(),
        embedding_endpoint: settings.embedding_endpoint_id,
        embedding_model: settings.embedding_model.clone(),
        embedding_model_revision: if placement {
            format!("mock-word-features-v1:{}", settings.embedding_model_revision)
        } else {
            settings.embedding_model_revision.clone()
        },
        dimensions: settings.dimensions,
        transport_mode: if placement {
            "mock"
        } else {
            endpoint::transport_mode(state, input.principal.tenant, &embedding)
        }
        .into(),
        cache_configuration_version: row.version,
        fences,
        fixed_request: json!({"request":eligible.fixed_request(),"completeSources":source.metadata(),
            "classificationFloor":settings.classification_floor,"profileMode":settings.mode}),
        authority_deadline_ms: 0,
    };
    let cache_plan_max_bytes = match budget::check(&evidence, call.agent_view()) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(PlanResult::Bypass(BypassReason::SourceBound)),
    };
    let domain = call.issue_domain(evidence.clone()).await?;
    let authority = CompleteAuthority { state: state.clone(), call, source, deadline: input.deadline };
    authority.revalidate(&domain).await?;
    Ok(PlanResult::Prepared(Box::new(PreparedSemantic {
        authority,
        domain,
        evidence,
        embedding: embedding_plan,
        threshold: settings.threshold(),
        ttl_seconds: settings.ttl_seconds,
        cache_plan_max_bytes,
        deadline: input.deadline,
    })))
}

pub(super) fn classify(
    settings: &Settings,
    agent: Option<DataClass>,
    client: DataClass,
    policy: Option<DataClass>,
) -> Option<DataClass> {
    let floor = settings.classification_floor.max(agent.unwrap_or(DataClass::Internal));
    let class = floor.max(client).max(policy.unwrap_or(DataClass::Public));
    if matches!(class, DataClass::Confidential | DataClass::Restricted)
        || settings.mode == Mode::Live && (agent != Some(DataClass::Public) || class != DataClass::Public)
    {
        return None;
    }
    Some(class)
}
pub(super) enum EmbeddingPreparation {
    Unavailable,
    Ready(EmbeddingPlan),
}

pub(super) fn embedding_plan(
    state: &AppState,
    tenant: agf_core::ids::TenantId,
    settings: &Settings,
    row: &StoredEndpoint,
    text: &str,
) -> DomainResult<EmbeddingPreparation> {
    if settings.mode == Mode::MockVector {
        let vector = match mock::vector(text, settings.dimensions) {
            Ok(vector) => vector,
            Err(DomainError::Validation(_)) => return Ok(EmbeddingPreparation::Unavailable),
            Err(error) => return Err(error),
        };
        return Ok(EmbeddingPreparation::Ready(EmbeddingPlan::MockVector {
            vector,
            configured_cost_micro: 0,
            provider_contacted: false,
        }));
    }
    // Reserve the configured maximum; byte length is only a local request-size limit.
    // No tokenizer estimate proves a vendor's usage. Usage above this ceiling stays unknown/held.
    let bound = u64::from(settings.max_input_tokens);
    if text.is_empty() || text.len() > usize::try_from(bound).map_err(|_| util::stale())? {
        return Ok(EmbeddingPreparation::Unavailable);
    }
    let endpoint::ClientPreparation::Ready(client) = endpoint::client(state, tenant, settings, row)? else {
        return Ok(EmbeddingPreparation::Unavailable);
    };
    let (configuration, client) = *client;
    Ok(EmbeddingPreparation::Ready(EmbeddingPlan::Live(Box::new(LiveEmbedding {
        configuration,
        client,
        input: text.into(),
        input_tokens_bound: bound,
        estimated_cost_micro: configured_cost(bound, settings.embedding_micro_per_1k).ok_or_else(util::stale)?,
    }))))
}
