use crate::{
    AppState, Principal,
    policy_store::{AccessLease, AuthorizedSubmission, PublicationAuthorization, authorize_publication},
};
use agf_core::{
    asset::Asset,
    enums::{AssetKind, DataClass},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_storage::semantic_response_cache::{
    ConfigurationFence, DomainIssuer, SemanticReadAuthority, ServerSemanticEvidence, TrustedSemanticDomain,
};
use async_trait::async_trait;
use axum::http::HeaderMap;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::time::Instant;

static MODELS_WRITE: PublicationAuthorization =
    PublicationAuthorization { resource: "models", action: "write", additional: &[] };

/// Actual Agent fields affecting classification and authorization; ordinary telemetry is excluded.
/// No caller DTO can deserialize or construct this view as an authorization capability.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentAuthorityView {
    id: Id,
    tenant: TenantId,
    kind: AssetKind,
    deleted_at: Option<Timestamp>,
    data_class: DataClass,
    department: Option<String>,
}

impl std::fmt::Debug for AgentAuthorityView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AgentAuthorityView(<redacted>)")
    }
}

impl AgentAuthorityView {
    pub const fn id(&self) -> Id {
        self.id
    }
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub const fn data_class(&self) -> DataClass {
        self.data_class
    }
    pub fn department(&self) -> Option<&str> {
        self.department.as_deref()
    }
    fn from_asset(asset: Asset, tenant: TenantId, id: Id) -> DomainResult<Self> {
        if asset.id != id || asset.tenant_id != tenant || asset.deleted_at.is_some() || asset.kind != AssetKind::Agent {
            return Err(stale());
        }
        Ok(Self {
            id: asset.id,
            tenant: asset.tenant_id,
            kind: asset.kind,
            deleted_at: asset.deleted_at,
            data_class: asset.data_class,
            department: asset.department,
        })
    }
    fn domain_record(&self) -> serde_json::Value {
        serde_json::json!({"id":self.id,"tenant":self.tenant,"kind":self.kind,
            "deletedAt":self.deleted_at,"dataClass":self.data_class,"department":self.department})
    }
}

/// Original authenticated request, original JWT lease and fixed deadline.
/// This type is neither a request DTO nor proof that a paid reservation has been settled.
pub struct CurrentCallAuthority {
    state: AppState,
    original: Principal,
    lease: Option<AccessLease>,
    submitted_at: Timestamp,
    deadline: Instant,
    deadline_ms: i64,
    agent_hint: Option<Id>,
    resolved_agent: Option<Id>,
    agent_authority: Option<AgentAuthorityView>,
    issuer: DomainIssuer,
    issued_domain: Option<String>,
}

impl std::fmt::Debug for CurrentCallAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CurrentCallAuthority(<redacted>)")
    }
}

impl CurrentCallAuthority {
    /// Capture from the middleware-authenticated principal and original headers before any wait.
    /// `deadline` must be the already fixed chat deadline, never a fresh timeout per stage.
    pub async fn capture(
        state: &AppState,
        principal: &Principal,
        headers: &HeaderMap,
        agent_hint: Option<Id>,
        deadline: Instant,
    ) -> DomainResult<Self> {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or_else(stale)?;
        let remaining_ms = i64::try_from(remaining.as_millis()).map_err(|_| stale())?;
        let deadline_ms = Timestamp::now().unix_millis().checked_add(remaining_ms).ok_or_else(stale)?;
        principal.require(state, "models", "write").map_err(|error| error.error)?;
        let lease = AccessLease::capture(state, principal, headers)?;
        let resolved_agent = principal.resolve_agent(agent_hint).map_err(|error| error.error)?;
        let agent_authority = Self::read_agent(state, principal.tenant, resolved_agent, deadline).await?;
        let master = base64::engine::general_purpose::STANDARD
            .decode(&state.config.security.master_key_b64)
            .map_err(|_| unavailable())?;
        if master.len() != 32 {
            return Err(unavailable());
        }
        let mut hash = Sha256::new();
        hash.update(b"agf-semantic-domain-service-key-v2\0");
        hash.update(master);
        let authority = Self {
            state: state.clone(),
            original: principal.clone(),
            lease,
            submitted_at: Timestamp::now(),
            deadline,
            deadline_ms,
            agent_hint,
            resolved_agent,
            agent_authority,
            issuer: DomainIssuer::from_server_key(hash.finalize().into())?,
            issued_domain: None,
        };
        authority.current().await?;
        Ok(authority)
    }

    /// Repository issuer, derived from the same service key without exposing that key.
    pub fn issuer(&self) -> DomainIssuer {
        self.issuer.clone()
    }

    /// Captured classification for the server planner; placement requires separate service evidence.
    /// Revalidation reads these same sensitive fields under the original deadline before dispatch.
    pub const fn agent_view(&self) -> Option<&AgentAuthorityView> {
        self.agent_authority.as_ref()
    }

    /// Bind exactly one server-resolved profile to this original call.
    ///
    /// All identity fields/deadline are replaced from the current authenticated principal.
    ///
    /// Evidence is not Deserialize: callers must provide actual complete stored witnesses,
    /// explicit cache enablement, model revisions, placement and fixed eligible parameters.
    pub async fn issue_domain(&mut self, mut evidence: ServerSemanticEvidence) -> DomainResult<TrustedSemanticDomain> {
        if self.issued_domain.is_some() {
            return Err(stale());
        }
        let current = self.current().await?;
        evidence.tenant = current.tenant;
        evidence.subject_id = current.subject_id.ok_or_else(stale)?;
        evidence.subject_kind = match current.subject_kind {
            agf_core::rbac::SubjectKind::User => "user",
            agf_core::rbac::SubjectKind::ApiKey => "api_key",
            _ => return Err(stale()),
        }
        .into();
        evidence.identity_tenant = current.identity_tenant;
        // Actor::resolve_for refreshes roles/accounts and intentionally has no JWT session field.
        // AccessLease verifies the original session; retain that session as domain identity.
        evidence.session.clone_from(&self.original.session_id);
        evidence.agent_id = self.resolved_agent;
        evidence.department.clone_from(&current.department);
        evidence.authority_deadline_ms = self.deadline_ms;
        if let Some(agent) = self.agent_view() {
            if evidence.data_class < agent.data_class {
                return Err(stale());
            }
            // Account department remains isolated above; bind hinted Agent department separately.
            // This is service metadata, never added to the provider wire messages or an audit body.
            evidence.fixed_request = serde_json::json!({"request":evidence.fixed_request,
                "agentAuthority":agent.domain_record()});
        }
        self.sources(&evidence.fences).await?;
        self.current().await?;
        let domain = self.issuer.issue(evidence)?;
        self.issued_domain = Some(domain.digest().into());
        Ok(domain)
    }

    fn check_deadline(&self) -> DomainResult<()> {
        if Instant::now() >= self.deadline || Timestamp::now().unix_millis() >= self.deadline_ms {
            return Err(stale());
        }
        Ok(())
    }

    async fn current(&self) -> DomainResult<Principal> {
        self.check_deadline()?;
        let submission = AuthorizedSubmission {
            principal: &self.original,
            submitted_at: self.submitted_at,
            lease: self.lease.as_ref(),
            authorization: &MODELS_WRITE,
        };
        let current = tokio::time::timeout_at(self.deadline, authorize_publication(&self.state, &submission))
            .await
            .map_err(|_| stale())??;
        self.check_deadline()?;
        if current.tenant != self.original.tenant
            || current.identity_tenant != self.original.identity_tenant
            || current.subject_id != self.original.subject_id
            || current.subject_kind != self.original.subject_kind
            || current.department != self.original.department
            || current.resolve_agent(self.agent_hint).map_err(|error| error.error)? != self.resolved_agent
        {
            return Err(stale());
        }
        if Self::read_agent(&self.state, self.original.tenant, self.resolved_agent, self.deadline).await?
            != self.agent_authority
        {
            return Err(stale());
        }
        self.check_deadline()?;
        Ok(current)
    }

    async fn read_agent(
        state: &AppState,
        tenant: TenantId,
        id: Option<Id>,
        deadline: Instant,
    ) -> DomainResult<Option<AgentAuthorityView>> {
        let Some(id) = id else { return Ok(None) };
        let asset = tokio::time::timeout_at(deadline, state.store.asset_get_durable(tenant, id))
            .await
            .map_err(|_| stale())??
            .ok_or_else(stale)?;
        AgentAuthorityView::from_asset(asset, tenant, id).map(Some)
    }

    async fn sources(&self, fences: &[ConfigurationFence]) -> DomainResult<()> {
        for fence in fences {
            self.check_deadline()?;
            let payload = tokio::time::timeout_at(
                self.deadline,
                self.state.configurations.get::<serde_json::Value>(self.original.tenant, fence.kind(), fence.id()),
            )
            .await
            .map_err(|_| stale())??
            .ok_or_else(stale)?;
            if !fence.matches(&payload)? {
                return Err(stale());
            }
        }
        self.check_deadline()
    }
}

#[async_trait]
impl SemanticReadAuthority for CurrentCallAuthority {
    async fn revalidate(&self, domain: &TrustedSemanticDomain) -> DomainResult<()> {
        if domain.tenant() != self.original.tenant || self.issued_domain.as_deref() != Some(domain.digest()) {
            return Err(stale());
        }
        self.current().await?;
        self.sources(domain.configuration_fences()).await?;
        self.current().await?;
        Ok(())
    }
}

fn stale() -> DomainError {
    DomainError::PreconditionFailed("Semantic cache original authority, source, or deadline changed".into())
}
fn unavailable() -> DomainError {
    DomainError::Config("Semantic cache requires a valid service master key".into())
}
