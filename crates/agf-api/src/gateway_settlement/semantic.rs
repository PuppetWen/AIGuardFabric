//! Cache, usage and both ledger writes borrow one transaction; SQL failure rolls all back.
use super::{
    authority::Submission,
    records::*,
    semantic_plan::{self, CacheResult},
    store,
};
use crate::{gateway_semantic::CurrentCallAuthority, state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::semantic_response_cache::{
    ConfigurationFence, SemanticReadAuthority, ServerSemanticEvidence, SqlRepository, TrustedSemanticDomain,
};
use axum::http::HeaderMap;
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Disposition {
    Absent,
    SourceChangedSkipped,
    ScopeChangedSkipped,
    ExpiredSkipped,
    Admitted { entry: Id },
}

// Keep the real original E authority through every later audit wait. An inserted row
// is still provisional until the same transaction rechecks this proof and commits.
pub(super) struct Publication {
    pub(super) disposition: Disposition,
    proof: Option<PublicationProof>,
}
struct PublicationProof {
    authority: CurrentCallAuthority,
    domain: TrustedSemanticDomain,
    state: AppState,
    tenant: agf_core::ids::TenantId,
    original_sources: Value,
    deadline: tokio::time::Instant,
}
impl Publication {
    fn skipped(disposition: Disposition) -> Self {
        Self { disposition, proof: None }
    }
    pub(super) async fn revalidate(&self) -> DomainResult<()> {
        if let Some(proof) = &self.proof {
            if !super::semantic_sources::current(&proof.state, proof.tenant, &proof.original_sources, proof.deadline)
                .await?
            {
                return Err(DomainError::Conflict(
                    "Full semantic source changed during audit; known result remains pending".into(),
                ));
            }
            proof.authority.revalidate(&proof.domain).await?;
        }
        Ok(())
    }
}

pub(super) async fn lock_fences(tx: &AssetTransaction<'_>, fact: &Fact, result: &CacheResult) -> DomainResult<bool> {
    result.validate(fact)?;
    let profile = &result.plan.profile;
    let mut ordered = profile.fences.iter().collect::<Vec<_>>();
    ordered.sort_by(|a, b| (&a.kind, a.id).cmp(&(&b.kind, b.id)));
    if ordered.windows(2).any(|pair| pair[0].kind == pair[1].kind && pair[0].id == pair[1].id) {
        return Err(store::missing());
    }
    for fence in &ordered {
        tx.configuration_lock(&fence.kind, fence.id).await?;
    }
    let mut current = true;
    for original in ordered {
        let payload = tx.configuration::<Value>(&original.kind, original.id).await?;
        if let Some(payload) = payload {
            let actual =
                ConfigurationFence::from_server_record(&original.kind, original.id, original.version, &payload)?;
            current &= semantic_plan::fence_matches(original, &actual)?;
        } else {
            current = false;
        }
    }
    // No cache permission is inferred from profile transport mode; E authority revalidates it.
    Ok(current)
}

pub(super) async fn admit(
    state: &AppState,
    tx: &AssetTransaction<'_>,
    submission: &Submission<'_>,
    headers: &HeaderMap,
    fact: &Fact,
    result: &CacheResult,
    current: bool,
) -> DomainResult<Publication> {
    result.validate(fact)?;
    if !current {
        return Ok(Publication::skipped(Disposition::SourceChangedSkipped));
    }
    let current_identity = submission.current_models(state, &fact.origin).await?;
    if current_identity.department != submission.principal.department {
        return Ok(Publication::skipped(Disposition::ScopeChangedSkipped));
    }
    let Some(ttl) = result.remaining_ttl(agf_core::time::Timestamp::now().unix_millis()) else {
        return Ok(Publication::skipped(Disposition::ExpiredSkipped));
    };
    let charge = fact.charge.as_ref().ok_or_else(store::missing)?;
    if let Some(safety) = &charge.agent_safety {
        match safety.current(state).await {
            Ok(()) => {}
            Err(DomainError::Conflict(_)) => return Ok(Publication::skipped(Disposition::ScopeChangedSkipped)),
            Err(error) => return Err(error),
        }
    }
    let agent = if charge.gateway.agent == "unassigned" {
        None
    } else {
        Some(charge.gateway.agent.parse::<Id>().map_err(|_| store::missing())?)
    };
    if let Some(id) = agent {
        let asset = state.store.asset_get_durable(fact.origin.tenant, id).await?.ok_or_else(store::missing)?;
        if asset.deleted_at.is_some() || asset.kind != agf_core::enums::AssetKind::Agent {
            return Err(store::missing());
        }
    }
    let mut authority =
        CurrentCallAuthority::capture(state, submission.principal, headers, agent, submission.deadline).await?;
    let profile = &result.plan.profile;
    let mut fences = Vec::new();
    for original in &profile.fences {
        let payload = state
            .configurations
            .get::<Value>(fact.origin.tenant, &original.kind, original.id)
            .await?
            .ok_or_else(store::missing)?;
        let fence = ConfigurationFence::from_server_record(&original.kind, original.id, original.version, &payload)?;
        if !semantic_plan::fence_matches(original, &fence)? {
            return Err(DomainError::Conflict(
                "Original semantic source changed; known settlement remains pending".into(),
            ));
        }
        fences.push(fence);
    }
    let evidence = ServerSemanticEvidence {
        tenant: fact.origin.tenant,
        identity_tenant: fact.origin.identity_tenant,
        subject_id: fact.origin.subject,
        subject_kind: fact.origin.kind.as_str().into(),
        session: fact.origin.session.clone(),
        agent_id: agent,
        department: None,
        data_class: profile.data_class,
        internal_placement_verified: profile.internal_placement_verified,
        chat_endpoint: profile.chat_endpoint,
        chat_model: profile.chat_model.clone(),
        chat_model_revision: profile.chat_model_revision.clone(),
        embedding_endpoint: profile.embedding_endpoint,
        embedding_model: profile.embedding_model.clone(),
        embedding_model_revision: profile.embedding_model_revision.clone(),
        dimensions: profile.dimensions,
        transport_mode: profile.transport_mode.clone(),
        cache_configuration_version: profile.cache_configuration_version,
        fences,
        fixed_request: profile.fixed_request.clone(),
        authority_deadline_ms: 0,
    };
    let domain = authority.issue_domain(evidence).await?;
    if domain.digest() != result.plan.domain {
        return Ok(Publication::skipped(Disposition::ScopeChangedSkipped));
    }
    let original_sources = profile.fixed_request.get("completeSources").cloned().ok_or_else(store::missing)?;
    if !super::semantic_sources::current(state, fact.origin.tenant, &original_sources, submission.deadline).await? {
        return Ok(Publication::skipped(Disposition::SourceChangedSkipped));
    }
    let database = super::authority::database(state)?.db().clone();
    let repository = SqlRepository::new(database, authority.issuer(), crate::model_gateway::cipher(state)?);
    let id = tx.admit_semantic_cache(&repository, &domain, result.admission(ttl)?).await?;
    submission.models(state, &fact.origin).await?;
    Ok(Publication {
        disposition: Disposition::Admitted { entry: id },
        proof: Some(PublicationProof {
            authority,
            domain,
            state: state.clone(),
            tenant: fact.origin.tenant,
            original_sources,
            deadline: submission.deadline,
        }),
    })
}
