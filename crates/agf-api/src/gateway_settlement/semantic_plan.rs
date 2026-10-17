//! Only a service-resolved, currently authorized E profile can produce this optional contribution.
use super::{codec, records::*, store};
use agf_aigw::wire::ChatResponse;
use agf_core::{enums::DataClass, error::DomainResult, ids::Id};
use agf_storage::semantic_response_cache::{
    Admission, ConfigurationFence, PlainResponse, SearchVector, ServerSemanticEvidence,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Fence {
    pub(super) kind: String,
    pub(super) id: Id,
    pub(super) version: u64,
    pub(super) witness: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Profile {
    pub(super) data_class: DataClass,
    pub(super) internal_placement_verified: bool,
    pub(super) chat_endpoint: Id,
    pub(super) chat_model: String,
    pub(super) chat_model_revision: String,
    pub(super) embedding_endpoint: Id,
    pub(super) embedding_model: String,
    pub(super) embedding_model_revision: String,
    pub(super) dimensions: u16,
    pub(super) transport_mode: String,
    pub(super) cache_configuration_version: u64,
    pub(super) fixed_request: Value,
    pub(super) fences: Vec<Fence>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct CachePlan {
    pub(super) profile: Profile,
    pub(super) vector: Vec<f32>,
    pub(super) ttl: u32,
    pub(super) domain: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct CacheResult {
    pub(super) id: Id,
    pub(super) plan: CachePlan,
    pub(super) response: Value,
    pub(super) created_ms: i64,
    pub(super) expires_ms: i64,
}

impl CachePlan {
    // Caller must already have issued the full E domain under the actual CurrentCallAuthority.
    pub(super) fn capture(
        evidence: ServerSemanticEvidence,
        vector: Vec<f32>,
        ttl: u32,
        domain: String,
    ) -> DomainResult<Self> {
        SearchVector::new(vector.clone(), 1.0, 0.0)?;
        if vector.len() != usize::from(evidence.dimensions) || !(1..=900).contains(&ttl) {
            return Err(store::missing());
        }
        let fences = evidence
            .fences
            .into_iter()
            .map(|row| {
                Ok(Fence { kind: row.kind().into(), id: row.id(), version: row.version(), witness: codec::hash(&row)? })
            })
            .collect::<DomainResult<Vec<_>>>()?;
        let plan = Self {
            profile: Profile {
                data_class: evidence.data_class,
                internal_placement_verified: evidence.internal_placement_verified,
                chat_endpoint: evidence.chat_endpoint,
                chat_model: evidence.chat_model,
                chat_model_revision: evidence.chat_model_revision,
                embedding_endpoint: evidence.embedding_endpoint,
                embedding_model: evidence.embedding_model,
                embedding_model_revision: evidence.embedding_model_revision,
                dimensions: evidence.dimensions,
                transport_mode: evidence.transport_mode,
                cache_configuration_version: evidence.cache_configuration_version,
                fixed_request: evidence.fixed_request,
                fences,
            },
            vector,
            ttl,
            domain,
        };
        // Leave room in the 64KiB encrypted settlement envelope for immutable quota anchors/usage.
        if serde_json::to_vec(&plan)?.len() > 24 * 1024 {
            return Err(store::missing());
        }
        Ok(plan)
    }
    pub(super) fn result(&self, fact: &Fact, response: &ChatResponse) -> DomainResult<CacheResult> {
        let charge = fact.charge.as_ref().ok_or_else(store::missing)?;
        if self.profile.chat_endpoint != charge.endpoint {
            return Err(store::missing());
        }
        let mut canonical = response.clone();
        canonical.raw = None;
        let response = serde_json::to_value(canonical)?;
        PlainResponse::from_canonical(response.clone(), &self.profile.chat_model)?;
        let created_ms = agf_core::time::Timestamp::now().unix_millis();
        let expires_ms = created_ms.checked_add(i64::from(self.ttl) * 1000).ok_or_else(store::missing)?;
        let result = CacheResult { id: cache_id(fact), plan: self.clone(), response, created_ms, expires_ms };
        result.validate(fact)?;
        Ok(result)
    }
}
impl CacheResult {
    pub(super) fn validate(&self, fact: &Fact) -> DomainResult<()> {
        if self.plan.domain.len() != 64
            || !self.plan.domain.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.created_ms < fact.submitted_at.unix_millis()
            || self.created_ms > fact.execute_before.unix_millis()
            || self.created_ms.checked_add(i64::from(self.plan.ttl) * 1000) != Some(self.expires_ms)
            || self.id != cache_id(fact)
            || self.plan.profile.chat_endpoint != fact.charge.as_ref().ok_or_else(store::missing)?.endpoint
            || self.plan.profile.fences.is_empty()
            || self.plan.profile.fences.len() > 32
            || serde_json::to_vec(self)?.len() > 48 * 1024
        {
            return Err(store::missing());
        }
        Admission::from_staged_server_result(
            self.id,
            self.plan.vector.clone(),
            PlainResponse::from_canonical(self.response.clone(), &self.plan.profile.chat_model)?,
            self.plan.ttl,
        )?;
        Ok(())
    }
    pub(super) fn remaining_ttl(&self, now_ms: i64) -> Option<u32> {
        let remaining = self.expires_ms.checked_sub(now_ms)? / 1000;
        u32::try_from(remaining).ok().filter(|ttl| *ttl > 0 && *ttl <= self.plan.ttl)
    }
    pub(super) fn admission(&self, ttl: u32) -> DomainResult<Admission> {
        Admission::from_staged_server_result(
            self.id,
            self.plan.vector.clone(),
            PlainResponse::from_canonical(self.response.clone(), &self.plan.profile.chat_model)?,
            ttl,
        )
    }
}
pub(super) fn cache_id(fact: &Fact) -> Id {
    agf_core::ids::deterministic_id(
        "agf.gateway-semantic-admission.v1",
        &format!("{}:{}", fact.origin.tenant, fact.attempt),
    )
}
pub(super) fn fence_matches(expected: &Fence, current: &ConfigurationFence) -> DomainResult<bool> {
    Ok(expected.kind == current.kind()
        && expected.id == current.id()
        && expected.version == current.version()
        && expected.witness == codec::hash(current)?)
}
