use super::util;
use crate::gateway_semantic::AgentAuthorityView;
use agf_core::error::DomainResult;
use agf_storage::semantic_response_cache::ServerSemanticEvidence;
use serde_json::json;

/// C v1 CachePlan has a 24KiB bound; E fixed domain input has a 16KiB bound.
/// This pessimistic preflight is deliberately before any paid embedding dispatch.
pub(super) fn check(evidence: &ServerSemanticEvidence, agent: Option<&AgentAuthorityView>) -> DomainResult<usize> {
    // This mirrors only the encoded field footprint. It is not an Agent authorization proof.
    let agent_bytes = agent
        .map(|agent| {
            serde_json::to_vec(&json!({"id":agent.id(),"tenant":agent.tenant(),
        "kind":"agent","deletedAt":null,"dataClass":agent.data_class(),"department":agent.department()}))
        })
        .transpose()?
        .map_or(0, |bytes| bytes.len());
    let fixed_bytes = serde_json::to_vec(&evidence.fixed_request)?
        .len()
        .checked_add(agent_bytes)
        .and_then(|bytes| bytes.checked_add(128))
        .ok_or_else(util::stale)?;
    if fixed_bytes > 16 * 1024 {
        return Err(util::stale());
    }
    maximum(serde_json::to_vec(evidence)?.len(), agent_bytes, evidence.dimensions)
}
pub(super) fn maximum(evidence_bytes: usize, agent_bytes: usize, dimensions: u16) -> DomainResult<usize> {
    // Normalized finite f32 components cannot exceed this JSON scalar reserve, including commas.
    let vector_bytes = usize::from(dimensions).checked_mul(32).ok_or_else(util::stale)?;
    let bytes = evidence_bytes
        .checked_add(agent_bytes)
        .and_then(|bytes| bytes.checked_add(vector_bytes))
        .and_then(|bytes| bytes.checked_add(2048))
        .ok_or_else(util::stale)?;
    if bytes > 24 * 1024 {
        return Err(util::stale());
    }
    Ok(bytes)
}
