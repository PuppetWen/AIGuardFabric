use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Kind {
    AgentHttp,
    McpHttp,
}
impl Kind {
    pub(super) const fn registry(self) -> &'static str {
        match self {
            Self::AgentHttp => "redteam-agent-targets",
            Self::McpHttp => "redteam-mcp-targets",
        }
    }
    pub(super) const fn asset(self) -> agf_core::enums::AssetKind {
        match self {
            Self::AgentHttp => agf_core::enums::AssetKind::Agent,
            Self::McpHttp => agf_core::enums::AssetKind::McpServer,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    pub kind: Kind,
    pub profile_id: Id,
    pub expected_version: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreviewInput {
    pub targets: Vec<Selection>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecuteInput {
    pub request_id: Id,
    pub targets: Vec<Selection>,
    pub reviewed_topology_sha256: String,
    pub confirm_registered_targets: bool,
    pub confirm_live: bool,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Empty {}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Target {
    pub kind: Kind,
    pub profile_id: Id,
    pub version: u64,
    pub asset_id: Id,
    pub profile_sha256: String,
    pub registry_sha256: String,
    pub transport_mode: String,
    #[serde(default)]
    pub managed_profile_version: Option<u64>,
    #[serde(default)]
    pub managed_profile_sha256: Option<String>,
    #[serde(default)]
    pub mcp_protocol_revision: Option<super::mcp::Revision>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Running,
    Completed,
    Failed,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StepEvidence {
    pub step: u8,
    pub profile_id: Id,
    pub request_sha256: Option<String>,
    pub response_sha256: Option<String>,
    pub relay_sha256: Option<String>,
    pub response_bytes: Option<usize>,
    #[serde(default)]
    pub transport_proof_sha256: Option<String>,
    pub completed: bool,
    pub protected_canary_observed: Option<bool>,
    pub dispatch: String,
    pub reason: Option<String>,
}
pub(super) fn validate(targets: &[Selection]) -> DomainResult<()> {
    if targets.len() != 3
        || targets[0].kind != Kind::AgentHttp
        || targets[1].kind != Kind::McpHttp
        || targets[2].kind != Kind::AgentHttp
        || targets.iter().any(|t| t.profile_id.is_nil() || t.expected_version == 0)
        || targets.iter().map(|t| t.profile_id).collect::<std::collections::BTreeSet<_>>().len() != 3
    {
        return Err(DomainError::Validation(
            "Select distinct current Agent A, MCP and Agent B profiles with positive versions".into(),
        ));
    }
    Ok(())
}
pub(super) fn hash(value: &impl Serialize) -> DomainResult<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}
pub(super) fn topology(targets: &[Target]) -> DomainResult<Value> {
    let value = json!({"version":super::VERSION,"playbook":super::execution::playbook_view()?,"targets":targets,"steps":[
        {"step":0,"kind":"agent-public-reference","from":null,"to":0},
        {"step":1,"kind":"mcp-readonly-context","from":0,"to":1},
        {"step":2,"kind":"agent-untrusted-context-summary","from":1,"to":2}],
        "edges":[{"from":0,"to":1,"evidence":"sanitized-reference-sha256"},
            {"from":1,"to":2,"evidence":"sanitized-untrusted-context-sha256"}],
        "rawBodiesStored":false,"externalDefenseVerified":false});
    Ok(json!({"topology":value,"topologySha256":hash(&value)?,"requiresDatabase":true}))
}
