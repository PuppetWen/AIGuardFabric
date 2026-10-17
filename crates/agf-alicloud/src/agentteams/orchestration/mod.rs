//! Application-owned DAG definitions. These declarations never execute a task or grant a role.
use agf_core::{
    cloud::{AgentTeam, OrchestrationNode},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde::{Deserialize, Serialize};

mod mock_bridge;
mod validate;
pub use mock_bridge::{MockDefinitionBridge, MockDefinitionReceipt, MockDefinitionView, Preview};
pub use validate::{inventory_fingerprint, validate_definition};

/// Maximum nodes in one declaration.
pub const MAX_NODES: usize = 128;
/// Maximum encoded declaration bytes.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
/// Permanent request facts retained by the process-local Mock bridge.
pub const MAX_MOCK_INTENTS: usize = 128;

/// Explicit application-owned declaration, independent from vendor task observations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionDocument {
    /// Format revision; currently exactly one.
    pub schema_version: u32,
    /// Tenant providing the declaration.
    pub tenant_id: TenantId,
    /// Exact observed Team identity, not its display name.
    pub cloud_team_id: String,
    /// Fingerprint of the member/role inventory used to validate references.
    pub inventory_fingerprint: String,
    /// Declared dependencies, not inferred from traces or task timestamps.
    #[serde(deserialize_with = "validate::deserialize_nodes")]
    pub nodes: Vec<OrchestrationNode>,
}
impl DefinitionDocument {
    /// Prepare a declaration from an explicit inventory and application-owned nodes.
    #[must_use]
    pub fn from_application(team: &AgentTeam, nodes: Vec<OrchestrationNode>) -> Self {
        Self {
            schema_version: 1,
            tenant_id: team.tenant_id,
            cloud_team_id: team.cloud_team_id.clone(),
            inventory_fingerprint: inventory_fingerprint(team),
            nodes,
        }
    }
}
/// Only the explicitly isolated Mock receiver supports these synchronization directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionDirection {
    /// Adopt the current Mock receiver declaration locally.
    Pull,
    /// Publish the supplied application-owned declaration to the Mock receiver.
    Push,
    /// Resolve differences explicitly in favor of the supplied application-owned declaration.
    Both,
}
/// An immutable, user-confirmed Mock synchronization intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionIntent {
    /// Unique operation ID; reusing it with a different body is a conflict.
    pub request_id: Id,
    /// Reviewed local/receiver state version.
    pub expected_version: u64,
    /// Explicit synchronization direction.
    pub direction: DefinitionDirection,
    /// Required for push/both; forbidden for pull.
    pub definition: Option<DefinitionDocument>,
    /// Confirmation that this does not update a real vendor or application runtime.
    pub confirm_mock: bool,
}
pub(super) fn invalid() -> DomainError {
    DomainError::Validation("编排声明格式、容量或引用无效；不会执行任务或修改云端".into())
}
pub(super) fn hash<T: Serialize>(value: &T) -> DomainResult<String> {
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
