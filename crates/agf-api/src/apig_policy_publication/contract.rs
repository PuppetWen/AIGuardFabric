//! Safe binding metadata, distinct from the independent policy's write-resource risk.
pub(super) use crate::policy_store::PublicationDependencyEvidence as DependencyEvidence;
use agf_alicloud::apig::policy_driver::Binding;
use agf_core::ids::{Id, TenantId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TransportMode {
    Mock,
    Live,
    LoopbackTest,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ManagedBinding {
    pub target_scope_id: Id,
    pub write_resource_id: Id,
    pub configuration_id: Id,
    pub configuration_version: u64,
    pub source_label: String,
    pub region: String,
    pub endpoint: String,
    pub binding: Binding,
    pub mocked: bool,
    pub transport_mode: TransportMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    pub tenant: TenantId,
    pub target: ManagedBinding,
    pub source_identity: String,
    pub payload_fingerprint: String,
}
