//! Safe target and dependency metadata. No credential or raw content belongs here.
pub(super) use crate::policy_store::PublicationDependencyEvidence as DependencyEvidence;
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
    pub configuration_id: Id,
    pub configuration_version: u64,
    pub source_label: String,
    pub region: String,
    pub instance_id: String,
    pub engine_origin: String,
    pub namespace_id: String,
    pub group: String,
    pub data_id: String,
    pub dialect: String,
    pub mocked: bool,
    pub transport_mode: TransportMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    pub tenant: TenantId,
    pub target: ManagedBinding,
    pub source_identity: String,
}

/// Configuration versions fence operations; this tuple identifies rollback content.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BundleTarget {
    pub configuration_id: Id,
    pub region: String,
    pub instance_id: String,
    pub engine_origin: String,
    pub namespace_id: String,
    pub group: String,
    pub data_id: String,
    pub dialect: String,
    pub transport_mode: TransportMode,
}

impl From<&ManagedBinding> for BundleTarget {
    fn from(target: &ManagedBinding) -> Self {
        Self {
            configuration_id: target.configuration_id,
            region: target.region.clone(),
            instance_id: target.instance_id.clone(),
            engine_origin: target.engine_origin.clone(),
            namespace_id: target.namespace_id.clone(),
            group: target.group.clone(),
            data_id: target.data_id.clone(),
            dialect: target.dialect.clone(),
            transport_mode: target.transport_mode,
        }
    }
}
