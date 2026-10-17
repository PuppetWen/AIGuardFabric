//! Only safe, exact existing resource identities cross the public boundary.
use agf_alicloud::apig::config_driver::{ContentBinding, ModelBinding};
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
#[serde(tag = "kind", content = "binding", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Binding {
    Content(ContentBinding),
    Models(ModelBinding),
}
impl Binding {
    pub(super) fn validate(&self) -> agf_core::error::DomainResult<()> {
        match self {
            Self::Content(value) => value.validate(),
            Self::Models(value) => value.validate(),
        }
    }
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
