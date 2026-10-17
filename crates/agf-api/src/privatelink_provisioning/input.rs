use agf_alicloud::privatelink::provisioning::CreateEndpoint;
use agf_core::ids::Id;
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Selection {
    Create { target: CreateEndpoint },
    Accept { observation_request_id: Id },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Preview {
    pub request_id: Id,
    pub configuration_version: u64,
    pub expected_generation: u64,
    pub selection: Selection,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Apply {
    pub request_id: Id,
    pub preview_id: Id,
    pub expected_generation: u64,
    pub confirm_resources_and_cost: bool,
    pub confirm_current_role: bool,
    pub confirm_no_connectivity_proof: bool,
    #[serde(default)]
    pub confirm_live: bool,
    #[serde(default)]
    pub initialize_mock_fixture: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observe {
    pub request_id: Id,
    pub configuration_version: u64,
    pub original_create_request_id: Option<Id>,
    pub inventory_scope_id: Option<Id>,
    #[serde(default)]
    pub confirm_live: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Archive {
    pub request_id: Id,
    pub expected_generation: u64,
    pub request_ids: Vec<Id>,
}
