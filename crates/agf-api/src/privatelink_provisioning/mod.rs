//! Durable explicit PrivateLink consumer creation and independent provider acceptance.
mod archive;
mod audit;
mod authority;
mod claim;
mod codec;
mod completion;
mod dispatch;
mod input;
mod inventory;
mod mock;
mod model;
mod observation;
mod preview;
mod records;
mod registry;
mod routes;
mod source;
mod sql;
mod staging;
mod store;
#[cfg(test)]
mod tests;
mod util;
mod views;
pub use registry::Registry;
pub(crate) use routes::router;
pub(crate) fn source_fingerprint(value: &serde_json::Value) -> agf_core::error::DomainResult<String> {
    util::fingerprint(value)
}
const NAME: &str = "alicloud-privatelink";
const STATE: &str = "privatelink-provisioning-state";
const FACT: &str = "privatelink-provisioning-fact";
const BODY: &str = "privatelink-provisioning-body";
const REQUEST: &str = "privatelink-provisioning-request";
const PENDING: &str = "privatelink-provisioning-pending";
const RISK: &str = "privatelink-provisioning-risk";
const MOCK: &str = "privatelink-provisioning-mock";
const MAX_ITEMS: usize = 128;
const MAX_FACTS: u64 = 4096;
