//! Task-owned integration preview; unregistered in the product until reviewed and admitted.
mod admission;
mod agent;
mod authority;
mod background;
mod background_tenants;
mod chat_components;
mod codec;
mod components;
mod denial;
mod execution;
mod idempotency;
mod limits;
#[cfg(feature = "test-loopback-transport")]
pub(crate) mod loopback;
mod maintenance;
mod meter_coverage;
mod meter_projection;
mod records;
mod reducer;
mod rejection;
mod routes;
mod semantic;
mod semantic_plan;
mod semantic_sources;
mod source;
mod sql;
mod stage;
mod store;
mod stream;
mod workflow;

pub use background::{GatewayMaintenance, start_gateway_maintenance};
pub(crate) use denial::permission as permission_denial;
pub(crate) use idempotency::prelookup as admission_key_prelookup;
pub(crate) use routes::router;
pub(crate) use stream::{AdmittedDeliveryStream, AdmittedStream, Delivery};
#[cfg(test)]
pub(crate) use stream::{committed_for_test, controlled_for_test};
pub(crate) use workflow::{AdmittedResponse, Call, Preparation, begin, execute};
#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_fixture;
#[cfg(test)]
mod tests_security;

#[cfg(test)]
mod tests_semantic;

#[cfg(test)]
mod tests_chat_components;
#[cfg(test)]
mod tests_components;

#[cfg(test)]
mod tests_background;
