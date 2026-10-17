//! Trusted platform bundle publication to an explicitly managed Nacos target.
//!
//! A cloud write receipt never proves that an external consumer loaded or
//! enforced a bundle. Network dispatch belongs to the explicit workflow only.

mod archive;
mod audit;
mod authority;
mod bundle;
mod claim;
mod completion;
mod context;
mod contract;
mod dependencies;
mod dispatch;
mod input;
mod mock;
mod observation;
mod operations;
mod preview;
mod projection;
mod provider;
mod records;
mod recover;
mod registry;
mod risk;
mod routes;
mod scope;
mod sql;
mod store;
mod util;
mod views;

pub use registry::Registry;
pub(crate) use routes::router;

const NAME: &str = "alicloud-mse";
const DIALECT: &str = "nacos-http-v2-cas";
const MAX_POLICIES: usize = 20;
const MAX_AGENT_IDS: usize = 500;
const MAX_GUARDS: usize = 32;
const MAX_CONTENT_BYTES: usize = 256 * 1024;
const MAX_RELATED: usize = 100;

#[cfg(test)]
mod tests_foundation;
