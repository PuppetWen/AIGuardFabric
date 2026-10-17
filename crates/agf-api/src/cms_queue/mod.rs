//! Explicit durable CMS delivery; provider acknowledgement is distinct from local publication.
mod archive;
mod audit;
mod authority;
mod codec;
mod completion;
mod dispatch;
mod enqueue;
mod input;
mod model;
mod provider;
mod records;
mod registry;
mod routes;
mod send;
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

const NAME: &str = "alicloud-cms";
const STATE: &str = "cms-queue-state";
const ITEM: &str = "cms-queue-item";
const BODY: &str = "cms-queue-body";
const ATTEMPT: &str = "cms-queue-attempt";
const REQUEST: &str = "cms-queue-request";
const PENDING: &str = "cms-queue-pending";
const MOCK: &str = "cms-queue-mock";
const MAX_ITEMS: usize = 128;
const MAX_FACTS: u64 = 4096;
const MAX_ATTEMPTS: u32 = 5;
const MAX_BODY: usize = 16 * 1024;
