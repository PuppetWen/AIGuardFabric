//! Service credentials never enter callback payloads, durable metadata or diagnostics.
pub(crate) mod artifacts;
mod client;
mod identity;
mod types;
pub(crate) use client::Client;
pub(crate) use identity::{Identity, Kind, positive_id, valid_execution};
pub(crate) use types::Receipt;

#[cfg(test)]
pub(crate) mod test_platform;
#[cfg(test)]
mod tests;
