//! Restricted existing content-security and ModelAPI configuration updates.
//! No new plugin, arbitrary YAML, provider CAS, deployment or consumer proof is inferred.
mod client;
mod content;
mod contract;
mod evidence;
mod json;
mod models;
mod parse;
mod types;

pub use super::policy_driver::{CurrentGuard, ReadbackState, WriteOutcome};
pub use client::{observe_content, observe_models, publish_once};
pub use content::prepare_content;
pub use evidence::{restore_content, restore_models};
pub use models::prepare_models;
pub use parse::{parse_content, parse_models};
pub use types::{ContentBinding, ContentSettings, ModelBinding, ModelService, Observation, Prepared, ServicePatch};

#[cfg(test)]
mod tests;
