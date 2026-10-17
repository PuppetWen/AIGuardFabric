//! Explicit server profile and preparation, with no provider call or paid settlement.
//! The caller reserves all components before using a prepared embedding client.
mod administration;
mod authority;
mod budget;
mod configuration;
mod endpoint;
mod mock;
mod plan;
mod routes;
mod source;
mod util;

pub(crate) use administration::{load, save};
pub(crate) use authority::Submission;
pub(crate) use configuration::{ProfileInput, ProfileView};
pub(crate) use plan::{EmbeddingPlan, LiveEmbedding, PlanResult, PreparationInput, PreparedSemantic, prepare};
pub(crate) use routes::router;

pub(crate) const KIND: &str = "semantic-cache-profile";

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_sources;

#[cfg(test)]
mod tests_embedding;
