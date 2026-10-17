//! Human annotations of immutable collector task-error evidence, with permanent local UUID facts.
//!
//! This workflow never retries a task, sends telemetry or reports an operator decision as cloud success.
mod audit;
mod authority;
mod codec;
mod evidence;
mod input;
mod model;
mod operations;
mod query;
mod reducer;
mod routes;
mod source;
mod source_proof;
mod sql;
mod store;
mod util;
mod views;

use evidence::FailureEvidence;
use input::{ArchiveInput, Decision, ResolutionInput};
use model::{Actor, ArchivePlan, Handling, Journal, RequestFact, ResolutionPlan};
#[cfg(test)]
use reducer::{archive, resolve};
pub(crate) use routes::router;
use source_proof::{ArchiveSource, SourceFingerprint, VerifiedSource};

const MAX_ACTIVE: usize = 128;
const MAX_HISTORY: usize = 20;
const MAX_ARCHIVE: usize = 99;
const MAX_SOURCE_GUARDS: usize = 31;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_archive;
#[cfg(test)]
mod tests_support;
