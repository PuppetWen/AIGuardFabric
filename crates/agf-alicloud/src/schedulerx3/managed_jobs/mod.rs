//! Restricted Scheduler job changes; this driver alone grants no workflow authority.
//!
//! Existing HTTP jobs use one write followed by separate readback. Live HTTP creation is
//! deliberately unavailable until its carrier wire contract is known. Durable intent,
//! original JWT, binding/source locks and staged audit publication belong to the API owner.

mod dispatch;
mod plan;
mod readback;
mod types;
mod validate;

pub use dispatch::dispatch_once;
pub use plan::{PreparedChange, prepare};
pub use readback::{Readback, compare_readback};
pub use types::{Change, Kind, MockDeclaration, SchedulePatch, Selection, WriteEvidence, WriteStatus};

#[cfg(test)]
mod tests;
