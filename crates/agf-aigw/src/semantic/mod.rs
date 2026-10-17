//! Strict Stage-1 semantic eligibility, independent of the legacy exact-cache contract.
mod eligibility;
pub use eligibility::{EligibleSemanticRequest, inspect_request};
#[cfg(test)]
mod tests;
