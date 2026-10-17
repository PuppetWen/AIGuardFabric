//! No handwritten authentication, ingestion ACK or usage records; helpers invoke the real router.
pub(crate) mod mcp;
mod owned;
mod platform;
mod queue;
pub(crate) mod startup;
mod subprocess;

use agf_core::error::DomainError;

fn fail(code: &str) -> DomainError {
    DomainError::Config(format!("owned zero-code acceptance: {code}"))
}
