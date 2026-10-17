//! Bounded AEAD vector-response cache; legacy exact-cache rows are never consulted.
//! Domain issuance is an internal service capability, not authentication or quota settlement.
mod codec;
mod domain;
mod memory;
mod model;
mod sql;
mod vector;

pub use domain::{ConfigurationFence, DomainIssuer, ServerSemanticEvidence, TrustedSemanticDomain};
pub use memory::MemoryRepository;
pub use model::{Admission, Lookup, PlainResponse, SemanticReadAuthority, SemanticRepository};
pub use sql::SqlRepository;
pub use vector::SearchVector;

/// Maximum rows examined in one exact-domain statement snapshot.
pub const MAX_CANDIDATES: usize = 128;
/// Maximum entries per tenant, shared across every domain.
pub const MAX_ROWS: usize = 512;
/// Maximum encoded sealed storage per tenant.
pub const MAX_TENANT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum encoded sealed entry, including metadata and AEAD envelope.
pub const MAX_ENTRY_BYTES: usize = 256 * 1024;
/// Maximum entry lifetime in seconds.
pub const MAX_TTL_SECONDS: u32 = 900;

#[cfg(test)]
mod tests;
