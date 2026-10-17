//! Explicit one-attempt embedding transport. No cache, authority or settlement is implemented here.
//! The caller must retain its original reservation if this future is dropped after dispatch.
mod cancellation;
mod client;
mod profile;
mod wire;

pub use cancellation::EmbeddingCancellation;
pub use client::EmbeddingClient;
pub use profile::{EmbeddingConfiguration, EmbeddingProfile, EmbeddingReservation};
pub use wire::{EmbeddingUsage, ValidatedEmbedding};

use agf_core::ids::{Id, TenantId};

pub(crate) const MAX_INPUT_BYTES: usize = 8 * 1024;
pub(crate) const MAX_REQUEST_BYTES: usize = 16 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_REPORTED_TOKENS: u64 = 1_000_000;

/// Safe fixed categories. Never hold the provider body, arbitrary headers, URL or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingFailure {
    Configuration,
    Credentials,
    EmptyInput,
    InputLimit,
    Budget,
    Cancelled,
    Deadline,
    Transport,
    Redirect,
    HttpStatus(u16),
    ResponseEncoding,
    ResponseType,
    ResponseLimit,
    MalformedResponse,
    InvalidUsage,
    UsageOverReservation,
    InvalidModel,
    InvalidVector,
}

/// Possibly sent is conservative; it never proves a remote call did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingDispatch {
    NotSent,
    PossiblySent,
    ResponseReceived,
}

#[derive(Debug)]
pub enum EmbeddingOutcome {
    Vector(ValidatedEmbedding),
    Failed(EmbeddingFailure),
}

/// A separate paid component. There is deliberately no aggregate cache-hit flag.
/// Configured cost is the server's price calculation, not a verified vendor invoice.
#[derive(Debug)]
pub struct EmbeddingAttempt {
    pub tenant_id: TenantId,
    pub endpoint_id: Id,
    pub configuration_version: u64,
    pub provider: String,
    pub model: String,
    pub model_revision: String,
    pub dispatch: EmbeddingDispatch,
    pub outcome: EmbeddingOutcome,
    pub usage: Option<EmbeddingUsage>,
    pub configured_cost_micro: Option<u64>,
    pub reservation: EmbeddingReservation,
}

impl EmbeddingAttempt {
    pub(crate) fn failed(
        profile: &EmbeddingProfile,
        reservation: EmbeddingReservation,
        dispatch: EmbeddingDispatch,
        failure: EmbeddingFailure,
        usage: Option<EmbeddingUsage>,
    ) -> Self {
        let configured_cost_micro = usage.map(|usage| profile.cost_for(usage.total_tokens));
        Self {
            tenant_id: profile.configuration.tenant_id,
            endpoint_id: profile.configuration.endpoint_id,
            configuration_version: profile.configuration.configuration_version,
            provider: profile.configuration.provider.clone(),
            model: profile.configuration.model.clone(),
            model_revision: profile.configuration.model_revision.clone(),
            dispatch,
            outcome: EmbeddingOutcome::Failed(failure),
            usage,
            configured_cost_micro,
            reservation,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod test_server;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests_profile;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests_response;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests_transport;
