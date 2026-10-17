//! Durable admission lookup takes precedence over process-local successful-body replay.
mod identity;
mod lookup;
mod model;
mod reservation;
#[cfg(test)]
mod tests;

pub(super) use lookup::by_header;
pub(crate) use lookup::prelookup;
pub(super) use reservation::{append, existing};

use crate::{Principal, middleware::IdempotencyContext, state::AppState};
use agf_core::{error::DomainResult, ids::Id};
use axum::{http::HeaderMap, response::IntoResponse};

pub(super) const INDEX: &str = "gateway-admission-key-v1";
pub(super) const CAPACITY: &str = "gateway-admission-key-capacity-v1";
pub(super) const MAX_KEYS: u32 = 16_384;
const OPERATION: &str = "openai-chat-completions-v1";

/// Only middleware-authenticated bytes can become an admission binding.
pub(super) struct Binding {
    id: Id,
    namespace: String,
    input: String,
}
impl Binding {
    pub(super) fn capture(
        state: &AppState,
        principal: &Principal,
        headers: &HeaderMap,
        witness: &IdempotencyContext,
    ) -> DomainResult<Option<Self>> {
        let Some(fingerprint) = witness.gateway_fingerprint(principal)? else { return Ok(None) };
        let key = identity::header(headers)?;
        let (id, namespace) = identity::namespace(state, principal, key)?;
        let input = identity::input(state, &namespace, fingerprint)?;
        Ok(Some(Self { id, namespace, input }))
    }
}

pub(crate) struct Duplicate {
    pub(crate) attempt: Id,
    same_input: bool,
    owner: Box<super::records::Origin>,
}
impl Duplicate {
    pub(super) async fn recheck(
        &self,
        state: &AppState,
        submission: &super::authority::Submission<'_>,
    ) -> DomainResult<()> {
        let current = submission.current_models(state, &self.owner).await?;
        current.require(state, "models", "read").map_err(|error| error.error)
    }
    pub(crate) fn response(self) -> axum::response::Response {
        let message = if self.same_input {
            "This request was already admitted; read the original attempt and recover known evidence explicitly"
        } else {
            "This Idempotency-Key already belongs to different request bytes or business headers"
        };
        crate::error::ApiError::new(agf_core::error::DomainError::Conflict(message.into()))
            .with_header("x-agf-attempt-id", self.attempt.to_string())
            .into_response()
    }
}
