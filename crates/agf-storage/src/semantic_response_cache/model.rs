use super::{MAX_ENTRY_BYTES, SearchVector, TrustedSemanticDomain};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use async_trait::async_trait;
use serde_json::Value;

/// Complete canonical plain assistant response, validated before encryption and after decryption.
#[derive(Clone)]
pub struct PlainResponse(pub(super) Value);

impl std::fmt::Debug for PlainResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PlainResponse(<redacted>)")
    }
}

impl PlainResponse {
    /// Reject tools, raw provider bodies, rich output, partial finish reasons and unknown fields.
    pub fn from_canonical(value: Value, expected_model: &str) -> DomainResult<Self> {
        let invalid = || DomainError::Validation("Semantic cache requires a complete plain assistant response".into());
        let object = value.as_object().ok_or_else(invalid)?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "id" | "model" | "message" | "finish_reason" | "usage" | "raw"))
            || value["model"].as_str() != Some(expected_model)
            || value["finish_reason"] != "stop"
            || !value.get("raw").is_none_or(Value::is_null)
            || value["id"].as_str().is_none_or(|id| id.is_empty() || id.len() > 256)
            || serde_json::to_vec(&value)?.len() > MAX_ENTRY_BYTES
        {
            return Err(invalid());
        }
        let message = value["message"].as_object().ok_or_else(invalid)?;
        if message
            .keys()
            .any(|key| !matches!(key.as_str(), "role" | "content" | "tool_calls" | "tool_call_id" | "name"))
            || message.get("role").and_then(Value::as_str) != Some("assistant")
            || message.get("content").and_then(Value::as_str).is_none_or(str::is_empty)
            || !message.get("tool_call_id").is_none_or(Value::is_null)
            || !message.get("name").is_none_or(Value::is_null)
            || !message.get("tool_calls").is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
        {
            return Err(invalid());
        }
        let usage = value["usage"].as_object().ok_or_else(invalid)?;
        if usage.keys().any(|key| {
            !matches!(
                key.as_str(),
                "prompt_tokens"
                    | "completion_tokens"
                    | "cached_tokens"
                    | "cache_write_tokens"
                    | "cache_write_1h_tokens"
            )
        }) || !usage.contains_key("prompt_tokens")
            || !usage.contains_key("completion_tokens")
            || usage.values().any(|value| value.as_u64().is_none_or(|tokens| tokens > 1_000_000_000))
        {
            return Err(invalid());
        }
        Ok(Self(value))
    }
    /// Original logical reply; its historical usage must not be billed as a new chat call.
    pub const fn canonical(&self) -> &Value {
        &self.0
    }
}

/// Validated service result to be admitted. No prompt text is accepted or stored.
#[derive(Clone)]
pub struct Admission {
    pub(super) id: Id,
    pub(super) vector: Vec<f32>,
    pub(super) response: PlainResponse,
    pub(super) ttl_seconds: u32,
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Admission(<redacted>)")
    }
}

impl Admission {
    /// Explicit positive TTL up to 900 seconds, nonzero finite vector, complete plain response.
    pub fn new(vector: Vec<f32>, response: PlainResponse, ttl_seconds: u32) -> DomainResult<Self> {
        Self::from_staged_server_result(Id::new(), vector, response, ttl_seconds)
    }
    /// Preserve the cache identity of an authenticated, encrypted staged service result.
    ///
    /// This validates data only. The caller must revalidate the original actor and sources.
    ///
    /// It does not renew dispatch permission, the original deadline, or any reservation.
    pub fn from_staged_server_result(
        id: Id,
        vector: Vec<f32>,
        response: PlainResponse,
        ttl_seconds: u32,
    ) -> DomainResult<Self> {
        super::vector::validate(&vector)?;
        if id.is_nil() || ttl_seconds == 0 || ttl_seconds > super::MAX_TTL_SECONDS {
            return Err(DomainError::Validation("Semantic cache identity or TTL is invalid".into()));
        }
        let model = response.canonical()["model"]
            .as_str()
            .ok_or_else(|| DomainError::Validation("Semantic cache response model is invalid".into()))?;
        PlainResponse::from_canonical(response.canonical().clone(), model)?;
        Ok(Self { id, vector, response, ttl_seconds })
    }
    /// Cache row identity; not an authority to repeat provider requests.
    pub const fn id(&self) -> Id {
        self.id
    }
}

/// Exhaustive lookup outcome; uncertain/overbound candidate sets never become a guessed hit.
#[derive(Debug)]
pub enum Lookup {
    /// One unambiguous sufficiently similar response.
    Hit {
        /// Opaque row identity.
        id: Id,
        /// Finite similarity.
        similarity: f64,
        /// Encrypted-at-rest original response.
        response: PlainResponse,
    },
    /// No sufficiently similar response.
    Miss,
    /// Candidate set exceeded the exact search bound; no subset was selected.
    CandidateLimit,
    /// Equal or too-close scores, including conflicting answers.
    Ambiguous,
}

/// Common bounded lookup contract for SQL and ephemeral memory backends.
#[async_trait]
pub trait SemanticRepository: Send + Sync {
    /// Check trusted domain/current sources, then read one bounded candidate snapshot.
    /// Optional-cache failures are not permission to skip original request authority or budget.
    async fn lookup(
        &self,
        domain: &TrustedSemanticDomain,
        query: &SearchVector,
        authority: &dyn SemanticReadAuthority,
    ) -> DomainResult<Lookup>;
}

/// Service-owned original-call authorization/source/deadline revalidator, never an HTTP boolean.
/// It must check current authority and all `configuration_fences`, including full content.
#[async_trait]
pub trait SemanticReadAuthority: Send + Sync {
    /// Revalidate the original subject and source, without provider or budget side effects.
    async fn revalidate(&self, domain: &TrustedSemanticDomain) -> DomainResult<()>;
}
