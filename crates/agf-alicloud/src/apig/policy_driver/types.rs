use agf_core::error::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Exact existing-resource identities; this contains no credentials.
/// The API workflow must additionally bind tenant, source, region, mode and config version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Binding {
    /// Model API identity (`GetHttpApi.type` must be `LLM`).
    pub http_api_id: String,
    /// Selected deployment gateway identity.
    pub gateway_id: String,
    /// Selected deployment environment identity.
    pub environment_id: String,
    /// Existing independent AiTokenRateLimit policy identity.
    pub policy_id: String,
    /// Exact existing attachment referenced by the selected deployment.
    pub attachment_id: String,
}

impl Binding {
    /// Reject path separators, control characters and implicit identifier normalization.
    ///
    /// # Errors
    /// A resource identity is empty, too long, or not safe as an exact path value.
    pub fn validate(&self) -> DomainResult<()> {
        for id in [&self.http_api_id, &self.gateway_id, &self.environment_id, &self.policy_id, &self.attachment_id] {
            if id.is_empty()
                || id.len() > 256
                || id.trim() != id
                || id.chars().any(char::is_control)
                || id.contains(['/', '\\'])
                || matches!(id.as_str(), "." | "..")
            {
                return Err(DomainError::Validation("APIG resource identity is invalid".into()));
            }
        }
        Ok(())
    }
}

/// A single existing global rule owned by this restricted publication profile.
/// Neither mode equates the provider's counting period with the platform UTC bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedLimit {
    /// API-global requests per provider minute.
    RequestPerMinute,
    /// API-global tokens per provider minute.
    TokenPerMinute,
}

impl ManagedLimit {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::RequestPerMinute => "RequestPerMinute",
            Self::TokenPerMinute => "TokenPerMinute",
        }
    }
}

/// Complete bounded control-plane evidence, with raw configuration excluded from Debug.
#[derive(Clone)]
pub struct Observation {
    pub(super) binding: Binding,
    pub(super) policy: Value,
    pub(super) config: Value,
    pub(super) attachment: Value,
    pub(super) digest: String,
    pub(super) evidence: Value,
}

impl Observation {
    /// Exact target identities validated against all three provider reads.
    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    /// Canonical comparison fingerprint; not an ETag, provider revision, or CAS token.
    pub fn fingerprint(&self) -> &str {
        &self.digest
    }

    /// Safe canonical config hash for preview DTOs; never a provider CAS token.
    pub fn config_hash(&self) -> String {
        super::json::fingerprint(&self.config)
    }

    /// Export the complete three-response evidence for authenticated encrypted persistence.
    /// This includes raw configuration: never expose it in public DTOs, Debug, or audit logs.
    /// Reconstruct with `restore_evidence`, which reruns the same identity and config validation.
    pub fn exported_evidence(&self) -> Value {
        self.evidence.clone()
    }
}

impl fmt::Debug for Observation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observation")
            .field("binding", &self.binding)
            .field("fingerprint", &self.digest)
            .field("configuration", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Prepared full configuration with exactly one managed limit value changed.
/// The enclosing workflow must authenticate its stored baseline and source-policy versions.
#[derive(Clone)]
pub struct PreparedUpdate {
    pub(super) baseline: Observation,
    pub(super) desired: Value,
    pub(super) mode: ManagedLimit,
    pub(super) limit: u32,
}

impl PreparedUpdate {
    /// Exact baseline fingerprint to compare again immediately before the unique PUT.
    pub fn baseline_fingerprint(&self) -> &str {
        self.baseline.fingerprint()
    }

    /// Safe desired-content hash; the full raw config stays inside the prepared update.
    pub fn desired_hash(&self) -> String {
        super::json::fingerprint(&self.desired)
    }

    /// Return the UTF-8 byte count of the exact canonical config string sent to UpdatePolicy.
    ///
    /// This shares the request encoder's size bound and does not expose raw content.
    ///
    /// # Errors
    /// The encoded desired config exceeds the supported 64 KiB limit.
    pub fn desired_config_bytes(&self) -> DomainResult<usize> {
        super::profile::encoded_desired(self).map(|raw| raw.len())
    }

    /// Compare a separately validated read with the desired full config and preserved policy metadata.
    /// A match cannot convert an earlier Unknown into Accepted, or prove consumer application.
    pub fn compare_readback(&self, current: &Observation) -> ReadbackState {
        let same_metadata = ["policyId", "classId", "className", "name", "description"]
            .iter()
            .all(|field| self.baseline.policy.get(field) == current.policy.get(field));
        if self.baseline.binding == current.binding
            && same_metadata
            && super::json::canonical(&self.desired) == super::json::canonical(&current.config)
        {
            ReadbackState::Matched
        } else {
            ReadbackState::Different
        }
    }
}

/// Configuration comparison only; provider acceptance and consumer application are separate facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadbackState {
    /// Observed current config and preserved metadata match the prepared update.
    Matched,
    /// The validated observation differs from the intended target content or preserved metadata.
    Different,
}

impl fmt::Debug for PreparedUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedUpdate")
            .field("binding", self.baseline.binding())
            .field("mode", &self.mode)
            .field("limit", &self.limit)
            .field("configuration", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Evidence from one transport invocation, independent of later readback or consumer application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Explicit successful provider response with a validated request identity.
    Accepted {
        /// Safe request identity from the successful provider acknowledgement.
        request_id: String,
    },
    /// Transport began but no trustworthy successful acknowledgement was obtained.
    /// The driver never retries this result; matching later reads cannot change its cause.
    Unknown,
}
