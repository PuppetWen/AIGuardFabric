//! Explicit Nacos HTTP v2 CAS driver. A successful write is not a consumer reload receipt.
//!
//! CAS compares content MD5 only; the server may insert a concurrently deleted configuration.
//! The caller must own durable claims, previews, scope checks and explicit recovery.

use crate::credential::CloudCredential;
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use async_trait::async_trait;
use std::{fmt, sync::Arc, time::Duration};

mod client;
mod publish;
mod query;
mod signing;
pub use client::{EngineEndpoint, NacosConfigClient};
pub use query::content_md5;

/// Exact configuration identity; the empty namespace is the Nacos public namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigKey {
    /// Namespace ID, not its display name. Use an empty string for public.
    pub namespace_id: String,
    /// Explicit configuration group.
    pub group: String,
    /// Explicit data ID.
    pub data_id: String,
}
impl ConfigKey {
    pub(super) fn validate(&self) -> DomainResult<()> {
        for (value, empty) in [(&self.namespace_id, true), (&self.group, false), (&self.data_id, false)] {
            if value.len() > 256 || (!empty && value.is_empty()) || value.chars().any(char::is_control) {
                return Err(DomainError::Validation("Nacos configuration identity is invalid".into()));
            }
        }
        if self.namespace_id == "public" {
            return Err(DomainError::Validation("Use the empty namespace ID for the public namespace".into()));
        }
        Ok(())
    }
    pub(super) fn pairs(&self) -> [(&str, &str); 3] {
        [("namespaceId", &self.namespace_id), ("group", &self.group), ("dataId", &self.data_id)]
    }
}

/// A verified, unencrypted, non-beta observation. Content is sensitive and not serializable here.
#[derive(Clone, PartialEq, Eq)]
pub struct ConfigObservation {
    /// Configuration identity used for this exact request.
    pub key: ConfigKey,
    /// Exact UTF-8 content, including empty content and line endings.
    pub content: String,
    /// Lowercase, server-provided MD5 checked against the exact content bytes.
    pub md5: String,
    /// Time the complete response was validated.
    pub observed_at: Timestamp,
}
impl fmt::Debug for ConfigObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigObservation")
            .field("key", &self.key)
            .field("content", &"<redacted>")
            .field("md5", &self.md5)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

/// Safe categories for a request whose write delivery or result could not be confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UncertainReason {
    /// The overall call deadline expired after transport was started.
    Deadline,
    /// Transport failed, including a truncated body.
    Transport,
    /// Response exceeded the configured byte bound.
    ResponseLimit,
    /// Status, envelope, body or headers did not satisfy the pinned protocol.
    Protocol,
}
/// Cloud response classification; none of these variants proves that a consumer applied content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Exactly HTTP 200 with the Nacos v2 envelope code 0 and boolean data true.
    Accepted,
    /// Exactly the known CAS failure: HTTP 500 with v2 error code 20005.
    Conflict,
    /// A verified protocol error denoting a definitive permission or parameter rejection.
    Rejected {
        /// HTTP status.
        http_status: u16,
        /// Public Nacos numeric error code.
        provider_code: u32,
    },
    /// Delivery/result unknown; the caller must never automatically retry the write.
    Uncertain(UncertainReason),
}

/// Existing RAM/STS resolution can implement this interface without exposing credentials in DTOs.
#[async_trait]
pub trait NacosCredentialProvider: Send + Sync {
    /// Get current credentials. No calls are made by the driver until this succeeds.
    /// # Errors
    /// Missing or unavailable credentials must return a safe error.
    async fn credentials(&self) -> DomainResult<CloudCredential>;
}
/// Business authority/configuration/lease check performed after credential acquisition.
#[async_trait]
pub trait NacosSendGuard: Send + Sync {
    /// Validate the current claim and original authority immediately before request construction.
    /// # Errors
    /// Any expired, stale or revoked state must reject without transport.
    async fn validate(&self) -> DomainResult<()>;
}

/// Bounded call settings. The deadline includes credentials, guard, send and body read.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum UTF-8 configuration content bytes, at most 256 KiB.
    pub max_content_bytes: usize,
    /// Maximum decoded response bytes, at most 320 KiB.
    pub max_response_bytes: usize,
    /// Total call budget, positive and at most 30 seconds.
    pub timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self { max_content_bytes: 256 * 1024, max_response_bytes: 320 * 1024, timeout: Duration::from_secs(30) }
    }
}
impl Limits {
    pub(super) fn validate(self) -> DomainResult<()> {
        if self.max_content_bytes == 0
            || self.max_content_bytes > 256 * 1024
            || self.max_response_bytes == 0
            || self.max_response_bytes > 320 * 1024
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(30)
        {
            return Err(DomainError::Validation("Nacos driver limits exceed the supported bounds".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_http;
#[cfg(test)]
mod tests_http_support;
