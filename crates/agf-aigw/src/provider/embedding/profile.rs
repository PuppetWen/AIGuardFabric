use std::fmt;

use agf_core::ids::{Id, TenantId};
use reqwest::Url;

use super::{EmbeddingFailure, MAX_REPORTED_TOKENS};

/// Service configuration only. Transport validation is not authority or an atomic quota claim.
#[derive(Clone)]
pub struct EmbeddingConfiguration {
    pub tenant_id: TenantId,
    pub endpoint_id: Id,
    pub configuration_version: u64,
    pub provider: String,
    pub origin: String,
    pub model: String,
    /// Local pinned revision evidence; the wire response only confirms the exact model string.
    pub model_revision: String,
    pub dimensions: u16,
    /// Set only when this configured model explicitly supports the dimensions parameter.
    pub send_dimensions: bool,
    pub max_input_tokens: u32,
    pub input_micro_per_1k: u64,
}

impl fmt::Debug for EmbeddingConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddingConfiguration")
            .field("tenant_id", &self.tenant_id)
            .field("endpoint_id", &self.endpoint_id)
            .field("configuration_version", &self.configuration_version)
            .field("dimensions", &self.dimensions)
            .finish_non_exhaustive()
    }
}

/// Immutable validated target and price; no implicit chat endpoint or automatic Mock fallback.
#[derive(Debug, Clone)]
pub struct EmbeddingProfile {
    pub(super) configuration: EmbeddingConfiguration,
    pub(super) request_url: Url,
    pub(super) loopback_test: bool,
}

/// Values supplied by the outer trusted reservation. These do not grant permission by themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddingReservation {
    pub reserved_tokens: u64,
    pub reserved_cost_micro: u64,
}

impl EmbeddingProfile {
    pub fn from_server_configuration(configuration: EmbeddingConfiguration) -> Result<Self, EmbeddingFailure> {
        Self::validate(configuration, false)
    }

    /// Default-off typed fixture endpoint. This capability is absent from normal release builds.
    /// # Errors
    /// Identity or literal endpoint mismatch is rejected; redirects and proxies remain disabled.
    #[cfg(feature = "test-loopback-transport")]
    pub fn from_literal_loopback_test_capability(
        configuration: EmbeddingConfiguration,
        tenant: TenantId,
        endpoint: Id,
        address: std::net::SocketAddr,
    ) -> Result<Self, EmbeddingFailure> {
        if tenant.as_id().is_nil()
            || endpoint.is_nil()
            || (configuration.tenant_id, configuration.endpoint_id) != (tenant, endpoint)
            || address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || address.port() == 0
            || configuration.origin != format!("http://{address}")
        {
            return Err(EmbeddingFailure::Configuration);
        }
        Self::validate(configuration, true)
    }

    fn validate(configuration: EmbeddingConfiguration, loopback_test: bool) -> Result<Self, EmbeddingFailure> {
        if configuration.tenant_id.as_id().is_nil()
            || configuration.endpoint_id.is_nil()
            || configuration.configuration_version == 0
            || !safe_identifier(&configuration.provider, 64)
            || !safe_identifier(&configuration.model, 128)
            || !safe_identifier(&configuration.model_revision, 128)
            || !(1..=4096).contains(&configuration.dimensions)
            || !(1..=8192).contains(&configuration.max_input_tokens)
            || configured_cost(MAX_REPORTED_TOKENS, configuration.input_micro_per_1k).is_none()
        {
            return Err(EmbeddingFailure::Configuration);
        }
        let raw = &configuration.origin;
        if raw.len() > 2048
            || raw.trim() != raw
            || raw.bytes().any(|byte| byte.is_ascii_control())
            || raw.contains(['@', '\\', '%', '?', '#'])
            || raw
                .split_once("://")
                .is_some_and(|(_, authority)| authority.split_once('/').is_some_and(|(_, path)| !path.is_empty()))
        {
            return Err(EmbeddingFailure::Configuration);
        }
        let mut url = Url::parse(raw).map_err(|_| EmbeddingFailure::Configuration)?;
        let valid_transport = if loopback_test {
            raw.starts_with("http://127.0.0.1:")
                && url.scheme() == "http"
                && url.host_str() == Some("127.0.0.1")
                && url.port().is_some_and(|port| port > 0)
        } else {
            url.scheme() == "https"
        };
        if !valid_transport
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(EmbeddingFailure::Configuration);
        }
        url.set_path("/v1/embeddings");
        Ok(Self { configuration, request_url: url, loopback_test })
    }

    /// Price is independently calculated even when a later chat reply is cached.
    pub(super) fn cost_for(&self, tokens: u64) -> u64 {
        // All callers limit tokens to MAX_REPORTED_TOKENS; profile validation proves this fits u64.
        configured_cost(tokens, self.configuration.input_micro_per_1k).unwrap_or(u64::MAX)
    }

    #[cfg(test)]
    pub(super) fn literal_loopback_for_test(configuration: EmbeddingConfiguration) -> Result<Self, EmbeddingFailure> {
        Self::validate(configuration, true)
    }
}

fn safe_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-:/".contains(&byte))
}

fn configured_cost(tokens: u64, price: u64) -> Option<u64> {
    let product = u128::from(tokens) * u128::from(price);
    u64::try_from(product.div_ceil(1000)).ok()
}
