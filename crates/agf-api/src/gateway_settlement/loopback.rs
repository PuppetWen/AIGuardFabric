//! Default-off integration-test capability; never selected by URL, environment or request headers.
use crate::AppState;
use agf_aigw::provider::embedding::{EmbeddingConfiguration, EmbeddingFailure, EmbeddingProfile};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub(crate) struct Capability {
    tenant: TenantId,
    endpoint: Id,
    address: SocketAddr,
}
impl Capability {
    fn new(tenant: TenantId, endpoint: Id, address: SocketAddr) -> DomainResult<Self> {
        if tenant.as_id().is_nil()
            || endpoint.is_nil()
            || address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || address.port() == 0
        {
            return Err(DomainError::Validation(
                "Test transport requires an exact owned tenant, endpoint and literal 127.0.0.1 port".into(),
            ));
        }
        Ok(Self { tenant, endpoint, address })
    }
    pub(crate) fn origin(&self, tenant: TenantId, endpoint: Id, raw: &str) -> Option<String> {
        let origin = format!("http://{}", self.address);
        if (tenant, endpoint) != (self.tenant, self.endpoint)
            || ![origin.clone(), format!("{origin}/"), format!("{origin}/v1"), format!("{origin}/v1/")]
                .contains(&raw.to_owned())
        {
            return None;
        }
        Some(origin)
    }
    pub(crate) fn profile(&self, configuration: EmbeddingConfiguration) -> Result<EmbeddingProfile, EmbeddingFailure> {
        EmbeddingProfile::from_literal_loopback_test_capability(configuration, self.tenant, self.endpoint, self.address)
    }
}
impl AppState {
    /// Install only a compiled integration-test capability bound to one already owned endpoint.
    /// # Errors
    /// Nil identities, a nonliteral address, IPv6, or a zero port are rejected.
    pub fn with_gateway_loopback_test_endpoint(
        mut self,
        tenant: TenantId,
        endpoint: Id,
        address: SocketAddr,
    ) -> DomainResult<Self> {
        self.gateway_test_transport = Some(std::sync::Arc::new(Capability::new(tenant, endpoint, address)?));
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origin_is_bound_to_exact_tenant_endpoint_port_and_literal_host() -> DomainResult<()> {
        let tenant = TenantId::new();
        let endpoint = Id::new();
        let capability = Capability::new(
            tenant,
            endpoint,
            "127.0.0.1:31791".parse().map_err(|_| DomainError::Validation("test address".into()))?,
        )?;
        assert_eq!(
            capability.origin(tenant, endpoint, "http://127.0.0.1:31791/v1").as_deref(),
            Some("http://127.0.0.1:31791")
        );
        for (t, e, origin) in [
            (TenantId::new(), endpoint, "http://127.0.0.1:31791"),
            (tenant, Id::new(), "http://127.0.0.1:31791"),
            (tenant, endpoint, "http://localhost:31791"),
            (tenant, endpoint, "http://127.0.0.1:31792"),
            (tenant, endpoint, "http://127.0.0.1:31791/v1/embeddings"),
            (tenant, endpoint, "http://127.0.0.1:31791?x=1"),
        ] {
            assert!(capability.origin(t, e, origin).is_none());
        }
        assert!(
            Capability::new(
                tenant,
                endpoint,
                "192.0.2.1:31791".parse().map_err(|_| DomainError::Validation("test address".into()))?
            )
            .is_err()
        );
        Ok(())
    }
}
