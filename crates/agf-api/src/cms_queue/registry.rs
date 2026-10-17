use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use std::net::SocketAddr;

/// HTTPS-only runtime capability, with an explicit tenant-owned literal-loopback test capability.
#[derive(Debug, Default)]
pub struct Registry {
    loopback: Option<(TenantId, String)>,
}
impl Registry {
    /// Permit one already-owned local provider origin for one test tenant.
    pub fn literal_loopback_for_test(tenant: TenantId, address: SocketAddr) -> DomainResult<Self> {
        if tenant.as_uuid().is_nil() || !address.ip().is_loopback() || address.port() == 0 {
            return Err(invalid());
        }
        Ok(Self { loopback: Some((tenant, format!("http://{address}"))) })
    }
    pub(crate) fn mode(&self, tenant: TenantId, origin: &str) -> DomainResult<&'static str> {
        let url = url::Url::parse(origin).map_err(|_| invalid())?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.host_str().is_none()
        {
            return Err(invalid());
        }
        if url.scheme() == "https" {
            return Ok("live");
        }
        if self
            .loopback
            .as_ref()
            .is_some_and(|(owner, allowed)| *owner == tenant && *allowed == url.origin().ascii_serialization())
        {
            return Ok("loopback_test");
        }
        Err(invalid())
    }
}
fn invalid() -> DomainError {
    DomainError::PreconditionFailed(
        "CMS delivery requires HTTPS or its exact tenant-owned loopback test capability".into(),
    )
}
