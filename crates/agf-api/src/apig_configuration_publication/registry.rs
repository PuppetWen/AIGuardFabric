//! Literal loopback access is a typed server capability, never an HTTP request field.
use super::contract::TransportMode;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use std::net::SocketAddr;

/// Production selects HTTPS; isolated tests may bind exactly one tenant and socket.
#[derive(Debug, Default)]
pub struct Registry {
    loopback: Option<(TenantId, String)>,
}

impl Registry {
    /// Permit one explicitly owned loopback socket in an isolated test server.
    ///
    /// # Errors
    /// Nil tenants, zero ports or non-loopback sockets are rejected.
    pub fn literal_loopback_for_test(tenant: TenantId, address: SocketAddr) -> DomainResult<Self> {
        if tenant.as_uuid().is_nil() || !address.ip().is_loopback() || address.port() == 0 {
            return Err(DomainError::Validation("APIG测试能力须指定租户和字面loopback socket".into()));
        }
        Ok(Self { loopback: Some((tenant, format!("http://{address}"))) })
    }
    pub(super) fn mode(&self, tenant: TenantId, origin: &str) -> DomainResult<TransportMode> {
        let parsed = url::Url::parse(origin).map_err(|_| invalid())?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(invalid());
        }
        let normalized = parsed.origin().ascii_serialization();
        if self.loopback.as_ref().is_some_and(|allowed| allowed.0 == tenant && allowed.1 == normalized) {
            return Ok(TransportMode::LoopbackTest);
        }
        if parsed.scheme() != "https" || parsed.host_str().is_none() {
            return Err(invalid());
        }
        Ok(TransportMode::Live)
    }
}
fn invalid() -> DomainError {
    DomainError::PreconditionFailed(
        "APIG受管配置须使用明确HTTPS OpenAPI origin；loopback仅允许服务端隔离测试能力".into(),
    )
}
