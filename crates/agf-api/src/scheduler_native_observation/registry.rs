//! A loopback provider is an explicit server capability, never a caller-supplied endpoint override.
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use std::net::SocketAddr;

/// Production observes HTTPS providers; isolated tests may admit exactly one tenant and socket.
#[derive(Debug, Default)]
pub struct Registry {
    loopback: Option<(TenantId, String)>,
}

impl Registry {
    /// Admit one explicitly owned literal loopback provider in an isolated test server.
    ///
    /// # Errors
    /// Rejects nil tenants, zero ports and non-loopback sockets.
    pub fn literal_loopback_for_test(tenant: TenantId, address: SocketAddr) -> DomainResult<Self> {
        if tenant.as_uuid().is_nil() || !address.ip().is_loopback() || address.port() == 0 {
            return Err(DomainError::Validation("Scheduler 测试能力须指定租户和字面 loopback socket".into()));
        }
        Ok(Self { loopback: Some((tenant, format!("http://{address}"))) })
    }

    pub(crate) fn mode(&self, tenant: TenantId, origin: &str) -> DomainResult<&'static str> {
        let parsed = url::Url::parse(origin).map_err(|_| invalid())?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
            || parsed.host_str().is_none()
        {
            return Err(invalid());
        }
        let normalized = parsed.origin().ascii_serialization();
        if self.loopback.as_ref().is_some_and(|allowed| allowed.0 == tenant && allowed.1 == normalized) {
            return Ok("loopback_test");
        }
        if parsed.scheme() != "https" {
            return Err(invalid());
        }
        Ok("live")
    }
}

fn invalid() -> DomainError {
    DomainError::PreconditionFailed("Scheduler 须使用 HTTPS RPC origin；loopback 仅限服务端隔离测试能力".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_loopback_is_bound_to_the_literal_origin_and_tenant() {
        let tenant = TenantId::new();
        let address = "127.0.0.1:31901".parse().unwrap();
        let registry = Registry::literal_loopback_for_test(tenant, address).unwrap();
        assert_eq!(registry.mode(tenant, "http://127.0.0.1:31901/").unwrap(), "loopback_test");
        assert!(registry.mode(TenantId::new(), "http://127.0.0.1:31901/").is_err());
        assert!(registry.mode(tenant, "http://127.0.0.1:31902/").is_err());
        assert!(registry.mode(tenant, "http://localhost:31901/").is_err());
        assert!(Registry::default().mode(tenant, "http://127.0.0.1:31901/").is_err());
        assert!(Registry::literal_loopback_for_test(tenant, "192.168.1.2:31901".parse().unwrap()).is_err());
        for suffix in ["jobs", "?token=synthetic", "#private"] {
            assert!(registry.mode(tenant, &format!("http://127.0.0.1:31901/{suffix}")).is_err());
        }
        assert_eq!(Registry::default().mode(tenant, "https://schedulerx3.cn-hangzhou.aliyuncs.com/").unwrap(), "live");
    }
}
