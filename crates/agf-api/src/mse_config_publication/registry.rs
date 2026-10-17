//! Origin permission is a server-owned capability, never a field in an API body.
use super::contract::TransportMode;
use agf_alicloud::mse::config_cas::EngineEndpoint;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use std::net::SocketAddr;

/// Production uses HTTPS only; isolated tests may explicitly bind one loopback socket.
#[derive(Debug, Default)]
pub struct Registry {
    loopback: Option<(TenantId, String)>,
}

impl Registry {
    /// Construct a server-side test capability for one tenant and literal loopback origin.
    ///
    /// No HTTP API can construct this capability or override its origin.
    /// # Errors
    /// A non-loopback address, empty tenant or zero port is rejected.
    pub fn literal_loopback_for_test(tenant: TenantId, origin: SocketAddr) -> DomainResult<Self> {
        if tenant.as_uuid().is_nil() || !origin.ip().is_loopback() || origin.port() == 0 {
            return Err(DomainError::Validation("Nacos测试入口须明确租户和字面loopback socket".into()));
        }
        let origin = format!("http://{origin}");
        EngineEndpoint::literal_loopback_for_test(&origin)?;
        let origin = url::Url::parse(&origin)
            .map_err(|_| DomainError::Validation("Nacos测试origin格式不正确".into()))?
            .origin()
            .ascii_serialization();
        Ok(Self { loopback: Some((tenant, origin)) })
    }

    pub(super) fn endpoint(&self, tenant: TenantId, origin: &str) -> DomainResult<(EngineEndpoint, TransportMode)> {
        if let Some(allowed) = self.loopback.as_ref().filter(|allowed| allowed.0 == tenant) {
            if let Ok(endpoint) = EngineEndpoint::literal_loopback_for_test(origin) {
                let normalized = url::Url::parse(origin)
                    .map_err(|_| DomainError::Validation("Nacos测试origin格式不正确".into()))?
                    .origin()
                    .ascii_serialization();
                if allowed.1 == normalized {
                    return Ok((endpoint, TransportMode::LoopbackTest));
                }
            }
        }
        Ok((EngineEndpoint::https(origin)?, TransportMode::Live))
    }
}
