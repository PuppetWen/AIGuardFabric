mod signature;
mod wire;

use agf_alicloud::{
    AdapterMode,
    credential::CloudCredential,
    endpoint::{EndpointStyle, ResolvedEndpoint},
    http::{ReqwestTransport, RpcClient, RpcClientConfig, SignStyle},
    privatelink::provisioning::CurrentGuard,
};
use agf_core::{
    cloud::CloudCredentialKind,
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};
use async_trait::async_trait;
pub(crate) use signature::{query, verify_signature};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
pub(crate) use wire::{Gate, Reply, Server, fixture_error};

const ACCESS_KEY: &str = "agf-owned-privatelink-key-no-cloud";
const SECRET: &str = "agf-owned-privatelink-signing-secret-no-cloud";
const TOKEN: &str = "agf-owned-privatelink-token+reserved/=";
pub(crate) fn client(server: &Server) -> DomainResult<RpcClient> {
    let origin = url::Url::parse(&server.origin).map_err(|_| fixture_error("invalid loopback origin"))?;
    if origin.scheme() != "http" || origin.host_str() != Some("127.0.0.1") {
        return Err(fixture_error("only literal loopback is supported"));
    }
    let port = origin.port().ok_or_else(|| fixture_error("loopback port missing"))?;
    let transport = Arc::new(ReqwestTransport::with_tls_options(5, None, false)?);
    Ok(RpcClient::live(
        AdapterMode::Live,
        RpcClientConfig {
            adapter: "alicloud-privatelink-owned-transport".into(),
            region: "cn-hangzhou".into(),
            account_id: "owned-test-account".into(),
            style: SignStyle::V3,
            timeout_secs: 5,
        },
        Some(CloudCredential {
            access_key_id: ACCESS_KEY.into(),
            access_key_secret: SECRET.into(),
            security_token: Some(TOKEN.into()),
            expires_at: None,
            kind: CloudCredentialKind::StsToken,
        }),
        ResolvedEndpoint {
            service: AliCloudService::Privatelink,
            region: "cn-hangzhou".into(),
            host: format!("127.0.0.1:{port}"),
            scheme: "http",
            style: EndpointStyle::Public,
            origin: "owned-loopback-test",
        },
        transport.clone(),
    )?
    .with_async_transport(transport))
}

#[derive(Debug, Default)]
pub(crate) struct Authority {
    revoked: AtomicBool,
}

impl Authority {
    pub(crate) fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl CurrentGuard for Authority {
    async fn validate(&self) -> DomainResult<()> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(DomainError::Forbidden("owned PrivateLink authority revoked".into()))
        } else {
            Ok(())
        }
    }
}
