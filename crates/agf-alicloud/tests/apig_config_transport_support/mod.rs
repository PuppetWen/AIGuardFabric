mod wire;

use agf_alicloud::{
    AdapterMode,
    apig::config_driver::CurrentGuard,
    credential::CloudCredential,
    endpoint::{EndpointStyle, ResolvedEndpoint},
    http::{ReqwestTransport, RpcClient, RpcClientConfig},
};
use agf_core::{
    cloud::CloudCredentialKind,
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};
use async_trait::async_trait;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::time::{Duration, Instant};
pub(crate) use wire::{Captured, Gate, Reply, Server, fixture_error};
pub(crate) mod service;

const ACCESS_KEY: &str = "agf-owned-synthetic-key";
const SECRET: &str = "agf-owned-synthetic-signing-secret-no-cloud";
const TOKEN: &str = "agf-owned-synthetic-sts-token";

pub(crate) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

pub(crate) fn client(server: &Server) -> DomainResult<RpcClient> {
    let origin = url::Url::parse(&server.origin).map_err(|_| fixture_error("invalid loopback origin"))?;
    if origin.host_str() != Some("127.0.0.1") || origin.scheme() != "http" {
        return Err(fixture_error("only literal loopback is supported"));
    }
    let port = origin.port().ok_or_else(|| fixture_error("loopback port missing"))?;
    let transport = Arc::new(ReqwestTransport::with_tls_options(5, None, false)?);
    Ok(RpcClient::live(
        AdapterMode::Live,
        RpcClientConfig {
            adapter: "alicloud-apig-owned-transport".into(),
            region: "cn-hangzhou".into(),
            account_id: "owned-test-account".into(),
            style: agf_alicloud::http::SignStyle::V3,
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
            service: AliCloudService::Apig,
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
            Err(DomainError::Forbidden("owned submission revoked".into()))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub(crate) struct WaitingAuthority(pub(crate) Arc<Gate>);

#[async_trait]
impl CurrentGuard for WaitingAuthority {
    async fn validate(&self) -> DomainResult<()> {
        self.0.wait().await;
        Ok(())
    }
}

// Independent reconstruction: do not call the production sign_v3 function to verify its own output.
pub(crate) fn verify_signature(request: &Captured, origin: &str) -> DomainResult<()> {
    let authorization = request.headers.get("authorization").ok_or_else(|| fixture_error("signature absent"))?;
    let parts: BTreeMap<_, _> = authorization
        .strip_prefix("ACS3-HMAC-SHA256 ")
        .ok_or_else(|| fixture_error("signature algorithm differs"))?
        .split(',')
        .filter_map(|part| part.split_once('='))
        .collect();
    if parts.get("Credential").copied() != Some(ACCESS_KEY) {
        return Err(fixture_error("credential differs"));
    }
    let signed = parts.get("SignedHeaders").ok_or_else(|| fixture_error("signed headers absent"))?;
    let names: Vec<_> = signed.split(';').collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted != names {
        return Err(fixture_error("signed headers are not canonical"));
    }
    for required in [
        "host",
        "x-acs-action",
        "x-acs-version",
        "x-acs-date",
        "x-acs-signature-nonce",
        "x-acs-security-token",
        "x-acs-content-sha256",
    ] {
        if !names.contains(&required) {
            return Err(fixture_error("required header is unsigned"));
        }
    }
    let host = origin.strip_prefix("http://").ok_or_else(|| fixture_error("invalid origin"))?;
    if request.headers.get("host").map(String::as_str) != Some(host)
        || request.headers.get("x-acs-version").map(String::as_str) != Some("2024-03-27")
        || request.headers.get("x-acs-security-token").map(String::as_str) != Some(TOKEN)
    {
        return Err(fixture_error("signed endpoint or metadata differs"));
    }
    let payload_hash = hex::encode(Sha256::digest(request.body.as_bytes()));
    if request.headers.get("x-acs-content-sha256") != Some(&payload_hash) {
        return Err(fixture_error("payload hash differs"));
    }
    let (path, query) = request.target.split_once('?').unwrap_or((&request.target, ""));
    let canonical_headers = names
        .iter()
        .map(|name| {
            request
                .headers
                .get(*name)
                .map(|value| format!("{name}:{}\n", value.trim()))
                .ok_or_else(|| fixture_error("signed header missing on the wire"))
        })
        .collect::<DomainResult<String>>()?;
    let canonical = format!("{}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}", request.method);
    let to_sign = format!("ACS3-HMAC-SHA256\n{}", hex::encode(Sha256::digest(canonical.as_bytes())));
    let mut mac =
        Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).map_err(|_| fixture_error("MAC initialization failed"))?;
    mac.update(to_sign.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if parts.get("Signature").copied() != Some(expected.as_str()) {
        return Err(fixture_error("MAC differs"));
    }
    Ok(())
}
