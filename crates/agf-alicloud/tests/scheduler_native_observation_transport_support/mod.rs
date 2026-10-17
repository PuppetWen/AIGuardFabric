mod signature;
mod wire;

use agf_alicloud::{
    AdapterMode,
    credential::CloudCredential,
    endpoint::{EndpointStyle, ResolvedEndpoint},
    http::{ReqwestTransport, RpcClient, RpcClientConfig, SignStyle},
    schedulerx3::native_observation::{CurrentGuard, Scope},
};
use agf_core::{
    cloud::CloudCredentialKind,
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};
use async_trait::async_trait;
use serde_json::{Value, json};
pub(crate) use signature::{query, verify_signature};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
pub(crate) use wire::{Captured, Gate, Server, fixture_error};

const ACCESS_KEY: &str = "agf-owned-scheduler-key-no-cloud";
const SECRET: &str = "agf-owned-scheduler-signing-secret-no-cloud";
const TOKEN: &str = "agf-owned-scheduler-token+reserved/=";
const APP_ID: &str = "9007199254740993";
const APP_SECRET: &str = "SYNTHETIC-APP-TOKEN-DO-NOT-EXPOSE";
const HANDLER_SECRET: &str = "SYNTHETIC-HTTP-HANDLER-DO-NOT-EXPOSE";
pub(crate) const PRIVATE_VALUES: [&str; 4] = [APP_SECRET, HANDLER_SECRET, SECRET, TOKEN];

pub(crate) fn scope() -> Scope {
    Scope { cluster_id: "cluster-agf-demo".into(), app_name: "app-agf-demo".into() }
}

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
            adapter: "alicloud-schedulerx3-owned-transport".into(),
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
            service: AliCloudService::SchedulerX3,
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
            Err(DomainError::Forbidden("owned read authority revoked".into()))
        } else {
            Ok(())
        }
    }
}

// Every response is actual loopback HTTP; no response is supplied through RecordingTransport.
pub(crate) fn respond(request: &Captured) -> DomainResult<wire::Reply> {
    let values = query(request)?;
    let configured = scope();
    if values.get("ClusterId") != Some(&configured.cluster_id) || values.get("AppName") != Some(&configured.app_name) {
        return Err(fixture_error("configured source identity differs"));
    }
    let action = request.headers.get("x-acs-action").map(String::as_str);
    let required: &[&str] = match action {
        Some("GetApp") => &["ClusterId", "AppName"],
        Some("ListJobs") => &["ClusterId", "AppName", "PageNum", "PageSize"],
        _ => return Err(fixture_error("unexpected provider action")),
    };
    if values.len() != required.len() || !required.iter().all(|name| values.contains_key(*name)) {
        return Err(fixture_error("RPC business fields differ"));
    }
    let body = if action == Some("GetApp") {
        json!({"Code":200,"Success":true,"RequestId":"owned-get-app", "Data":{
            "Id":APP_ID,"AppName":configured.app_name,"Title":"Owned loopback app","AppType":1,"AccessToken":APP_SECRET}})
    } else {
        if values.get("PageSize").map(String::as_str) != Some("100") {
            return Err(fixture_error("actual PageSize differs"));
        }
        let (number, start, count) = match values.get("PageNum").map(String::as_str) {
            Some("1") => (1, 1, 100),
            Some("2") => (2, 101, 1),
            _ => return Err(fixture_error("unexpected page number")),
        };
        let records: Vec<Value> = (start..start + count)
            .map(|id| {
                json!({
                    "JobId":format!("{}",9_007_199_254_740_993_i64+id), "AppGroupId":APP_ID,
                    "AppName":configured.app_name,"Name":format!("owned-job-{id}"),"JobType":"http","Status":1,
                    "TimeType":1,"TimeExpression":"0 0/5 * * * ?","Timezone":"UTC",
                    "Parameters":"{\"Authorization\":\"Bearer SYNTHETIC-CALLBACK-TOKEN\"}","JobHandler":HANDLER_SECRET
                })
            })
            .collect();
        json!({"Code":200,"Success":true,"RequestId":format!("owned-list-page-{number}"),
            "Data":{"Total":101,"PageNumber":number,"PageSize":100,"Records":records}})
    };
    Ok(wire::Reply::json(&body))
}
