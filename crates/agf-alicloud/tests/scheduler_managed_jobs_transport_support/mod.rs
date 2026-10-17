mod signature;
mod wire;

use agf_alicloud::{
    AdapterMode,
    credential::CloudCredential,
    endpoint::{EndpointStyle, ResolvedEndpoint},
    http::{ReqwestTransport, RpcClient, RpcClientConfig, SignStyle},
    schedulerx3::{
        managed_jobs::{Kind, Selection},
        native_observation::{CurrentGuard, Observation, Scope},
    },
};
use agf_core::{
    cloud::CloudCredentialKind,
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};
use async_trait::async_trait;
use serde_json::{Value, json};
pub(crate) use signature::{form, query, verify_signature};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
pub(crate) use wire::{Captured, Gate, Reply, Server, fixture_error};

const ACCESS_KEY: &str = "agf-owned-scheduler-key-no-cloud";
const SECRET: &str = "agf-owned-scheduler-signing-secret-no-cloud";
const TOKEN: &str = "agf-owned-scheduler-token+reserved/=";
const APP_ID: &str = "9007199254740993";
pub(crate) const JOB_ID: &str = "9007199254741001";
pub(crate) const PRIVATE_VALUES: [&str; 4] = [SECRET, TOKEN, "SYNTHETIC-CALLBACK-TOKEN", "SYNTHETIC-APP-TOKEN"];

pub(crate) fn scope() -> Scope {
    Scope { cluster_id: "cluster-agf-demo".into(), app_name: "app-agf-demo".into() }
}
pub(crate) fn selection(current: &Observation) -> Selection {
    Selection {
        kind: Kind::Report,
        app_id: current.app().id.clone(),
        job_id: JOB_ID.into(),
        observation_fingerprint: current.fingerprint().into(),
    }
}
pub(crate) fn client(server: &Server) -> DomainResult<RpcClient> {
    let origin = url::Url::parse(&server.origin).map_err(|_| fixture_error("invalid loopback origin"))?;
    if origin.scheme() != "http" || origin.host_str() != Some("127.0.0.1") {
        return Err(fixture_error("literal loopback required"));
    }
    let port = origin.port().ok_or_else(|| fixture_error("loopback port missing"))?;
    let transport = Arc::new(ReqwestTransport::with_tls_options(5, None, false)?);
    Ok(RpcClient::live(
        AdapterMode::Live,
        RpcClientConfig {
            adapter: "alicloud-schedulerx3-owned-write-test".into(),
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
            Err(DomainError::Forbidden("owned write authority revoked".into()))
        } else {
            Ok(())
        }
    }
}

pub(crate) struct Fixture {
    job: Mutex<Value>,
}
impl Fixture {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            job: Mutex::new(json!({"JobId":JOB_ID,"AppGroupId":APP_ID,"AppName":"app-agf-demo",
            "Name":"owned-http-job","JobType":"http","Status":0,"TimeType":1,"TimeExpression":"0 0/5 * * * ?",
            "Timezone":"UTC","MaxAttempt":1,"AttemptInterval":30,"RouteStrategy":8,
            "Parameters":"{\"Authorization\":\"Bearer SYNTHETIC-CALLBACK-TOKEN\"}","JobHandler":"opaque-handler"})),
        })
    }
    pub(crate) fn set(&self, key: &str, value: Value) -> DomainResult<()> {
        self.job.lock().map_err(|_| fixture_error("job mutex poisoned"))?[key] = value;
        Ok(())
    }
    pub(crate) fn respond(&self, request: &Captured) -> DomainResult<Reply> {
        let values = if request.method == "GET" { query(request)? } else { form(request)? };
        if values.get("ClusterId").map(String::as_str) != Some("cluster-agf-demo")
            || values.get("AppName").map(String::as_str) != Some("app-agf-demo")
        {
            return Err(fixture_error("exact configured source required"));
        }
        let action = request.headers.get("x-acs-action").map(String::as_str);
        let body = match (request.method.as_str(), action) {
            ("GET", Some("GetApp")) if values.len() == 2 => {
                json!({"Code":200,"Success":true,"RequestId":"owned-get-app",
                "Data":{"Id":APP_ID,"AppName":"app-agf-demo","Title":"Owned app","AppType":1,"AccessToken":"SYNTHETIC-APP-TOKEN"}})
            }
            ("GET", Some("ListJobs"))
                if values.len() == 4
                    && values.get("PageNum").map(String::as_str) == Some("1")
                    && values.get("PageSize").map(String::as_str) == Some("100") =>
            {
                let job = self.job.lock().map_err(|_| fixture_error("job mutex poisoned"))?.clone();
                json!({"Code":200,"Success":true,"RequestId":"owned-list-jobs",
                    "Data":{"Total":1,"PageNumber":1,"PageSize":100,"Records":[job]}})
            }
            ("POST", Some("UpdateJob")) if values.get("JobId").map(String::as_str) == Some(JOB_ID) => {
                let allowed = [
                    "ClusterId",
                    "AppName",
                    "JobId",
                    "TimeType",
                    "TimeExpression",
                    "Calendar",
                    "Timezone",
                    "MaxAttempt",
                    "AttemptInterval",
                ];
                if values.len() < 4
                    || values.keys().any(|key| !allowed.contains(&key.as_str()))
                    || !query(request)?.is_empty()
                {
                    return Err(fixture_error("update contains an unreviewed field"));
                }
                let mut job = self.job.lock().map_err(|_| fixture_error("job mutex poisoned"))?;
                if job["Status"] != json!(0) {
                    return Err(fixture_error("active job update forbidden"));
                }
                for (name, value) in &values {
                    if !matches!(name.as_str(), "ClusterId" | "AppName" | "JobId") {
                        job[name] = if matches!(name.as_str(), "TimeType" | "MaxAttempt" | "AttemptInterval") {
                            json!(value.parse::<i32>().map_err(|_| fixture_error("invalid integer control"))?)
                        } else {
                            json!(value)
                        };
                    }
                }
                ack()
            }
            ("POST", Some("OperateEnableJobs" | "OperateDisableJobs"))
                if values.len() == 3
                    && values.get("JobIds").map(String::as_str) == Some("[9007199254741001]")
                    && query(request)?.is_empty() =>
            {
                let enabling = action == Some("OperateEnableJobs");
                let mut job = self.job.lock().map_err(|_| fixture_error("job mutex poisoned"))?;
                if job["Status"] != json!(i32::from(!enabling)) {
                    return Err(fixture_error("reviewed status changed"));
                }
                job["Status"] = json!(i32::from(enabling));
                ack()
            }
            _ => return Err(fixture_error("unexpected method/action or exact business fields")),
        };
        Ok(Reply::json(&body))
    }
}
fn ack() -> Value {
    json!({"Code":200,"Success":true,"RequestId":"owned-single-write"})
}

pub(crate) async fn assert_requests(server: &Server, expected: usize, writes: usize) -> DomainResult<Vec<Captured>> {
    server.settled(expected).await?;
    let requests = server.requests()?;
    for request in &requests {
        verify_signature(request, &server.origin)?;
    }
    assert_eq!(requests.iter().filter(|request| request.method == "POST").count(), writes);
    Ok(requests)
}
