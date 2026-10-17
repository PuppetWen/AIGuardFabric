//! 公开 SchedulerX3 协议的离线回归，不访问真实云账号。
use super::*;
use crate::{
    credential::CloudCredential,
    test_support::{ScriptedTransport, fixture_config_with_secrets},
};
use serde_json::{Value, json};

async fn adapter(responses: Vec<Value>) -> (SchedulerX3Adapter, Arc<ScriptedTransport>) {
    let mut config = fixture_config_with_secrets(AliCloudService::SchedulerX3, false);
    config.settings.insert("cluster_id".into(), json!("cluster-one"));
    config.settings.insert("app_name".into(), json!("app-one"));
    let mut adapter = SchedulerX3Adapter::new();
    adapter.init(&config).await.unwrap();
    adapter.core_mut().set_credential(Some(CloudCredential::long_term("ak", "sk")));
    let transport = ScriptedTransport::new(responses);
    adapter.with_recording_transport(transport.clone()).unwrap();
    (adapter, transport)
}
fn page(rows: Vec<Value>, total: usize) -> Value {
    json!({"Success":true,"Data":{"Records":rows,"Total":total}})
}
fn job(id: u64) -> Value {
    json!({"JobId":id,"Name":format!("job-{id}"),"AppName":"app-one","Status":1,
        "JobType":"xxljob","TimeType":1,"TimeExpression":"0 0 2 * * ?","JobHandler":"agfInventory",
        "TimeZone":"Asia/Shanghai","MaxAttempt":3})
}
fn configured_job() -> SchedulerX3Job {
    let mut job = SchedulerX3Job::platform_defaults(TenantId::default_tenant()).remove(0);
    job.cron = "0 0 2 * * ?".into();
    job.cloud_parameters.insert("JobType".into(), json!("xxljob"));
    job.cloud_parameters.insert("JobHandler".into(), json!("agfInventory"));
    job.cloud_parameters.insert("Coordinate".into(), json!({"X":1.0,"Y":2.0}));
    job
}
fn fields(request: &crate::http::RpcRequest) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(request.query.as_bytes())
        .chain(url::form_urlencoded::parse(request.body.as_bytes()))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

#[tokio::test]
async fn actual_pages_preserve_scope_dependencies_and_write_shapes() {
    let mut first = job(41);
    first["ChildJobId"] = json!("42");
    first["NoticeConfig"] = json!("{\"timeoutEnable\":true,\"timeout\":30}");
    let (adapter, transport) = adapter(vec![page(vec![first], 2), page(vec![job(42)], 2)]).await;
    let jobs = adapter.pull_jobs().await.unwrap();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[1].depends_on, vec![jobs[0].id]);
    assert_eq!(jobs[0].cloud_parameters["Timezone"], "Asia/Shanghai");
    assert_eq!(jobs[0].cloud_parameters["NoticeConfig"]["TimeoutEnable"], true);
    jobs[0].parameters("cluster-one", "app-one").unwrap();
    let requests = transport.requests.lock().unwrap();
    let second = fields(&requests[1]);
    assert_eq!(second["PageNum"], "2");
    assert_eq!(second["ClusterId"], "cluster-one");
    assert_eq!(second["AppName"], "app-one");
    assert_eq!(second["Version"], "2024-06-24");
    assert!(!second.contains_key("PageNumber"));
}

#[tokio::test]
async fn pagination_rejects_partial_duplicate_wrong_app_and_missing_success() {
    let mut other = job(41);
    other["AppName"] = json!("other-app");
    let samples = vec![
        vec![page(vec![job(41)], 2), page(Vec::new(), 2)],
        vec![page(vec![job(41)], 2), page(vec![job(41)], 2)],
        vec![page(vec![other], 1)],
        vec![page(vec![job(41)], 0)],
        vec![json!({"Data":{"Records":[],"Total":0}})],
    ];
    for responses in samples {
        let (adapter, _) = adapter(responses).await;
        assert!(adapter.pull_jobs().await.is_err());
    }
}

#[tokio::test]
async fn mutation_uses_create_id_update_then_enable_and_plural_delete() {
    let (adapter, transport) = adapter(vec![
        json!({"Success":true,"Data":{"JobId":71}}),
        json!({"Success":true}),
        json!({"Success":true}),
        json!({"Success":true}),
    ])
    .await;
    let mut job = configured_job();
    assert_eq!(adapter.create_job(&job, "app-one").await.unwrap(), "71");
    job.cloud_job_id = Some("71".into());
    job.enabled = false;
    assert_eq!(adapter.create_job(&job, "app-one").await.unwrap(), "71");
    adapter.delete_job("71", "app-one").await.unwrap();
    let requests = transport.requests.lock().unwrap();
    let requests: Vec<_> = requests.iter().map(fields).collect();
    assert_eq!(requests[0]["Action"], "CreateJob");
    assert_eq!(serde_json::from_str::<Value>(&requests[0]["Coordinate"]).unwrap()["X"], 1.0);
    assert_eq!(requests[1]["Action"], "UpdateJob");
    for key in ["Status", "JobType", "Coordinate"] {
        assert!(!requests[1].contains_key(key));
    }
    assert_eq!(requests[2]["Action"], "OperateDisableJobs");
    assert_eq!(requests[3]["Action"], "DeleteJobs");
    assert_eq!(requests[3]["JobIds"], "[71]");
}

#[tokio::test]
async fn invalid_input_never_writes_and_incomplete_receipt_is_not_success() {
    let (adapter, transport) = adapter(vec![json!({"Success":true})]).await;
    assert!(adapter.delete_job("not-numeric", "app-one").await.is_err());
    assert!(adapter.create_job(&configured_job(), "other-app").await.is_err());
    assert!(transport.requests.lock().unwrap().is_empty());
    let error = adapter.create_job(&configured_job(), "app-one").await.unwrap_err();
    assert!(error.to_string().contains("Data.JobId"));
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn registration_binds_only_owned_jobs_and_is_repeatable() {
    let mut owned = job(51);
    owned["Label"] =
        json!(json!({"agf_tenant":TenantId::default_tenant(),"agf_job_kind":"asset-inventory"}).to_string());
    let mut unrelated = job(52);
    unrelated["Name"] = json!("资产盘点");
    let mut responses = Vec::new();
    for _ in 0..2 {
        responses.extend([
            page(vec![unrelated.clone(), owned.clone()], 2),
            json!({"Success":true}),
            json!({"Success":true}),
        ]);
    }
    let (mut adapter, transport) = adapter(responses).await;
    adapter.registration_jobs = vec![configured_job()];
    for _ in 0..2 {
        let report = adapter.register_platform_jobs(TenantId::default_tenant()).await.unwrap();
        assert_eq!(report.updated, 1);
        assert_eq!(report.created, 0);
        assert_eq!(report.cloud_job_ids["asset-inventory"], "51");
    }
    let requests = transport.requests.lock().unwrap();
    assert!(requests.iter().all(|r| fields(r)["Action"] != "CreateJob"));
}

#[tokio::test]
async fn registration_requires_explicit_configuration_and_full_preflight() {
    let (mut adapter, transport) = adapter(Vec::new()).await;
    assert!(adapter.register_platform_jobs(TenantId::default_tenant()).await.is_err());
    let mut invalid = configured_job();
    invalid.job_kind = "invalid".into();
    invalid.cloud_parameters.insert("UnknownField".into(), json!(true));
    adapter.registration_jobs = vec![configured_job(), invalid];
    assert!(adapter.register_platform_jobs(TenantId::default_tenant()).await.is_err());
    assert!(adapter.register_platform_jobs(TenantId::new()).await.is_err());
    assert!(transport.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn executions_preserve_unknown_time_units_and_reject_other_job() {
    let execution = json!({"JobId":41,"JobExecutionId":"exec-41","Status":4,
        "ScheduleTime":"2026-09-20 12:00:00","Duration":42});
    let (adapter, transport) = adapter(vec![page(vec![execution.clone()], 1), page(vec![execution], 1)]).await;
    let rows = adapter.pull_executions(Some("41")).await.unwrap();
    assert_eq!(rows[0].status, "SUCCESS");
    assert_eq!(rows[0].at, None);
    assert_eq!(rows[0].duration_ms, None);
    assert_eq!(rows[0].duration_native, Some(42));
    assert_eq!(rows[0].shard_index, None);
    assert_eq!(rows[0].scheduled_at_raw.as_deref(), Some("2026-09-20 12:00:00"));
    assert!(adapter.pull_executions(Some("42")).await.is_err());
    assert_eq!(fields(&transport.requests.lock().unwrap()[0])["JobId"], "41");
}
