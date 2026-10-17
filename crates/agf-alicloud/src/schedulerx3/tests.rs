//! 由 `schedulerx3.rs` 拆分：`tenant` 等 17 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn tenant() -> TenantId {
    TenantId::default_tenant()
}

#[tokio::test]
pub(crate) async fn platform_defaults_cover_six_jobs_with_cron_shard_retry_deps() {
    let jobs = SchedulerX3Job::platform_defaults(tenant());
    assert_eq!(jobs.len(), 6);
    let kinds: Vec<&str> = jobs.iter().map(|j| j.job_kind.as_str()).collect();
    for expected in PLATFORM_JOB_KINDS {
        assert!(kinds.contains(&expected), "缺少任务 {expected}");
    }
    let by_kind = |kind: &str| jobs.iter().find(|j| j.job_kind == kind);
    let inventory = by_kind("asset-inventory");
    assert!(inventory.is_some());
    if let Some(job) = inventory {
        assert_eq!(job.cron, "0 2 * * *");
        assert_eq!(job.shard_count, 1, "资产汇总必须单分片，否则跳过分片无法满足下游完整成功依赖");
        assert_eq!(job.max_retries, 3);
        assert!(job.depends_on.is_empty(), "资产盘点是根任务");
        assert!(job.handler.starts_with("/api/v1/internal/jobs/"));
        assert!(job.cloud_job_id.is_none());
        assert_eq!(job.backend, ScheduleBackend::SchedulerX3);
        assert!(!job.is_degraded_backend());
    }
    let log_pull = by_kind("log-pull");
    assert!(log_pull.is_some_and(|j| j.shard_count == 8 && j.max_retries == 5 && j.depends_on.len() == 1));
    let report = by_kind("report");
    assert!(report.is_some_and(|j| j.depends_on.len() == 2));
    let archive = by_kind("archive");
    assert!(archive.is_some_and(|j| j.depends_on.len() == 1 && j.cron == "0 4 1 * *"));
    assert!(by_kind("rule-hot-reload").is_some_and(|j| j.shard_count == 1 && j.cron == "*/5 * * * *"));
    assert!(by_kind("redteam-cruise").is_some_and(|j| j.cron == "0 3 * * 1"));
}

#[tokio::test]
pub(crate) async fn platform_defaults_are_deterministic_and_tenant_scoped() {
    let a = SchedulerX3Job::platform_defaults(tenant());
    let b = SchedulerX3Job::platform_defaults(tenant());
    assert_eq!(a[0].id, b[0].id, "同一租户必须产出同一任务 id");
    let other = SchedulerX3Job::platform_defaults(TenantId::new());
    assert_ne!(a[0].id, other[0].id, "不同租户的任务 id 必须隔离");
}

#[tokio::test]
pub(crate) async fn platform_defaults_pass_self_validation() {
    let jobs = SchedulerX3Job::platform_defaults(tenant());
    assert_eq!(validate_platform_jobs(&jobs), Ok(()));
}

#[tokio::test]
pub(crate) async fn validation_catches_broken_definitions() {
    let mut jobs = SchedulerX3Job::platform_defaults(tenant());
    jobs[0].cron = "not a cron".to_string();
    jobs[1].shard_count = 0;
    jobs[2].max_retries = 99;
    jobs[3].depends_on = vec![Id::new()];
    let problems = validate_platform_jobs(&jobs);
    assert!(problems.is_err());
    if let Err(problems) = problems {
        assert!(problems.iter().any(|p| p.contains("cron")), "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("分片")), "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("重试")), "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("批次外")), "{problems:?}");
    }
    let short = SchedulerX3Job::platform_defaults(tenant()).into_iter().take(3).collect::<Vec<_>>();
    assert!(validate_platform_jobs(&short).is_err());
}

#[tokio::test]
pub(crate) async fn job_parameters_require_explicit_executor_and_public_names() {
    let mut job = SchedulerX3Job::platform_defaults(tenant()).remove(0);
    assert!(job.parameters("cluster", "app").is_err());
    job.cloud_parameters.insert("JobType".into(), serde_json::json!("xxljob"));
    job.cloud_parameters.insert("JobHandler".into(), serde_json::json!("agfInventory"));
    let body = job.parameters("cluster", "app").unwrap();
    assert_eq!(body["ClusterId"], "cluster");
    assert_eq!(body["AppName"], "app");
    assert_eq!(body["TimeType"], 1);
    assert_eq!(body["JobHandler"], "agfInventory");
    assert!(body.get("Namespace").is_none());
    assert!(body.get("ShardCount").is_none());
    assert!(body.get("DependOnJobIds").is_none());
}

#[tokio::test]
pub(crate) async fn health_states_and_backend_fallback_message() {
    let adapter = SchedulerX3Adapter::new();
    assert!(adapter.health().await.is_ok_and(|h| h.state == HealthState::Unconfigured));
    assert_eq!(adapter.effective_backend(), ScheduleBackend::LocalCron, "无云环境必须回退本地 cron");
    let mut mocked = SchedulerX3Adapter::mocked();
    assert!(mocked.init(&fixture_config(AliCloudService::SchedulerX3, true)).await.is_ok());
    let health = mocked.health().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert_eq!(health.state, HealthState::Degraded);
        let message = health.message.unwrap_or_default();
        assert!(message.contains("AGF_MOCK_MODE"));
        assert!(message.contains("local-cron"), "必须说明调度回退后端: {message}");
    }
}

#[tokio::test]
pub(crate) async fn mock_register_platform_jobs_creates_six() {
    let mut adapter = SchedulerX3Adapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::SchedulerX3, true)).await.is_ok());
    let report = adapter.register_platform_jobs(tenant()).await;
    assert!(report.is_ok(), "{report:?}");
    if let Ok(report) = report {
        assert_eq!(report.created, 6);
        assert_eq!(report.updated, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.total(), 6);
        assert_eq!(report.cloud_job_ids.len(), 6);
        assert_eq!(
            report.cloud_job_ids.get("asset-inventory").map(String::as_str),
            Some("cloud-job-mock-asset-inventory")
        );
    }
    assert_eq!(adapter.transport.call_count().ok(), Some(0), "Mock 必须零网络");
}

#[tokio::test]
pub(crate) async fn mock_sync_reports_jobs_executions_and_creates() {
    let mut adapter = SchedulerX3Adapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::SchedulerX3, true)).await.is_ok());
    let outcome = adapter.sync(SyncDirection::Both, &PullRequest::default()).await;
    assert!(outcome.is_ok(), "{outcome:?}");
    if let Ok(outcome) = outcome {
        assert!(outcome.mocked && outcome.degraded);
        assert_eq!(outcome.changes.get("schedule_job").copied(), Some(6));
        assert_eq!(outcome.changes.get("execution").copied(), Some(2));
        assert_eq!(outcome.changes.get("execution_failed").copied(), Some(1));
        assert_eq!(outcome.changes.get("job_created").copied(), Some(6));
        assert_eq!(outcome.pushed, 6);
    }
    assert_eq!(adapter.transport.call_count().ok(), Some(0));
}

#[tokio::test]
pub(crate) async fn platform_registrations_use_fallback_backend_when_unconfigured() {
    let adapter = SchedulerX3Adapter::new();
    let registrations = adapter.platform_registrations(tenant());
    assert_eq!(registrations.len(), 6);
    assert!(registrations.iter().all(|r| r.backend == ScheduleBackend::LocalCron));
    assert!(registrations.iter().all(|r| r.enabled));
    let report = registrations.iter().find(|r| r.job_kind == "report").expect("report 存在");
    assert_eq!(report.depends_on.len(), 2);
    assert_eq!(report.max_retries, 3);
}

#[tokio::test]
pub(crate) async fn mocked_registrations_also_have_backend_annotated() {
    let adapter = SchedulerX3Adapter::mocked();
    let registrations = adapter.platform_registrations(tenant());
    assert!(registrations.iter().all(|r| r.backend == ScheduleBackend::LocalCron));
    // 云后端时 backend 保持 SchedulerX3
    let mut live_ish = SchedulerX3Adapter::mocked();
    live_ish.core.mode = AdapterMode::Live;
    let registrations = live_ish.platform_registrations(tenant());
    assert!(registrations.iter().all(|r| r.backend == ScheduleBackend::SchedulerX3));
}

#[tokio::test]
pub(crate) async fn pull_resource_routing() {
    let mut adapter = SchedulerX3Adapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::SchedulerX3, true)).await.is_ok());
    for (resource, expected) in [("jobs", 6), ("executions", 2), ("registrations", 6)] {
        let response = adapter.pull(&PullRequest { resource: resource.to_string(), ..PullRequest::default() }).await;
        assert!(response.is_ok(), "{resource}: {response:?}");
        if let Ok(response) = response {
            assert_eq!(response.items.len(), expected, "{resource}");
            assert!(response.origin.contains("mock.rs"));
        }
    }
    let filtered = adapter.pull_executions(Some("job-asset-inventory")).await;
    assert_eq!(filtered.map(|e| e.len()).ok(), Some(1));
    let unknown = PullRequest { resource: "teams".to_string(), ..PullRequest::default() };
    assert!(matches!(adapter.pull(&unknown).await, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn push_schedule_payload() {
    let mut adapter = SchedulerX3Adapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::SchedulerX3, true)).await.is_ok());
    let defaults = SchedulerX3Job::platform_defaults(tenant());
    let Some(job) = defaults.first() else { return };
    let payload = PushPayload {
        entity: "schedule".to_string(),
        entity_id: job.job_kind.clone(),
        body: serde_json::to_value(job).unwrap_or_default(),
        idempotency_key: Some("idem".to_string()),
    };
    assert!(adapter.push(&payload).await.is_ok());
    let bad = PushPayload {
        entity: "policy".to_string(),
        entity_id: "p".to_string(),
        body: serde_json::json!({}),
        idempotency_key: None,
    };
    assert!(matches!(adapter.push(&bad).await, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn parsers_handle_aliyun_shapes() {
    let jobs = parse_jobs(
        &serde_json::json!({
            "Jobs": { "Job": [ { "JobId": "j-1", "JobName": "资产盘点", "TimeExpression": "0 2 * * *", "ShardCount": "4", "MaxAttempt": "3", "Enabled": true, "Handler": "/jobs/asset" } ] }
        }),
        tenant(),
    );
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].cloud_job_id.as_deref(), Some("j-1"));
    assert_eq!(jobs[0].shard_count, 4);

    let executions = parse_executions(&serde_json::json!({
        "Executions": { "Execution": [ { "JobId": "j-1", "ExecutionId": "e-1", "ShardIndex": 2, "Status": "FAILED", "StartTime": "1700000000000", "DurationMs": "900", "Message": "boom" } ] }
    }));
    assert_eq!(executions.len(), 1);
    assert_eq!(executions[0].shard_index, Some(2));
    assert_eq!(executions[0].duration_ms, Some(900));
    assert_eq!(executions[0].result, "boom");
}

#[tokio::test]
pub(crate) async fn job_kind_normalization_prefers_platform_kinds() {
    assert_eq!(normalize_job_kind("资产盘点 - asset_inventory"), "asset-inventory");
    assert_eq!(normalize_job_kind("LOG PULL"), "log-pull");
    assert_eq!(normalize_job_kind("custom-thing"), "custom-thing");
}

#[tokio::test]
pub(crate) async fn live_register_pulls_existing_to_decide_create_vs_update() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({
        "Success":true, "Data": { "Records": [ { "JobId": 74, "Name": "资产盘点", "TimeExpression": "0 2 * * *", "RouteStrategy": 1, "MaxAttempt": 3, "Status": 1 } ],"Total":1 }
    })));
    let mut adapter = SchedulerX3Adapter::new();
    let mut config = fixture_config(AliCloudService::SchedulerX3, false);
    config.settings.insert("cluster_id".into(), serde_json::json!("cluster-test"));
    config.secret_refs.insert("access_key_id".to_string(), Id::new());
    config.secret_refs.insert("access_key_secret".to_string(), Id::new());
    assert!(adapter.init(&config).await.is_ok());
    adapter.core_mut().set_credential(Some(crate::credential::CloudCredential::long_term("ak", "sk")));
    assert!(adapter.with_recording_transport(transport.clone()).is_ok());
    let jobs = adapter.pull_jobs().await;
    assert_eq!(jobs.as_ref().ok().map(Vec::len), Some(1));
    let last = transport.last_request().ok().flatten();
    assert!(last.is_some_and(|r| r.query.contains("Action=ListJobs")));
}

#[tokio::test]
pub(crate) async fn self_check_and_descriptor() {
    let mut adapter = SchedulerX3Adapter::mocked();
    assert!(adapter.init(&fixture_config(AliCloudService::SchedulerX3, true)).await.is_ok());
    let health = adapter.self_check().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert!(health.message.unwrap_or_default().contains("schedulerx3:"));
    }
    let descriptor = SchedulerX3Adapter::new().descriptor();
    assert_eq!(descriptor.name, "alicloud-schedulerx3");
    assert!(descriptor.capabilities.contains(&agf_core::adapter::AdapterCapability::ScheduleTask));
    assert!(descriptor.mock_location.ends_with("#mock_schedulerx3"));
    assert!(descriptor.degradation.contains("tokio-cron"));
}
