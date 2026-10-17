//! 由 `cms.rs` 拆分：`health_unconfigured_without_config` 等 17 个函数（纯搬移，逻辑不变）。
use super::*;

#[tokio::test]
pub(crate) async fn health_unconfigured_without_config() {
    let adapter = CmsAdapter::new();
    let health = adapter.health().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert_eq!(health.state, HealthState::Unconfigured);
        assert!(!health.configured);
        assert!(!health.mocked);
        assert!(!health.capabilities.is_empty());
    }
}

pub(crate) fn mocked_and_configured() -> CmsAdapter {
    CmsAdapter::mocked()
}

#[tokio::test]
pub(crate) async fn health_degraded_and_mentions_mock_env() {
    let mut adapter = mocked_and_configured();
    let config = fixture_config(AliCloudService::Cms, true);
    assert!(adapter.init(&config).await.is_ok());
    assert_eq!(adapter.mode(), AdapterMode::Mocked);
    let health = adapter.health().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert_eq!(health.state, HealthState::Degraded);
        assert!(health.mocked);
        assert!(health.message.unwrap_or_default().contains("AGF_MOCK_MODE"));
    }
}

#[tokio::test]
pub(crate) async fn init_without_credentials_is_unconfigured_not_error() {
    let mut adapter = CmsAdapter::new();
    assert!(adapter.init(&fixture_config(AliCloudService::Cms, false)).await.is_ok());
    assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
    let health = adapter.health().await;
    assert!(health.is_ok_and(|h| h.state == HealthState::Unconfigured));
    let err = adapter
        .put_event(&CmsEvent {
            event_name: "x".to_string(),
            content: "{}".to_string(),
            group_id: String::new(),
            at: Timestamp::now(),
            severity: Severity::High,
        })
        .await;
    assert!(matches!(err, Err(DomainError::DependencyUnavailable { .. })));
}

#[tokio::test]
pub(crate) async fn init_with_invalid_region_is_error() {
    let mut adapter = CmsAdapter::new();
    let mut config = fixture_config(AliCloudService::Cms, true);
    config.settings.insert("region_id".to_string(), serde_json::Value::from("cn hangzhou"));
    let err = adapter.init(&config).await;
    assert!(matches!(err, Err(DomainError::Config(_))), "配置存在但非法必须报错: {err:?}");
}

#[tokio::test]
pub(crate) async fn mock_sync_never_touches_network() {
    let mut adapter = mocked_and_configured();
    assert!(adapter.init(&fixture_config(AliCloudService::Cms, true)).await.is_ok());
    let outcome = adapter.sync(SyncDirection::Both, &PullRequest::default()).await;
    assert!(outcome.is_ok(), "{outcome:?}");
    if let Ok(outcome) = outcome {
        assert!(outcome.mocked);
        assert!(outcome.degraded);
        assert!(outcome.pulled >= 1);
        assert_eq!(outcome.changes.get("alarm_history").copied(), Some(outcome.pulled));
        assert!(outcome.changes.get("critical_alarm").copied().unwrap_or(0) >= 1);
        assert!(!outcome.warnings.is_empty());
        assert!(outcome.finished_at.is_some());
    }
    assert_eq!(adapter.transport.call_count().ok(), Some(0), "Mock 模式绝不能发请求");
}

#[tokio::test]
pub(crate) async fn mock_push_event_and_metric() {
    let mut adapter = mocked_and_configured();
    assert!(adapter.init(&fixture_config(AliCloudService::Cms, true)).await.is_ok());
    let name = adapter
        .put_event(&CmsEvent {
            event_name: "agf.prompt_attack".to_string(),
            content: "{\"agent\":\"a1\"}".to_string(),
            group_id: "g1".to_string(),
            at: Timestamp::now(),
            severity: Severity::Critical,
        })
        .await;
    assert_eq!(name.ok().as_deref(), Some("agf.prompt_attack"));
    assert_eq!(
        adapter.put_metric(&CmsMetric::new("agf_agent_calls", 12.0)).await.ok().as_deref(),
        Some("agf_agent_calls")
    );
    assert_eq!(adapter.transport.call_count().ok(), Some(0));
}

#[tokio::test]
pub(crate) async fn push_payload_routing() {
    let mut adapter = mocked_and_configured();
    assert!(adapter.init(&fixture_config(AliCloudService::Cms, true)).await.is_ok());
    let event = PushPayload {
        entity: "event".to_string(),
        entity_id: "ev-1".to_string(),
        body: serde_json::json!({ "event_name": "", "content": "{}", "at": Timestamp::now() }),
        idempotency_key: Some("k1".to_string()),
    };
    assert!(adapter.push(&event).await.is_ok());
    let metric = PushPayload {
        entity: "metric".to_string(),
        entity_id: "m-1".to_string(),
        body: serde_json::to_value(CmsMetric::new("agf_x", 1.0)).unwrap_or_default(),
        idempotency_key: None,
    };
    assert!(adapter.push(&metric).await.is_ok());
    let bad = PushPayload {
        entity: "policy".to_string(),
        entity_id: "p".to_string(),
        body: serde_json::json!({}),
        idempotency_key: None,
    };
    assert!(matches!(adapter.push(&bad).await, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn pull_returns_items_and_rejects_unknown_resource() {
    let mut adapter = mocked_and_configured();
    assert!(adapter.init(&fixture_config(AliCloudService::Cms, true)).await.is_ok());
    let response = adapter.pull(&PullRequest::default()).await;
    assert!(response.is_ok());
    if let Ok(response) = response {
        assert!(response.mocked);
        assert!(response.origin.contains("mock.rs"));
        assert_eq!(response.items.len(), 3);
    }
    let unknown = PullRequest { resource: "teams".to_string(), ..PullRequest::default() };
    assert!(matches!(adapter.pull(&unknown).await, Err(DomainError::Validation(_))));
}

#[tokio::test]
pub(crate) async fn level_mapping_and_params_shape() {
    let mut event = CmsEvent {
        event_name: "e".to_string(),
        content: "{}".to_string(),
        group_id: "g".to_string(),
        at: Timestamp::now(),
        severity: Severity::Critical,
    };
    assert_eq!(event.level(), "CRITICAL");
    event.severity = Severity::Medium;
    assert_eq!(event.level(), "WARN");
    event.severity = Severity::Low;
    assert_eq!(event.level(), "INFO");
    let params = event.params();
    assert_eq!(params.len(), 4);
    assert!(params.iter().any(|(k, _)| k == "EventInfo.1.EventName"));
    assert!(params.iter().any(|(k, v)| k == "EventInfo.1.Time" && v.ends_with("+0000")));
}

#[tokio::test]
pub(crate) async fn metric_params_shape() {
    let mut metric = CmsMetric::new("agf_tokens", 1234.5);
    metric.dimensions.insert("agent_id".to_string(), "a1".to_string());
    let params = metric.params();
    let dims = params.iter().find(|(k, _)| k == "MetricList.1.Dimensions").map(|(_, v)| v.clone()).unwrap_or_default();
    assert!(dims.contains("agent_id"), "维度必须是 JSON 对象: {dims}");
    assert!(params.iter().any(|(k, v)| k == "MetricList.1.Type" && v == "0"));
    assert!(params.iter().any(|(k, v)| k == "MetricList.1.Values" && v.contains("1234")));
}

#[tokio::test]
pub(crate) async fn alarm_callback_token_is_masked() {
    let adapter = CmsAdapter::new();
    let sub = adapter.subscribe_alarm_callback("https://agf.example.com/");
    assert!(sub.is_ok());
    if let Ok(sub) = sub {
        assert!(sub.callback_url.starts_with("https://agf.example.com/api/v1/ingest/webhook/alicloud-cms?token="));
        assert!(sub.verify_token_masked.contains('*'), "token 必须掩码返回");
    }
}

#[tokio::test]
pub(crate) async fn parse_alarm_histories_both_shapes() {
    let response = RpcResponse {
        status: 200,
        body: serde_json::json!({
            "RequestId": "r1",
            "AlarmHistory": [{
                "AlarmId": "alarm-1",
                "RuleName": "CPU 高",
                "InstanceId": "i-123",
                "Level": "CRITICAL",
                "State": "ALARM",
                "Content": "CPU > 90",
                "AlarmTime": 1_700_000_000_000_i64
            }]
        }),
        raw: String::new(),
    };
    let parsed = parse_alarm_histories(&response);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].alarm_id, "alarm-1");
    assert_eq!(parsed[0].at.unix_millis(), 1_700_000_000_000);
    let nested = RpcResponse {
        status: 200,
        body: serde_json::json!({
            "AlarmHistories": {
                "AlarmHistory": [ {"AlarmId": "a2", "Timestamp": "1700000000000"} ]
            }
        }),
        raw: String::new(),
    };
    let parsed = parse_alarm_histories(&nested);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].alarm_id, "a2");
    // 老接口偶发「复数复数」形态
    let doubly = RpcResponse {
        status: 200,
        body: serde_json::json!({ "AlarmHistories": { "AlarmHistories": [ {"AlarmId": "a3"} ] } }),
        raw: String::new(),
    };
    assert_eq!(parse_alarm_histories(&doubly).len(), 1);
}

#[tokio::test]
pub(crate) async fn live_path_builds_signed_request() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({ "RequestId": "req-9" })));
    let mut adapter = CmsAdapter::new();
    let mut config = fixture_config(AliCloudService::Cms, false);
    config.secret_refs.insert("access_key_id".to_string(), agf_core::ids::Id::new());
    config.secret_refs.insert("access_key_secret".to_string(), agf_core::ids::Id::new());
    assert!(adapter.init(&config).await.is_ok());
    assert_eq!(adapter.mode(), AdapterMode::Live);
    assert!(adapter.core().credential.is_none(), "本 crate 未实现真实 STS，凭据需外部注入");
    // 注入凭据后走真实请求构造路径（传输为录制替身，不触网）
    adapter.core_mut().set_credential(Some(crate::credential::CloudCredential::sts(
        "STS.test",
        "sk",
        "token",
        Timestamp::now().offset_secs(3_600),
        CloudCredentialKind::AssumeRole,
    )));
    assert!(adapter.with_recording_transport(transport.clone()).is_ok());
    let request_id = adapter
        .put_event(&CmsEvent {
            event_name: "agf.test".to_string(),
            content: "{}".to_string(),
            group_id: String::new(),
            at: Timestamp::now(),
            severity: Severity::Info,
        })
        .await;
    assert_eq!(request_id.ok().as_deref(), Some("req-9"));
    assert_eq!(transport.call_count().ok(), Some(1));
    let last = transport.last_request().ok().flatten();
    assert!(last.is_some());
    if let Some(last) = last {
        assert_eq!(last.method, "POST");
        assert!(last.query.contains("Action=PutCustomEvent"), "{}", last.query);
        assert!(last.query.contains("Signature="));
        assert!(last.query.contains("AccessKeyId=STS.test"));
    }
    let _ = fixture_integration(CloudCredentialKind::AssumeRole, "1234567890");
}

#[tokio::test]
pub(crate) async fn live_pull_parses_alarm_histories() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({
        "AlarmHistoryList": {"AlarmHistory": [ {"RuleId": "a1", "Level": "WARN", "State": "ALARM", "AlertTime": "1700000000000"} ]}
    })));
    let mut adapter = CmsAdapter::new();
    let mut config = fixture_config(AliCloudService::Cms, false);
    config.secret_refs.insert("access_key_id".to_string(), agf_core::ids::Id::new());
    config.secret_refs.insert("access_key_secret".to_string(), agf_core::ids::Id::new());
    assert!(adapter.init(&config).await.is_ok());
    adapter.core_mut().set_credential(Some(crate::credential::CloudCredential::long_term("ak", "sk")));
    assert!(adapter.with_recording_transport(transport.clone()).is_ok());
    let req = PullRequest { resource: "alarms".to_string(), limit: Some(10), ..PullRequest::default() };
    let items = adapter.pull_alarm_histories(&req).await;
    assert!(items.is_ok(), "{items:?}");
    if let Ok(items) = items {
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].level, "WARN");
        assert_eq!(items[0].at.unix_millis(), 1_700_000_000_000);
    }
    let last = transport.last_request().ok().flatten();
    assert!(last.is_some_and(|r| r.query.contains("Action=DescribeAlertHistoryList")));
}

#[tokio::test]
pub(crate) async fn self_check_and_shutdown() {
    let mut adapter = mocked_and_configured();
    assert!(adapter.init(&fixture_config(AliCloudService::Cms, true)).await.is_ok());
    let health = adapter.self_check().await;
    assert!(health.is_ok());
    if let Ok(health) = health {
        assert!(health.message.unwrap_or_default().contains("Mock"));
    }
    assert_eq!(adapter.transport.call_count().ok(), Some(0));
    assert!(adapter.shutdown().await.is_ok());
    assert!(adapter.shutdown().await.is_ok(), "shutdown 必须幂等");
    assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
}

#[tokio::test]
pub(crate) async fn descriptor_is_complete() {
    let descriptor = CmsAdapter::new().descriptor();
    assert_eq!(descriptor.name, "alicloud-cms");
    assert_eq!(descriptor.capabilities, CAPABILITIES.to_vec());
    assert!(!descriptor.degradation.is_empty());
    assert!(descriptor.mock_location.ends_with("#mock_cms"));
    assert!(descriptor.real_implementation);
}

#[tokio::test]
async fn real_metric_requires_group_and_alarm_pagination_uses_public_shape() {
    let transport = Arc::new(RecordingTransport::with_body(serde_json::json!({ "Code":"200","RequestId":"metric-r" })));
    let mut adapter = CmsAdapter::new();
    adapter.init(&crate::test_support::fixture_config_with_secrets(AliCloudService::Cms, false)).await.unwrap();
    adapter.core_mut().set_credential(Some(crate::credential::CloudCredential::long_term("ak", "sk")));
    adapter.with_recording_transport(transport.clone()).unwrap();
    let mut metric = CmsMetric::new("tokens", 12.5);
    assert!(matches!(adapter.put_metric(&metric).await, Err(DomainError::Validation(_))));
    assert_eq!(transport.call_count().unwrap(), 0);
    metric.group_id = "12345".into();
    metric.dimensions.insert("worker".into(), "worker-1".into());
    assert_eq!(adapter.put_metric(&metric).await.unwrap(), "metric-r");
    let request = transport.last_request().unwrap().unwrap();
    assert!(request.query.contains("Action=PutCustomMetric"));
    assert!(request.query.contains("MetricList.1.GroupId=12345"));
    assert!(request.query.contains("MetricList.1.Values=%7B%22value%22%3A12.5%7D"));
    transport
        .set_body(serde_json::json!({"AlarmHistoryList":{"AlarmHistory":[{
            "RuleId":"rule-one","InstanceName":"ecs-one","AlertTime":1_700_000_000_000_i64,"Level":"P2"
        }]}}))
        .unwrap();
    let request = PullRequest { limit: Some(1), cursor: Some("3".into()), ..PullRequest::default() };
    let page = adapter.pull(&request).await.unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("4"));
    assert_eq!(page.items[0]["resource_id"], "ecs-one");
    let sent = transport.last_request().unwrap().unwrap();
    assert!(sent.query.contains("Action=DescribeAlertHistoryList"));
    assert!(sent.query.contains("Page=3"));
    assert!(!sent.query.contains("StartTime="));
    transport.set_body(serde_json::json!({"unexpected":[]})).unwrap();
    assert!(matches!(adapter.pull(&request).await, Err(DomainError::Parse(_))));
}
