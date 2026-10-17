//! CMS 上报结果与调度回执回归：仅合成凭据和录制传输，不读取真实凭据或触网。
use super::*;
use agf_alicloud::{
    AdapterMode,
    credential::CloudCredential,
    http::{RecordingTransport, RpcRequest, RpcResponse, Transport},
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::deterministic_id,
};
use std::collections::BTreeSet;

#[derive(Debug)]
struct MetricTransport {
    recording: RecordingTransport,
    failures: Mutex<BTreeSet<String>>,
}

impl MetricTransport {
    fn new(failures: &[&str]) -> Self {
        Self {
            recording: RecordingTransport::default(),
            failures: Mutex::new(failures.iter().map(|name| (*name).to_owned()).collect()),
        }
    }
}

impl Transport for MetricTransport {
    fn send(&self, request: &RpcRequest) -> DomainResult<RpcResponse> {
        let name = request
            .query
            .split('&')
            .find_map(|pair| pair.strip_prefix("MetricList.1.MetricName="))
            .ok_or_else(|| DomainError::Validation("测试请求缺少指标名".into()))?;
        let failures = self.failures.lock().map_err(|_| DomainError::Internal("测试响应锁中毒".into()))?;
        let body = if failures.contains(name) {
            serde_json::json!({"Code":"Forbidden.RAM", "Message":"synthetic rejection", "RequestId":"cms-rejected"})
        } else {
            serde_json::json!({"Code":"200", "RequestId":format!("cms-accepted-{name}")})
        };
        self.recording.set_body(body)?;
        self.recording.send(request)
    }
}

async fn live_recorded(transport: Arc<dyn Transport>) -> CmsAdapter {
    let mut adapter = CmsAdapter::new();
    // Mock 初始化只解析 endpoint；随后明确切换到 Live + 合成凭据 + 录制传输。
    // 既不依赖 AGF_MOCK_MODE，也不进入 EnvResolver 或创建真实网络客户端。
    let mut config = live_cms_config("cn-hangzhou");
    config.mock = true;
    config.settings.remove("credential_source");
    adapter.init(&config).await.unwrap();
    adapter.core_mut().mode = AdapterMode::Live;
    adapter
        .core_mut()
        .set_credential(Some(CloudCredential::long_term("owned-cms-access-key", "owned-cms-signing-secret")));
    adapter.with_recording_transport(transport).unwrap();
    adapter
}

fn metrics() -> Vec<(String, f64)> {
    cms_metrics(&[snapshot("rules-regression", 7, 2, 10)], Some(12), Some(0.75))
}

#[tokio::test]
async fn cms_partial_failures_attempt_every_metric_and_report_actual_counts() {
    for failures in [
        vec!["agf_scheduler_task_runs"],
        vec!["agf_scheduler_task_runs", "agf_scheduler_task_failures", "agf_rules_total"],
    ] {
        let transport = Arc::new(MetricTransport::new(&failures));
        let adapter = live_recorded(transport.clone()).await;
        let outcome = run_cms_push_with(&adapter, &metrics(), "12345", "").await;
        assert!(!outcome.ok, "部分失败不得计为成功：{}", outcome.note);
        assert!(!outcome.degraded && !outcome.skipped);
        assert_eq!(outcome.status_label(), "failed");
        assert!(outcome.note.contains(&format!("{}/4 条已上报", 4 - failures.len())));
        assert!(outcome.note.contains(&format!("失败 {} 条", failures.len())));
        assert!(outcome.note.contains("真实模式"));
        assert!(outcome.note.contains("agf_redteam_success_rate=75"), "成功指标必须保留");
        for name in failures {
            assert!(outcome.note.contains(&format!("{name}:")), "缺少失败指标：{}", outcome.note);
        }
        assert!(outcome.note.contains("synthetic rejection"));
        assert_eq!(transport.recording.call_count().unwrap(), 4, "失败后仍应尝试其他指标");
    }
}

#[tokio::test]
async fn cms_all_failures_preserve_zero_successes_and_every_failure() {
    let metric_values = metrics();
    let names: Vec<_> = metric_values.iter().map(|(name, _)| name.as_str()).collect();
    let transport = Arc::new(MetricTransport::new(&names));
    let adapter = live_recorded(transport.clone()).await;
    let outcome = run_cms_push_with(&adapter, &metric_values, "12345", "").await;
    assert!(!outcome.ok);
    assert_eq!(outcome.status_label(), "failed");
    assert!(outcome.note.contains("0/4 条已上报") && outcome.note.contains("失败 4 条"));
    for name in names {
        assert!(outcome.note.contains(&format!("{name}:")));
        assert!(!outcome.note.contains(&format!("{name}=")), "失败指标不得放入成功列表");
    }
    assert_eq!(transport.recording.call_count().unwrap(), 4);
}

#[tokio::test]
async fn cms_complete_live_success_uses_signed_recording_channel() {
    let transport = Arc::new(MetricTransport::new(&[]));
    let adapter = live_recorded(transport.clone()).await;
    let outcome = run_cms_push_with(&adapter, &metrics(), " 12345 ", "").await;
    assert!(outcome.ok && !outcome.degraded && !outcome.skipped, "{}", outcome.note);
    assert_eq!(outcome.status_label(), "ok");
    assert!(outcome.note.contains("4/4 条已上报") && outcome.note.contains("失败 0 条"));
    assert!(!outcome.note.contains("失败指标") && !outcome.note.contains("Mock"));
    assert_eq!(transport.recording.call_count().unwrap(), 4);
    let request = transport.recording.last_request().unwrap().unwrap();
    assert_eq!(request.method, "POST");
    for query in [
        "Action=PutCustomMetric",
        "MetricList.1.GroupId=12345",
        "MetricList.1.MetricName=agf_redteam_success_rate",
        "AccessKeyId=owned-cms-access-key",
        "Signature=",
    ] {
        assert!(request.query.contains(query), "缺少实际签名请求字段 {query}");
    }
    assert!(!request.query.contains("owned-cms-signing-secret"));
}

#[tokio::test]
async fn cms_live_missing_group_is_failed_before_any_transport_call() {
    let transport = Arc::new(MetricTransport::new(&[]));
    let adapter = live_recorded(transport.clone()).await;
    let outcome = run_cms_push_with(&adapter, &metrics(), "  ", "").await;
    assert!(!outcome.ok && !outcome.degraded);
    assert!(outcome.note.contains("AGF_CMS_GROUP_ID"));
    assert_eq!(transport.recording.call_count().unwrap(), 0);
}

#[tokio::test]
async fn cms_invalid_metric_still_attempts_remaining_valid_metrics() {
    let transport = Arc::new(MetricTransport::new(&[]));
    let adapter = live_recorded(transport.clone()).await;
    let mut metric_values = metrics();
    metric_values[0].1 = f64::NAN;
    let outcome = run_cms_push_with(&adapter, &metric_values, "12345", "").await;
    assert!(!outcome.ok);
    assert!(outcome.note.contains("3/4 条已上报") && outcome.note.contains("失败 1 条"));
    assert!(outcome.note.contains("agf_scheduler_task_runs:") && outcome.note.contains("数值必须有限"));
    assert_eq!(transport.recording.call_count().unwrap(), 3, "非法数值不发送，其余三条照常发送");
}

#[test]
fn cms_failed_outcome_keeps_mock_and_fallback_diagnostics() {
    let outcome = cms_push_outcome(
        true,
        2,
        &["accepted=1（mocked-id）".into()],
        &["rejected: synthetic rejection".into()],
        "初始化失败已回退 Mock；",
    );
    assert!(!outcome.ok && outcome.degraded && !outcome.skipped);
    assert_eq!(outcome.status_label(), "failed", "降级标识不能把失败变成成功");
    assert!(outcome.note.contains("初始化失败已回退 Mock"));
    assert!(outcome.note.contains("1/2 条已上报") && outcome.note.contains("失败 1 条"));
    assert!(outcome.note.contains("未真实触达云监控") && outcome.note.contains("rejected: synthetic rejection"));
}

#[tokio::test]
async fn cms_partial_failure_is_a_failed_receipt_and_can_retry_without_success_cache() {
    use crate::{Partition, Registry, dispatch, metrics_text, tasks_value};
    let name = "alicloud-cms-push";
    let execution_id = "cms-owned-partial";
    let registry = Arc::new(Registry::new());
    let transport = Arc::new(MetricTransport::new(&["agf_rules_total"]));
    let adapter = Arc::new(live_recorded(transport.clone()).await);
    let handler: dispatch::Handler = Arc::new(move |_partition| {
        let adapter = Arc::clone(&adapter);
        Box::pin(async move { run_cms_push_with(&adapter, &metrics(), "12345", "").await })
    });
    let failed = dispatch::execute(&registry, name, execution_id, Arc::clone(&handler)).await.unwrap();
    assert!(!failed.ok && failed.note.contains("3/4 条已上报"));
    assert!(dispatch::completed(&registry, name, execution_id, Partition::default()).await.unwrap().is_none());
    assert!(!dispatch::recent_completion(&registry, name, 300).await.unwrap());
    let tenant = registry.execution.tenant;
    let lane_id = deterministic_id("scheduler-execution", &format!("{tenant}:{name}"));
    let lane = registry
        .execution
        .store
        .get::<serde_json::Value>(tenant, "scheduler-execution", lane_id)
        .await
        .unwrap()
        .unwrap();
    let row = &lane["records"][format!("{execution_id}#0")];
    assert_eq!(row["state"], "failed");
    assert_eq!(row["result"]["ok"], false);
    assert_eq!(row["attempts"], 1);
    let tasks = tasks_value(&registry);
    let cms = tasks["tasks"].as_array().unwrap().iter().find(|item| item["name"] == name).unwrap();
    assert_eq!(cms["runs"], 1);
    assert_eq!(cms["failures"], 1);
    assert!(cms["note"].as_str().unwrap().contains("[failed]"));
    assert!(cms["note"].as_str().unwrap().contains("agf_rules_total:"));
    let (_, _, text) = metrics_text(Arc::clone(&registry));
    assert!(text.contains("agf_scheduler_task_failures_total{task=\"alicloud-cms-push\"} 1"));

    transport.failures.lock().unwrap().clear();
    let recovered = dispatch::execute(&registry, name, execution_id, Arc::clone(&handler)).await.unwrap();
    assert!(recovered.ok && recovered.note.contains("4/4 条已上报"));
    assert_eq!(transport.recording.call_count().unwrap(), 8, "失败回执不应缓存为已成功");
    assert!(dispatch::recent_completion(&registry, name, 300).await.unwrap());
    assert!(dispatch::execute(&registry, name, execution_id, handler).await.unwrap().ok);
    assert_eq!(transport.recording.call_count().unwrap(), 8, "仅完整成功才可复用成功回执");
    let state = registry.state(name).unwrap();
    assert_eq!(state.runs.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(state.failures.load(std::sync::atomic::Ordering::SeqCst), 1);
}
