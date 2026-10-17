//! 对**正在运行的** `agf-ingest` 的 OTLP/gRPC(4317) 端口做真实 gRPC 调用（默认 `#[ignore]`）。
//!
//! 与 `tests/otlp_grpc.rs`（回环自建服务端）互补：这里连的是**真实进程**，用于
//! Docker/宿主端到端验证里"从宿主机直连 4317"的负例与正例证据——
//! 特别是 `partial_success` 的**原始响应文本**。
//!
//! 运行方式（服务端已由 `tools/simulators/run_otlpgrpc_mqtt_e2e.ps1` 拉起）：
//!
//! ```text
//! set AGF_E2E_OTLP_GRPC_ENDPOINT=http://127.0.0.1:4317
//! cargo test -p agf-ingest --test otlp_grpc_live -- --ignored --nocapture
//! ```
//!
//! 未设置该环境变量时用例直接跳过（`cargo test` 默认也不跑 `#[ignore]`，因此
//! **常规测试不依赖任何外部进程/docker**）。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;

/// 环境变量：被测 agf-ingest 的 gRPC 端点（如 `http://127.0.0.1:4317`）。
const ENV_ENDPOINT: &str = "AGF_E2E_OTLP_GRPC_ENDPOINT";

fn endpoint() -> Option<String> {
    std::env::var(ENV_ENDPOINT).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

fn text(value: String) -> AnyValue {
    AnyValue { value: Some(any_value::Value::StringValue(value)) }
}

fn attr(key: &str, value: &str) -> KeyValue {
    KeyValue { key: key.to_string(), value: Some(text(value.to_string())) }
}

/// `count` 条 syslog 正文（内容各不相同，避免被流水线按"同源+同时间+同哈希"去重）。
fn request_with(count: usize) -> ExportLogsServiceRequest {
    let records = (0..count)
        .map(|index| LogRecord {
            time_unix_nano: 1_770_985_425_000_000_000 + u64::try_from(index).unwrap_or(0) * 1_000_000,
            observed_time_unix_nano: 0,
            severity_number: 17,
            severity_text: "ERROR".to_string(),
            body: Some(text(format!(
                "<34>Feb 21 10:23:4{index} live-prod-0{index} sshd[2311]: Failed password for root from 203.0.113.7{index} port 5123{index} ssh2"
            ))),
            attributes: vec![attr("e2e.case", "otlp-grpc-live")],
            dropped_attributes_count: 0,
            flags: 0,
            trace_id: vec![],
            span_id: vec![],
            event_name: String::new(),
        })
        .collect();
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![attr("service.name", "agf-e2e-live")],
                dropped_attributes_count: 0,
                entity_refs: vec![],
            }),
            scope_logs: vec![ScopeLogs { scope: None, log_records: records, schema_url: String::new() }],
            schema_url: String::new(),
        }],
    }
}

#[tokio::test]
#[ignore = "需要正在运行的 agf-ingest（AGF_E2E_OTLP_GRPC_ENDPOINT）"]
async fn live_export_is_accepted_without_partial_success() {
    let Some(endpoint) = endpoint() else {
        println!("[live] {ENV_ENDPOINT} 未设置，跳过");
        return;
    };
    let mut client = LogsServiceClient::connect(endpoint.clone()).await.expect("连接真实 agf-ingest 的 4317");
    let response = client.export(request_with(2)).await.expect("export 调用成功").into_inner();
    println!("[live] endpoint={endpoint} partial_success={:?}", response.partial_success);
    assert!(response.partial_success.is_none(), "2 条记录（默认上限 10000）不应被拒绝");
}

#[tokio::test]
#[ignore = "需要正在运行的 agf-ingest（AGF_E2E_OTLP_GRPC_ENDPOINT）且上限 < 5"]
async fn live_export_over_limit_reports_partial_success() {
    let Some(endpoint) = endpoint() else {
        println!("[live] {ENV_ENDPOINT} 未设置，跳过");
        return;
    };
    let mut client = LogsServiceClient::connect(endpoint.clone()).await.expect("连接真实 agf-ingest 的 4317");
    let response = client.export(request_with(5)).await.expect("export 调用成功").into_inner();
    let partial = response.partial_success.expect("服务端设置了 AGF_INGEST_OTLP_GRPC_MAX_RECORDS=3，第 4/5 条必须被拒");
    println!(
        "[live] endpoint={endpoint} rejected_log_records={} error_message={:?}",
        partial.rejected_log_records, partial.error_message
    );
    assert_eq!(partial.rejected_log_records, 2, "上限 3、发 5 条 ⇒ 拒绝 2 条");
    assert!(!partial.error_message.is_empty(), "拒绝原因必须非空");
}
