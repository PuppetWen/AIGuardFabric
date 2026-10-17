//! OTLP/gRPC(4317) 集成测试：**真实 tonic 客户端 ↔ 真实 gRPC 服务端**（回环，无需 docker）。
//!
//! 覆盖：
//! * `LogsService/Export` 把 LogRecord 经既有 OTLP 映射落到同一 pipeline（事件真的进 Sink）；
//! * 与 OTLP/HTTP 通道的中间形态逐字节一致（不存在"第二套映射"）；
//! * `partial_success` 在超限/整包拒绝时如实回填；
//! * 服务端接受 **gzip** 压缩的 gRPC 消息；
//! * 绑定失败/地址非法只返回错误（不 panic、不让调用方以为"起来了"）。
//!
//! 不依赖 docker：docker 侧的真实验证（collector → 4317）见
//! `tools/simulators/run_otlpgrpc_mqtt_e2e.ps1`。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::sync::Arc;

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::error::DomainError;
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use agf_ingest::bus::NoopEventBus;
use agf_ingest::otlp::{OtlpLogsReceiver, parse_json};
use agf_ingest::otlp_grpc::{
    OtlpGrpcConfig, OtlpGrpcServer, count_log_records, partial_success_response, report_to_response, request_to_json,
    request_to_records,
};
use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use agf_ingest::registry::ParserRegistry;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use tokio::net::TcpListener;

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "otlp-grpc-e2e".to_string(),
        protocol: IngestProtocol::Otlp,
        vendor: "generic".to_string(),
        product: "otlp".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Push,
        poll_interval_secs: None,
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

fn pipeline_and_sink() -> (Arc<IngestPipeline>, Arc<InMemorySink>) {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

fn text(value: &str) -> AnyValue {
    AnyValue { value: Some(any_value::Value::StringValue(value.to_string())) }
}

fn attr(key: &str, value: &str) -> KeyValue {
    KeyValue { key: key.to_string(), value: Some(text(value)) }
}

/// 一条导出请求：resource + scope + 2 条 LogRecord（一条 syslog 正文，一条 JSON）。
fn sample_request() -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![attr("service.name", "checkout"), attr("host.name", "prod-01")],
                dropped_attributes_count: 0,
                entity_refs: vec![],
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "my.instrumentation".to_string(),
                    version: "1.2.3".to_string(),
                    attributes: vec![],
                    dropped_attributes_count: 0,
                }),
                log_records: vec![
                    LogRecord {
                        time_unix_nano: 1_770_985_425_000_000_123,
                        observed_time_unix_nano: 1_770_985_425_000_000_999,
                        severity_number: 17,
                        severity_text: "ERROR".to_string(),
                        body: Some(text(
                            "<34>Feb 21 10:23:45 web-prod-01 sshd[2311]: Failed password for root from 203.0.113.77 port 51234 ssh2",
                        )),
                        attributes: vec![attr("http.status_code", "504")],
                        dropped_attributes_count: 0,
                        flags: 0,
                        trace_id: vec![
                            0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47,
                            0x36,
                        ],
                        span_id: vec![0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7],
                        event_name: "exception".to_string(),
                    },
                    LogRecord {
                        time_unix_nano: 1_770_985_426_000_000_000,
                        observed_time_unix_nano: 0,
                        severity_number: 9,
                        severity_text: String::new(),
                        body: Some(text(r#"{"event":"cache_warmup","ok":true}"#)),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                        flags: 0,
                        trace_id: vec![],
                        span_id: vec![],
                        event_name: String::new(),
                    },
                ],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    }
}

/// 起一个回环服务端，返回 (实际地址, 关闭句柄)。
async fn start_server(receiver: Arc<OtlpLogsReceiver>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let config = OtlpGrpcConfig { listen: "127.0.0.1:0".to_string(), ..OtlpGrpcConfig::default() };
    let server = OtlpGrpcServer::bind(&config.listen, &config, Arc::clone(&receiver)).await.expect("bind 回环端口");
    let addr = server.local_addr().expect("读取绑定地址");
    let handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    (addr, handle)
}

#[tokio::test]
async fn grpc_export_persists_events_into_the_same_pipeline() {
    let (pipeline, sink) = pipeline_and_sink();
    let receiver = Arc::new(OtlpLogsReceiver::new(pipeline, log_source()));
    let (addr, serving) = start_server(Arc::clone(&receiver)).await;

    let mut client = LogsServiceClient::connect(format!("http://{addr}")).await.expect("gRPC 客户端连接");
    let response = client.export(sample_request()).await.expect("export 调用成功");
    let response = response.into_inner();
    assert!(response.partial_success.is_none(), "全部收下时不应有 partial_success");

    let landed = sink.event_count(TenantId::default_tenant()).await.unwrap_or(0);
    assert_eq!(landed, 2, "两条 LogRecord 必须经同一 pipeline 落库");
    let snapshot = receiver.counters().snapshot();
    assert_eq!(snapshot.received, 2);
    assert_eq!(snapshot.matched, 2, "syslog 正文与 JSON 正文都应命中内置模板");
    println!("[grpc] persisted={landed} counters={snapshot:?}");
    serving.abort();
}

#[tokio::test]
async fn grpc_export_over_limit_reports_partial_success() {
    let (pipeline, _sink) = pipeline_and_sink();
    let receiver = Arc::new(OtlpLogsReceiver::new(pipeline, log_source()).with_max_records(1));
    let (addr, serving) = start_server(Arc::clone(&receiver)).await;

    let mut client = LogsServiceClient::connect(format!("http://{addr}")).await.expect("gRPC 客户端连接");
    let response = client.export(sample_request()).await.expect("export 调用成功").into_inner();
    let partial = response.partial_success.expect("超限必须回填 partial_success");
    assert_eq!(partial.rejected_log_records, 1);
    assert!(partial.error_message.contains("超过单请求上限"), "{}", partial.error_message);
    println!("[grpc] partial_success rejected={} message={}", partial.rejected_log_records, partial.error_message);
    serving.abort();
}

#[tokio::test]
async fn grpc_export_accepts_gzip_compressed_messages() {
    let (pipeline, sink) = pipeline_and_sink();
    let receiver = Arc::new(OtlpLogsReceiver::new(pipeline, log_source()));
    let (addr, serving) = start_server(receiver).await;

    let mut client = LogsServiceClient::connect(format!("http://{addr}"))
        .await
        .expect("gRPC 客户端连接")
        .send_compressed(tonic::codec::CompressionEncoding::Gzip);
    let response = client.export(sample_request()).await.expect("gzip 压缩请求必须被接受").into_inner();
    assert!(response.partial_success.is_none());
    let landed = sink.event_count(TenantId::default_tenant()).await.unwrap_or(0);
    assert_eq!(landed, 2, "gzip 压缩通道同样必须落库");
    println!("[grpc] gzip compression accepted, persisted={landed}");
    serving.abort();
}

#[tokio::test]
async fn grpc_and_http_paths_produce_identical_payloads() {
    let request = sample_request();
    let json = request_to_json(&request).expect("请求可序列化为 OTLP/JSON");
    let shape = String::from_utf8_lossy(&json).to_string();
    for needle in [
        "\"resourceLogs\"",
        "\"scopeLogs\"",
        "\"logRecords\"",
        "\"timeUnixNano\":\"1770985425000000123\"",
        "\"severityNumber\":17",
        "\"traceId\":\"4bf92f3577b34da6a3ce929d0e0e4736\"",
        "\"key\":\"service.name\"",
        "\"stringValue\":\"checkout\"",
    ] {
        assert!(shape.contains(needle), "OTLP/JSON 缺少 {needle}: {shape}");
    }
    let via_grpc = request_to_records(&request).expect("gRPC 请求 → 中间形态");
    let via_http = parse_json(&json).expect("OTLP/JSON → 中间形态");
    assert_eq!(via_grpc, via_http, "gRPC 与 HTTP 的中间形态必须逐字段一致");
    assert_eq!(
        via_grpc.first().map(agf_ingest::otlp::OtlpLogRecord::to_payload),
        via_http.first().map(agf_ingest::otlp::OtlpLogRecord::to_payload)
    );
    assert_eq!(count_log_records(&request), 2);
    println!("[grpc] json bytes={} records={}", json.len(), via_grpc.len());
}

#[test]
fn partial_success_helpers_are_honest() {
    let (pipeline, _sink) = pipeline_and_sink();
    let _ = pipeline;
    let clean = agf_ingest::otlp::OtlpIngestReport { received: 3, persisted: 3, ..Default::default() };
    assert!(report_to_response(&clean).partial_success.is_none());
    let rejected = partial_success_response(7, "整包拒绝".to_string());
    let partial = rejected.partial_success.expect("必须带上 partial_success");
    assert_eq!(partial.rejected_log_records, 7);
    assert_eq!(partial.error_message, "整包拒绝");
}

#[tokio::test]
async fn bind_failure_is_reported_as_error() {
    let (pipeline, _sink) = pipeline_and_sink();
    let holder = TcpListener::bind("127.0.0.1:0").await.expect("占用一个端口");
    let taken = holder.local_addr().expect("读取端口").to_string();

    let config = OtlpGrpcConfig { listen: taken.clone(), ..OtlpGrpcConfig::default() };
    let receiver = Arc::new(OtlpLogsReceiver::new(pipeline, log_source()));
    let bound = OtlpGrpcServer::bind(&taken, &config, receiver).await;
    assert!(matches!(bound, Err(DomainError::DependencyUnavailable { .. })), "端口被占用必须如实报错：{bound:?}");

    let bad = OtlpGrpcConfig { listen: "1.2.3.4:99999".to_string(), ..OtlpGrpcConfig::default() };
    let (pipeline, _sink) = pipeline_and_sink();
    let receiver = Arc::new(OtlpLogsReceiver::new(pipeline, log_source()));
    assert!(matches!(OtlpGrpcServer::bind(&bad.listen, &bad, receiver).await, Err(DomainError::Config(_))));
}

#[test]
fn config_parsing_is_lenient_but_configurable() {
    use std::collections::BTreeMap;

    let empty: BTreeMap<String, String> = BTreeMap::new();
    let defaults = OtlpGrpcConfig::from_lookup(|key| empty.get(key).cloned());
    assert_eq!(defaults, OtlpGrpcConfig::default());
    assert!(defaults.enabled);
    assert_eq!(defaults.listen, "0.0.0.0:4317");
    assert_eq!(defaults.socket_addr().map(|a| a.port()).ok(), Some(4317));

    let mut env = BTreeMap::new();
    env.insert("AGF_INGEST_OTLP_GRPC_ENABLED".to_string(), "0".to_string());
    env.insert("AGF_INGEST_OTLP_GRPC_LISTEN".to_string(), "127.0.0.1:14317".to_string());
    env.insert("AGF_INGEST_OTLP_GRPC_MAX_RECORDS".to_string(), "3".to_string());
    env.insert("AGF_INGEST_OTLP_GRPC_MAX_MESSAGE_BYTES".to_string(), "4096".to_string());
    let configured = OtlpGrpcConfig::from_lookup(|key| env.get(key).cloned());
    assert!(!configured.enabled);
    assert_eq!(configured.listen, "127.0.0.1:14317");
    assert_eq!(configured.max_records, 3);
    assert_eq!(configured.max_message_bytes, 4096);
    println!("[grpc] config={configured:?} describe={}", configured.describe());
}
