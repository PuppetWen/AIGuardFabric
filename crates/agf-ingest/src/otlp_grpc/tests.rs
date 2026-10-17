//! OTLP/gRPC 单元测试：配置解读、请求映射、gzip 与真实 gRPC 导出落库。

use super::*;
use crate::bus::NoopEventBus;
use crate::otlp::OtlpLogsReceiver;
use crate::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use crate::registry::ParserRegistry;
use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use std::collections::BTreeMap;

/// 测试用"环境变量表"：拥有所有权，避免闭包与临时 `HashMap` 的生命周期纠缠。
struct EnvMap(BTreeMap<String, String>);

impl EnvMap {
    fn new(pairs: &[(&str, &str)]) -> Self {
        Self(pairs.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect())
    }

    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

fn text(value: &str) -> AnyValue {
    AnyValue { value: Some(any_value::Value::StringValue(value.to_string())) }
}

fn attr(key: &str, value: &str) -> KeyValue {
    KeyValue { key: key.to_string(), value: Some(text(value)) }
}

/// 一条可复现的导出请求：resource(service.name/host.name) + scope + 2 条 LogRecord。
fn sample_request() -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![attr("service.name", "checkout"), attr("host.name", "prod-01")],
                dropped_attributes_count: 0,
                entity_refs: vec![],
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(opentelemetry_proto::tonic::common::v1::InstrumentationScope {
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
                        body: Some(text("upstream timeout after 3000ms")),
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
                        body: Some(text("cache warm-up done")),
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

fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "otlp-grpc-test".to_string(),
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

#[test]
fn config_defaults_and_overrides() {
    let empty = EnvMap::new(&[]);
    let defaults = OtlpGrpcConfig::from_lookup(|key| empty.get(key));
    assert_eq!(defaults, OtlpGrpcConfig::default());
    assert!(defaults.enabled, "默认必须启用（OTLP/gRPC 是 OTel 缺省协议）");
    assert_eq!(defaults.listen, "0.0.0.0:4317");
    assert_eq!(defaults.max_records, 10_000);
    assert_eq!(defaults.max_message_bytes, 16 * 1024 * 1024);
    assert!(defaults.socket_addr().is_ok());

    let custom_env =
        EnvMap::new(&[(ENV_LISTEN, "127.0.0.1:14317"), (ENV_MAX_RECORDS, "7"), (ENV_MAX_MESSAGE_BYTES, "2048")]);
    let custom = OtlpGrpcConfig::from_lookup(|key| custom_env.get(key));
    assert_eq!(custom.listen, "127.0.0.1:14317");
    assert_eq!(custom.max_records, 7);
    assert_eq!(custom.max_message_bytes, 2048);
    assert_eq!(custom.socket_addr().ok().map(|a| a.port()), Some(14317));
}

#[test]
fn config_disables_and_tolerates_bad_values() {
    for off in ["0", "false", "no", "off", "OFF"] {
        let env = EnvMap::new(&[(ENV_ENABLED, off)]);
        let config = OtlpGrpcConfig::from_lookup(|key| env.get(key));
        assert!(!config.enabled, "{off} 必须关闭 gRPC 监听");
    }
    // 非法值只 warn + 回退默认，绝不 panic / 不让进程起不来
    let broken = EnvMap::new(&[
        (ENV_ENABLED, "maybe"),
        (ENV_MAX_RECORDS, "ten"),
        (ENV_MAX_MESSAGE_BYTES, "-1"),
        (ENV_LISTEN, "   "),
    ]);
    let config = OtlpGrpcConfig::from_lookup(|key| broken.get(key));
    assert!(config.enabled, "无法识别的开关必须回退默认（启用）");
    assert_eq!(config.max_records, 10_000);
    assert_eq!(config.max_message_bytes, 16 * 1024 * 1024);
    assert_eq!(config.listen, "0.0.0.0:4317");
    // 非法监听地址：配置照旧保留原文（由其后的绑定失败如实汇报），解析时明确报错
    let bad_env = EnvMap::new(&[(ENV_LISTEN, "not-an-addr")]);
    let bad = OtlpGrpcConfig::from_lookup(|key| bad_env.get(key));
    assert!(matches!(bad.socket_addr(), Err(DomainError::Config(_))));
    // 0 也要收敛到至少 1 条，避免"任何请求都被全拒"这种运维陷阱
    let zero_env = EnvMap::new(&[(ENV_MAX_RECORDS, "0")]);
    let zero = OtlpGrpcConfig::from_lookup(|key| zero_env.get(key));
    assert_eq!(zero.max_records, 1);
}

#[test]
fn request_maps_to_the_same_json_shape_as_otlp_http() {
    let json = request_to_json(&sample_request());
    assert!(json.is_ok(), "{json:?}");
    let Ok(json) = json else { return };
    let text = String::from_utf8_lossy(&json).to_string();
    // with-serde 必须给出 OTLP/JSON 规范形状（否则 HTTP 侧 parse_json 会漏字段）
    for needle in [
        "\"resourceLogs\"",
        "\"scopeLogs\"",
        "\"logRecords\"",
        "\"timeUnixNano\":\"1770985425000000123\"",
        "\"severityNumber\":17",
        "\"severityText\":\"ERROR\"",
        "\"stringValue\":\"upstream timeout after 3000ms\"",
        "\"traceId\":\"4bf92f3577b34da6a3ce929d0e0e4736\"",
        "\"spanId\":\"00f067aa0ba902b7\"",
        "\"key\":\"service.name\"",
        "\"stringValue\":\"checkout\"",
        "\"key\":\"http.status_code\"",
        "\"eventName\":\"exception\"",
        "\"name\":\"my.instrumentation\"",
    ] {
        assert!(text.contains(needle), "OTLP/JSON 缺少 {needle}: {text}");
    }
}

#[test]
fn grpc_request_and_http_json_produce_identical_payloads() {
    let request = sample_request();
    let via_grpc = request_to_records(&request);
    assert!(via_grpc.is_ok(), "{via_grpc:?}");
    let via_http = crate::otlp::parse_json(&request_to_json(&request).unwrap_or_default());
    assert!(via_http.is_ok(), "{via_http:?}");
    let (Ok(grpc_records), Ok(http_records)) = (via_grpc, via_http) else { return };
    assert_eq!(grpc_records.len(), 2);
    assert_eq!(grpc_records, http_records, "gRPC 与 HTTP 的中间形态必须逐字段一致");
    let first = grpc_records.first().cloned().unwrap_or_default();
    assert_eq!(first.body.as_deref(), Some("upstream timeout after 3000ms"));
    assert_eq!(first.severity_label(), "ERROR");
    assert_eq!(first.severity_number, Some(17));
    assert_eq!(first.trace_id.as_deref(), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
    assert_eq!(first.span_id.as_deref(), Some("00f067aa0ba902b7"));
    assert_eq!(first.event_name.as_deref(), Some("exception"));
    assert_eq!(first.resource.get("service.name").map(String::as_str), Some("checkout"));
    assert_eq!(first.attributes.get("http.status_code").map(String::as_str), Some("504"));
    assert_eq!(first.scope_name.as_deref(), Some("my.instrumentation"));
    assert_eq!(first.timestamp_rfc3339().as_deref(), Some("2026-02-13T12:23:45.000000123Z"));
    assert_eq!(first.to_payload(), http_records.first().map(OtlpLogRecord::to_payload).unwrap_or_default());
    assert_eq!(count_log_records(&request), 2);
}

#[test]
fn partial_success_is_reported_only_when_records_are_rejected() {
    let clean = OtlpIngestReport { received: 3, persisted: 3, ..OtlpIngestReport::default() };
    assert!(report_to_response(&clean).partial_success.is_none(), "全收下时不设 partial_success");
    let partial = OtlpIngestReport {
        received: 5,
        persisted: 3,
        rejected: 2,
        error_message: Some("超过单请求上限 3，2 条被拒绝".to_string()),
        ..OtlpIngestReport::default()
    };
    let response = report_to_response(&partial);
    assert!(response.partial_success.is_some(), "有拒绝时必须回填 partial_success");
    if let Some(success) = response.partial_success {
        assert_eq!(success.rejected_log_records, 2);
        assert!(success.error_message.contains("超过单请求上限"));
    }
    // 整包拒绝：rejected 用请求内的 LogRecord 条数，不猜
    let response = partial_success_response(count_log_records(&sample_request()), "boom".to_string());
    assert_eq!(response.partial_success.map(|p| p.rejected_log_records), Some(2));
}

#[tokio::test]
async fn grpc_export_persists_events_and_reports_counters() {
    let (pipeline, sink) = pipeline_and_sink();
    let receiver = Arc::new(OtlpLogsReceiver::new(pipeline, log_source()));
    let config = OtlpGrpcConfig { listen: "127.0.0.1:0".to_string(), ..OtlpGrpcConfig::default() };
    let server = OtlpGrpcServer::bind(&config.listen, &config, Arc::clone(&receiver)).await;
    assert!(server.is_ok(), "{server:?}");
    let Ok(server) = server else { return };
    let addr = server.local_addr();
    assert!(addr.is_ok(), "{addr:?}");
    let Ok(addr) = addr else { return };
    assert_ne!(addr.port(), 0, "必须汇报内核实际分配的端口");
    let serving = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    let endpoint = format!("http://{addr}");
    let client =
        opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient::connect(endpoint)
            .await;
    assert!(client.is_ok(), "真实 gRPC 客户端必须能连上：{client:?}");
    let Ok(mut client) = client else { return };
    let response = client.export(sample_request()).await;
    assert!(response.is_ok(), "{response:?}");
    let response = response.map(tonic::Response::into_inner).unwrap_or_default();
    assert!(response.partial_success.is_none(), "全部收下时不应有 partial_success");

    let landed = sink.event_count(TenantId::default_tenant()).await.unwrap_or(0);
    assert_eq!(landed, 2, "两条 LogRecord 必须经同一 pipeline 落库");
    let snapshot = receiver.counters().snapshot();
    assert_eq!(snapshot.received, 2);
    assert_eq!(snapshot.matched, 2, "两条记录都必须命中内置模板");
    serving.abort();
}

#[tokio::test]
async fn grpc_export_over_limit_returns_partial_success() {
    let (pipeline, _sink) = pipeline_and_sink();
    let receiver = Arc::new(OtlpLogsReceiver::new(pipeline, log_source()).with_max_records(1));
    let config = OtlpGrpcConfig { listen: "127.0.0.1:0".to_string(), ..OtlpGrpcConfig::default() };
    let server = OtlpGrpcServer::bind(&config.listen, &config, Arc::clone(&receiver)).await;
    assert!(server.is_ok(), "{server:?}");
    let Ok(server) = server else { return };
    let Ok(addr) = server.local_addr() else { return };
    let serving = tokio::spawn(async move {
        let _ = server.serve().await;
    });
    let client = opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient::connect(
        format!("http://{addr}"),
    )
    .await;
    assert!(client.is_ok(), "{client:?}");
    let Ok(mut client) = client else { return };
    let response = client.export(sample_request()).await;
    assert!(response.is_ok(), "{response:?}");
    let response = response.map(tonic::Response::into_inner).unwrap_or_default();
    assert!(response.partial_success.is_some(), "超限必须回填 partial_success");
    if let Some(success) = response.partial_success {
        assert_eq!(success.rejected_log_records, 1, "2 条记录、上限 1 条 ⇒ 拒绝 1 条");
        assert!(success.error_message.contains("超过单请求上限"), "{}", success.error_message);
    }
    serving.abort();
}

#[tokio::test]
async fn bind_failure_is_reported_without_panicking() {
    let (pipeline, _sink) = pipeline_and_sink();
    let receiver = Arc::new(OtlpLogsReceiver::new(pipeline, log_source()));
    // 先占一个端口，再让 gRPC 去绑同一个端口：必须**返回错误**而不是 panic
    let holder = TcpListener::bind("127.0.0.1:0").await;
    assert!(holder.is_ok(), "{holder:?}");
    let Ok(holder) = holder else { return };
    let Ok(addr) = holder.local_addr() else { return };
    let config = OtlpGrpcConfig { listen: addr.to_string(), ..OtlpGrpcConfig::default() };
    let bound = OtlpGrpcServer::bind(&config.listen, &config, receiver).await;
    assert!(matches!(bound, Err(DomainError::DependencyUnavailable { .. })), "端口被占用必须如实报错：{bound:?}");
    // 非法地址同样只报错
    let bad = OtlpGrpcConfig { listen: "1.2.3.4:99999".to_string(), ..OtlpGrpcConfig::default() };
    let (pipeline, _sink) = pipeline_and_sink();
    let receiver = Arc::new(OtlpLogsReceiver::new(pipeline, log_source()));
    let bound = OtlpGrpcServer::bind(&bad.listen, &bad, receiver).await;
    assert!(matches!(bound, Err(DomainError::Config(_))), "{bound:?}");
}
