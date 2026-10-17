//! OTLP/HTTP **traces + metrics** 的接入锁定：路由**真的挂上了**（不再是 404）、
//! JSON/Protobuf/gzip 三编码都能收、`partialSuccess` 计数如实、Span/data point 归一化后
//! **落到存储事件**（`trace.id` / `duration_nano` / `metric.name` 等）。
//!
//! ## 为什么单列这个文件
//!
//! 修复前 `traces_router` / `metrics_router` **全仓零调用方**（`main.rs` 只挂 `/v1/logs`），
//! 而能力矩阵却报 `ready`——用户发 `POST /v1/traces` 得到 404，文档却说已实现。
//! 本文件把"路由存在"升级为"路由可服务"：
//!
//! * [`unwired_signals_answer_404_when_router_is_not_mounted`] 是**对照**：不挂路由就是 404，
//!   因此下面"非 404"才有意义；
//! * [`traces_and_metrics_routes_accept_all_three_encodings`] 三编码 × 两信号；
//! * [`partial_success_counts_are_reported_truthfully`] 超限时 `rejectedSpans` / `rejectedDataPoints`；
//! * [`traces_and_metrics_land_as_events_with_their_own_fields`] 落库事件里的字段级断言。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::io::Write as _;
use std::sync::Arc;

use agf_core::enums::{HealthState, IngestProtocol};
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};
use agf_core::time::Timestamp;
use agf_ingest::bus::NoopEventBus;
use agf_ingest::otlp::metrics_signal::OTLP_METRICS_PATH;
use agf_ingest::otlp::traces::OTLP_TRACES_PATH;
use agf_ingest::otlp::{OtlpLogsReceiver, OtlpMetricsReceiver, OtlpTracesReceiver, signal_router};
use agf_ingest::pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink};
use agf_ingest::registry::ParserRegistry;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt as _;

fn log_source(name: &str) -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: name.to_string(),
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
        max_message_bytes: 8 * 1_048_576,
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
        IngestConfig { emit_to_bus: false, dedup_window_secs: 0, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

/// 装配好的三信号路由器（与 `apps/ingest` 调用的是**同一个** `signal_router`）。
fn mounted_app(max_records: usize) -> (Router, Arc<InMemorySink>) {
    let (pipeline, sink) = pipeline_and_sink();
    let logs = Arc::new(OtlpLogsReceiver::new(Arc::clone(&pipeline), log_source("otlp")));
    let traces = Arc::new(
        OtlpTracesReceiver::new(Arc::clone(&pipeline), log_source("otlp-traces")).with_max_records(max_records),
    );
    let metrics = Arc::new(
        OtlpMetricsReceiver::new(Arc::clone(&pipeline), log_source("otlp-metrics")).with_max_records(max_records),
    );
    let (app, mounted) = signal_router(Some(logs), Some(traces), Some(metrics));
    assert_eq!(mounted, vec!["otlp", "otlp-traces", "otlp-metrics"], "三信号必须都被挂载");
    (app, sink)
}

/// 打一次请求，返回 `(状态码, 响应体文本)`。
async fn post(app: &Router, path: &str, content_type: &str, body: Vec<u8>, gzip: bool) -> (StatusCode, String) {
    let body = if gzip {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&body).expect("gzip 压缩");
        encoder.finish().expect("gzip 收尾")
    } else {
        body
    };
    let mut request = Request::builder().method("POST").uri(path).header("content-type", content_type);
    if gzip {
        request = request.header("content-encoding", "gzip");
    }
    let request = request.body(Body::from(body)).expect("构造请求");
    let response = app.clone().oneshot(request).await.expect("请求处理");
    let status = response.status();
    if status.is_success() {
        assert_eq!(response.headers()["content-type"], content_type);
    }
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1_048_576).await.expect("读取响应体");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

// ---------------------------------------------------------------------------
// OTLP/JSON 载荷（形状与 OTLP 规范一致）
// ---------------------------------------------------------------------------

/// `ExportTraceServiceRequest`（JSON）：`count` 条 Span。
fn traces_json(count: usize) -> Vec<u8> {
    let spans: Vec<Value> = (0..count)
        .map(|index| {
            serde_json::json!({
                "traceId": format!("{:032x}", 0x4bf9_2f35_77b3_4da6_a3ce_929d_0e0e_4736_u128 + index as u128),
                "spanId": format!("{:016x}", 0x00f0_67aa_0ba9_02b7_u64 + index as u64),
                "parentSpanId": "00f067aa0ba90200",
                "name": format!("GET /checkout/{index}"),
                "kind": 2,
                "startTimeUnixNano": format!("{}", 1_771_669_425_000_000_000_u64 + index as u64 * 1_000_000),
                "endTimeUnixNano": format!("{}", 1_771_669_425_000_000_000_u64 + index as u64 * 1_000_000 + 12_300_000),
                "attributes": [
                    {"key": "http.status_code", "value": {"intValue": "500"}},
                    {"key": "sim.index", "value": {"intValue": index.to_string()}}
                ],
                "status": {"code": 2, "message": "upstream timeout"}
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "resourceSpans": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "agf-otlp-sim-traces"}},
                {"key": "host.name", "value": {"stringValue": "agf-sim-host"}}
            ]},
            "scopeSpans": [{
                "scope": {"name": "tools.simulators.otlp_signals", "version": "1.0.0"},
                "spans": spans
            }]
        }]
    }))
    .expect("traces JSON 序列化")
}

/// `ExportMetricsServiceRequest`（JSON）：`count` 个 Gauge data point。
fn metrics_json(count: usize) -> Vec<u8> {
    let points: Vec<Value> = (0..count)
        .map(|index| {
            serde_json::json!({
                "timeUnixNano": format!("{}", 1_771_669_425_000_000_000_u64 + index as u64 * 1_000_000),
                "asDouble": 12.5 + index as f64,
                "attributes": [{"key": "sim.index", "value": {"intValue": index.to_string()}}]
            })
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "resourceMetrics": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "agf-otlp-sim-metrics"}}
            ]},
            "scopeMetrics": [{
                "scope": {"name": "tools.simulators.otlp_signals", "version": "1.0.0"},
                "metrics": [{
                    "name": "checkout.latency_ms",
                    "description": "checkout latency",
                    "unit": "ms",
                    "gauge": {"dataPoints": points}
                }]
            }]
        }]
    }))
    .expect("metrics JSON 序列化")
}

// ---------------------------------------------------------------------------
// 手写 protobuf 编码（wire-format；与 `otlp::proto::Reader` 的字段号一一对应）
// ---------------------------------------------------------------------------

fn varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn tag(field: u32, wire: u8, out: &mut Vec<u8>) {
    varint(u64::from(field) << 3 | u64::from(wire), out);
}

fn len_field(field: u32, payload: &[u8], out: &mut Vec<u8>) {
    tag(field, 2, out);
    varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn varint_field(field: u32, value: u64, out: &mut Vec<u8>) {
    tag(field, 0, out);
    varint(value, out);
}

fn fixed64_field(field: u32, value: u64, out: &mut Vec<u8>) {
    tag(field, 1, out);
    out.extend_from_slice(&value.to_le_bytes());
}

fn any_string(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    len_field(1, text.as_bytes(), &mut out);
    out
}

fn key_value(key: &str, any: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    len_field(1, key.as_bytes(), &mut out);
    len_field(2, any, &mut out);
    out
}

fn resource(service: &str) -> Vec<u8> {
    let mut out = Vec::new();
    len_field(1, &key_value("service.name", &any_string(service)), &mut out);
    len_field(1, &key_value("host.name", &any_string("agf-sim-host")), &mut out);
    out
}

/// `ExportTraceServiceRequest`（protobuf）：`count` 条 Span。
fn traces_protobuf(count: usize) -> Vec<u8> {
    let base = 1_771_669_425_000_000_000_u64;
    let mut spans = Vec::new();
    for index in 0..count {
        let mut span = Vec::new();
        len_field(
            1,
            &[0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e, 0x47, 0x36],
            &mut span,
        );
        len_field(2, &[0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7], &mut span);
        len_field(4, &[0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0x00], &mut span);
        len_field(5, format!("GET /checkout/{index}").as_bytes(), &mut span);
        varint_field(6, 2, &mut span);
        fixed64_field(7, base + index as u64 * 1_000_000, &mut span);
        fixed64_field(8, base + index as u64 * 1_000_000 + 12_300_000, &mut span);
        let mut status = Vec::new();
        len_field(2, b"upstream timeout", &mut status);
        varint_field(3, 2, &mut status);
        len_field(15, &status, &mut span);
        len_field(2, &span, &mut spans);
    }
    let mut scope_spans = Vec::new();
    let mut scope = Vec::new();
    len_field(1, b"tools.simulators.otlp_signals", &mut scope);
    len_field(2, b"1.0.0", &mut scope);
    len_field(1, &scope, &mut scope_spans);
    scope_spans.extend_from_slice(&spans);
    let mut resource_spans = Vec::new();
    len_field(1, &resource("agf-otlp-sim-traces"), &mut resource_spans);
    len_field(2, &scope_spans, &mut resource_spans);
    let mut out = Vec::new();
    len_field(1, &resource_spans, &mut out);
    out
}

/// `ExportMetricsServiceRequest`（protobuf）：`count` 个 Gauge data point。
fn metrics_protobuf(count: usize) -> Vec<u8> {
    let base = 1_771_669_425_000_000_000_u64;
    let mut points = Vec::new();
    for index in 0..count {
        let mut point = Vec::new();
        fixed64_field(3, base + index as u64 * 1_000_000, &mut point);
        fixed64_field(4, (12.5_f64 + index as f64).to_bits(), &mut point);
        let mut any = Vec::new();
        varint_field(3, index as u64, &mut any);
        len_field(7, &key_value("sim.index", &any), &mut point);
        len_field(1, &point, &mut points);
    }
    let mut gauge = Vec::new();
    gauge.extend_from_slice(&points);
    let mut metric = Vec::new();
    len_field(1, b"checkout.latency_ms", &mut metric);
    len_field(2, b"checkout latency", &mut metric);
    len_field(3, b"ms", &mut metric);
    len_field(5, &gauge, &mut metric);
    let mut scope_metrics = Vec::new();
    let mut scope = Vec::new();
    len_field(1, b"tools.simulators.otlp_signals", &mut scope);
    len_field(2, b"1.0.0", &mut scope);
    len_field(1, &scope, &mut scope_metrics);
    len_field(2, &metric, &mut scope_metrics);
    let mut resource_metrics = Vec::new();
    len_field(1, &resource("agf-otlp-sim-metrics"), &mut resource_metrics);
    len_field(2, &scope_metrics, &mut resource_metrics);
    let mut out = Vec::new();
    len_field(1, &resource_metrics, &mut out);
    out
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

/// **对照组**：不挂路由就是 404——因此后面"非 404"确实证明了"路由真的挂上了"。
#[tokio::test]
async fn unwired_signals_answer_404_when_router_is_not_mounted() {
    let (app, _sink) = signal_router(None, None, None);
    let (status, _) = post(&app, OTLP_TRACES_PATH, "application/json", traces_json(1), false).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "未装配 traces 路由必须 404（这正是修复前的线上表现）");
    let (status, _) = post(&app, OTLP_METRICS_PATH, "application/json", metrics_json(1), false).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "未装配 metrics 路由必须 404");
}

/// 三编码（JSON / Protobuf / gzip）× 两信号：都必须 200 且响应体 `{}`（无部分失败）。
#[tokio::test]
async fn traces_and_metrics_routes_accept_all_three_encodings() {
    let (app, sink) = mounted_app(10_000);
    let mut expected_events = 0_usize;
    for (path, label, json, protobuf, want) in [
        (OTLP_TRACES_PATH, "traces", traces_json(3), traces_protobuf(3), 3_usize),
        (OTLP_METRICS_PATH, "metrics", metrics_json(3), metrics_protobuf(3), 3_usize),
    ] {
        for (mode, body, gzip) in
            [("json", json.clone(), false), ("protobuf", protobuf.clone(), false), ("gzip", json.clone(), true)]
        {
            let content_type = if mode == "protobuf" { "application/x-protobuf" } else { "application/json" };
            let (status, text) = post(&app, path, content_type, body, gzip).await;
            assert_eq!(status, StatusCode::OK, "{label}/{mode} 必须 200，实际 {status} body={text}");
            assert_eq!(text, if mode == "protobuf" { "" } else { "{}" }, "{label}/{mode} uses the request encoding");
            println!("POST {path} [{label}/{mode}] -> {status} {text}");
        }
        expected_events += want * 3;
        let events = sink.events().expect("事件快照");
        assert_eq!(events.len(), expected_events, "{label} 三编码各 {want} 条 ⇒ 累计 {expected_events} 条事件");
    }
}

/// 超限：超出部分必须**如实**回填 `partialSuccess.rejectedSpans` / `rejectedDataPoints`。
#[tokio::test]
async fn partial_success_counts_are_reported_truthfully() {
    let (app, sink) = mounted_app(2);
    let (status, text) = post(&app, OTLP_TRACES_PATH, "application/json", traces_json(5), false).await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_str(&text).expect("响应体是 JSON");
    assert_eq!(body["partialSuccess"]["rejectedSpans"], Value::from(3), "5 条上限 2 ⇒ 拒绝 3: {text}");
    assert!(body["partialSuccess"]["errorMessage"].as_str().is_some_and(|m| m.contains("上限")), "{text}");
    println!("traces 超限响应：{text}");

    let (status, text) = post(&app, OTLP_METRICS_PATH, "application/json", metrics_json(5), false).await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_str(&text).expect("响应体是 JSON");
    assert_eq!(body["partialSuccess"]["rejectedDataPoints"], Value::from(3), "5 条上限 2 ⇒ 拒绝 3: {text}");
    println!("metrics 超限响应：{text}");

    // 收下的 2 + 2 条必须真的落库（拒绝不是"整包丢弃"）
    let events = sink.events().expect("事件快照");
    assert_eq!(events.len(), 4, "被接受的 2+2 条必须落库");
}

/// 落库事件里的字段级断言：`trace.id` / `duration_nano` / `metric.name` / `metric.value`。
#[tokio::test]
async fn traces_and_metrics_land_as_events_with_their_own_fields() {
    let (app, sink) = mounted_app(10_000);
    let (status, text) = post(&app, OTLP_TRACES_PATH, "application/json", traces_json(1), false).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let (status, text) = post(&app, OTLP_METRICS_PATH, "application/json", metrics_json(1), false).await;
    assert_eq!(status, StatusCode::OK, "{text}");

    let events = sink.events().expect("事件快照");
    assert_eq!(events.len(), 2);
    let trace = events.iter().find(|e| e.extra.get("otel.event.category").and_then(Value::as_str) == Some("trace"));
    let trace = trace
        .unwrap_or_else(|| panic!("必须有一条 trace 事件: {:?}", events.iter().map(|e| &e.extra).collect::<Vec<_>>()));
    assert_eq!(
        trace.extra.get("trace.id").and_then(Value::as_str),
        Some("4bf92f3577b34da6a3ce929d0e0e4736"),
        "落库事件必须含 trace.id: {:?}",
        trace.extra
    );
    assert_eq!(
        trace.extra.get("duration_nano").and_then(Value::as_u64),
        Some(12_300_000),
        "落库事件必须含 duration_nano"
    );
    assert_eq!(trace.extra.get("service.name").and_then(Value::as_str), Some("agf-otlp-sim-traces"));
    assert!(trace.message.contains("GET /checkout/0"), "message 取自 span 名称: {}", trace.message);
    assert_eq!(trace.network.source_ip, None, "trace 事件不含源 IP（不猜语义）");

    let metric = events.iter().find(|e| e.extra.get("otel.event.category").and_then(Value::as_str) == Some("metric"));
    let metric = metric.unwrap_or_else(|| panic!("必须有一条 metric 事件"));
    assert_eq!(metric.extra.get("metric.name").and_then(Value::as_str), Some("checkout.latency_ms"));
    assert_eq!(metric.extra.get("metric.type").and_then(Value::as_str), Some("gauge"));
    assert_eq!(metric.extra.get("metric.value").and_then(Value::as_f64), Some(12.5));
    assert_eq!(metric.extra.get("metric.unit").and_then(Value::as_str), Some("ms"));
    println!("trace 事件 extra 键：{:?}", trace.extra.keys().collect::<Vec<_>>());
    println!("metric 事件 extra 键：{:?}", metric.extra.keys().collect::<Vec<_>>());
}

/// 不受支持的编码是**调用方错误**（4xx），不能假装"部分成功"。
#[tokio::test]
async fn unsupported_media_type_is_rejected_with_4xx() {
    let (app, _sink) = mounted_app(10_000);
    let (status, text) = post(&app, OTLP_TRACES_PATH, "text/plain", b"not otlp".to_vec(), false).await;
    assert!(status.is_client_error(), "必须 4xx，实际 {status} body={text}");
    println!("不支持编码 -> {status} {text}");
}

#[tokio::test]
async fn pipeline_batch_limits_are_counted_for_every_signal() {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = Arc::new(IngestPipeline::new(
        ParserRegistry::with_builtins(),
        sink.clone(),
        Arc::new(NoopEventBus),
        IngestConfig { batch_limit: 1, emit_to_bus: false, dedup_window_secs: 0, ..IngestConfig::default() },
    ));
    let (app, _) = signal_router(
        Some(Arc::new(OtlpLogsReceiver::new(pipeline.clone(), log_source("logs")))),
        Some(Arc::new(OtlpTracesReceiver::new(pipeline.clone(), log_source("traces")))),
        Some(Arc::new(OtlpMetricsReceiver::new(pipeline, log_source("metrics")))),
    );
    let logs = serde_json::to_vec(&serde_json::json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[
        {"body":{"stringValue":"one"}}, {"body":{"stringValue":"two"}}, {"body":{"stringValue":"three"}}
    ]}]}]}))
    .unwrap();
    for (path, body, field) in [
        ("/v1/logs", logs, "rejectedLogRecords"),
        (OTLP_TRACES_PATH, traces_json(3), "rejectedSpans"),
        (OTLP_METRICS_PATH, metrics_json(3), "rejectedDataPoints"),
    ] {
        let (status, text) = post(&app, path, "application/json", body, false).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["partialSuccess"][field], 2, "{path}: {text}");
    }
    assert_eq!(sink.events().unwrap().len(), 3);
}
