//! OTLP/HTTP traces 接入（`POST /v1/traces`）：Span → Event（`event.category='trace'`）。
//!
//! 与 [`super::logs`] 同源：JSON 与 Protobuf 双编码、`Content-Encoding: gzip`、单请求上限
//! 与解压上限保护、`partialSuccess.rejectedSpans` 如实回填。每个 Span 归一化为一条 JSON
//! 载荷交给既有 [`crate::pipeline::IngestPipeline`]，含 `event.category='trace'`、
//! `trace.id`/`span.id`/`parent.span.id`、`span_kind`、`duration_nano`、`status_code` 等；
//! `resource`/`attributes` 键保持 OTLP 原文（由解析模板决定落 ECS 的方式）。
//!
//! 接收器与路由见 [`super::traces_receiver`]（`POST /v1/traces`，必须由装配点 merge 到
//! 服务上，否则能力矩阵里的 `otlp-traces` 显示 `not-wired`）。
//!
//! **gRPC `TraceService/Export` 未实现**：[`crate::otlp_grpc`] 只注册了 `LogsService`，
//! 向 TraceService/Export 发送会得到 gRPC `Unimplemented`（显式失败，不假装成功）；
//! 本模块的映射**只服务 OTLP/HTTP 通道**，不存在"HTTP 与 gRPC 共用"的接线。

use std::collections::BTreeMap;

use agf_core::error::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::debug;

use super::{decode_key_value, decode_resource, decode_scope, get, parse_key_values, proto, string_map};

/// OTLP/HTTP traces 端点路径（规范固定值）。
pub const OTLP_TRACES_PATH: &str = "/v1/traces";

/// 一条 Span（ResourceSpans / ScopeSpans 上下文已内联展开）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OtlpSpanRecord {
    /// trace id（hex，32 字符）。
    pub trace_id: Option<String>,
    /// span id（hex，16 字符）。
    pub span_id: Option<String>,
    /// 父 span id（hex；根 span 为空）。
    pub parent_span_id: Option<String>,
    /// span 名称。
    pub name: String,
    /// `SpanKind`（1=INTERNAL 2=SERVER 3=CLIENT 4=PRODUCER 5=CONSUMER）。
    pub kind: i32,
    /// 起始时间（纳秒）。
    pub start_time_unix_nano: Option<u64>,
    /// 结束时间（纳秒）。
    pub end_time_unix_nano: Option<u64>,
    /// `Status.code`（0=UNSET 1=OK 2=ERROR）。
    pub status_code: i32,
    /// `Status.message`。
    pub status_message: Option<String>,
    /// Span 属性。
    pub attributes: BTreeMap<String, String>,
    /// Resource 属性。
    pub resource: BTreeMap<String, String>,
    /// InstrumentationScope 名称。
    pub scope_name: Option<String>,
    /// scope 版本。
    pub scope_version: Option<String>,
    /// dropped attributes 计数（如实透出，便于判断采样丢弃）。
    pub dropped_attributes_count: u32,
    /// dropped events 计数。
    pub dropped_events_count: u32,
    /// dropped links 计数。
    pub dropped_links_count: u32,
}

/// `SpanKind` → 文本。
#[must_use]
pub fn span_kind_name(kind: i32) -> &'static str {
    match kind {
        1 => "internal",
        2 => "server",
        3 => "client",
        4 => "producer",
        5 => "consumer",
        _ => "unspecified",
    }
}

/// `StatusCode` → 文本。
#[must_use]
pub fn status_code_name(code: i32) -> &'static str {
    match code {
        1 => "ok",
        2 => "error",
        _ => "unset",
    }
}

impl OtlpSpanRecord {
    /// RFC3339（带纳秒）起始时间戳。
    #[must_use]
    pub fn timestamp_rfc3339(&self) -> Option<String> {
        let nanos = self.start_time_unix_nano.filter(|v| *v > 0)?;
        let secs = i64::try_from(nanos / 1_000_000_000).ok()?;
        let sub = u32::try_from(nanos % 1_000_000_000).unwrap_or(0);
        let dt = chrono::DateTime::from_timestamp(secs, sub)?;
        Some(dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
    }

    /// span 时长（纳秒）。
    #[must_use]
    pub fn duration_nano(&self) -> Option<u64> {
        let start = self.start_time_unix_nano?;
        let end = self.end_time_unix_nano?;
        Some(end.saturating_sub(start))
    }

    /// 事件来源（`service.name` → `scope.name` → 兜底）。
    #[must_use]
    pub fn origin(&self) -> String {
        self.resource
            .get("service.name")
            .cloned()
            .or_else(|| self.scope_name.clone())
            .unwrap_or_else(|| "otlp-traces".to_string())
    }
}

/// 归一化载荷（交给既有解析流水线的 JSON 文本）。
#[must_use]
pub fn span_payload(span: &OtlpSpanRecord) -> Vec<u8> {
    let mut root = Map::new();
    if let Some(ts) = span.timestamp_rfc3339() {
        root.insert("@timestamp".to_string(), Value::from(ts));
    }
    root.insert("event.category".to_string(), Value::from("trace"));
    root.insert("message".to_string(), Value::from(span.name.clone()));
    root.insert("span_name".to_string(), Value::from(span.name.clone()));
    root.insert("span_kind".to_string(), Value::from(span_kind_name(span.kind)));
    root.insert("status_code".to_string(), Value::from(status_code_name(span.status_code)));
    if let Some(msg) = &span.status_message {
        root.insert("status_message".to_string(), Value::from(msg.clone()));
    }
    if let Some(d) = span.duration_nano() {
        root.insert("duration_nano".to_string(), Value::from(d));
    }
    if let Some(t) = &span.trace_id {
        root.insert("trace.id".to_string(), Value::from(t.clone()));
    }
    if let Some(s) = &span.span_id {
        root.insert("span.id".to_string(), Value::from(s.clone()));
    }
    if let Some(p) = &span.parent_span_id {
        root.insert("parent.span.id".to_string(), Value::from(p.clone()));
    }
    if !span.resource.is_empty() {
        root.insert("resource".to_string(), Value::Object(string_map(&span.resource)));
    }
    if !span.attributes.is_empty() {
        root.insert("attributes".to_string(), Value::Object(string_map(&span.attributes)));
    }
    if span.scope_name.is_some() || span.scope_version.is_some() {
        let mut scope = Map::new();
        if let Some(n) = &span.scope_name {
            scope.insert("name".to_string(), Value::from(n.clone()));
        }
        if let Some(v) = &span.scope_version {
            scope.insert("version".to_string(), Value::from(v.clone()));
        }
        root.insert("scope".to_string(), Value::Object(scope));
    }
    root.insert("service.name".to_string(), Value::from(span.origin()));
    root.entry("event.action".to_string()).or_insert_with(|| Value::from("span"));
    Value::Object(root).to_string().into_bytes()
}

/// OTLP/JSON 的 `int64-as-string` 与裸数字都要能读。
fn as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<u64>().ok()))
        .or_else(|| value.as_i64().and_then(|v| u64::try_from(v).ok()))
}

/// 枚举字段（数字或字符串）→ `i32`。
fn as_i32(value: &Value) -> Option<i32> {
    value.as_i64().and_then(|v| i32::try_from(v).ok()).or_else(|| value.as_str().and_then(|s| s.parse::<i32>().ok()))
}

/// 非全零 hex（OTLP 用全 0 表示"未设置"id）。
fn non_zero_hex(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(ToString::to_string).filter(|s| !s.is_empty() && s.chars().any(|c| c != '0'))
}

/// 读取 `dropped*Count`（uint32）。
fn as_u32(value: Option<&Value>) -> u32 {
    value.and_then(as_u64).and_then(|v| u32::try_from(v).ok()).unwrap_or(0)
}
/// OTLP/JSON 解析（`resourceSpans → scopeSpans → spans`）。
///
/// # Errors
/// JSON 非法或顶层不是对象。
pub fn parse_traces_json(body: &[u8]) -> DomainResult<Vec<OtlpSpanRecord>> {
    let root: Value =
        serde_json::from_slice(body).map_err(|e| DomainError::Parse(format!("OTLP/JSON traces 解析失败: {e}")))?;
    let Some(object) = root.as_object() else {
        return Err(DomainError::Parse("OTLP/JSON 顶层必须是对象（ExportTraceServiceRequest）".to_string()));
    };
    let mut out = Vec::new();
    for resource_span in
        get(&root, &["resourceSpans", "resource_spans"]).and_then(Value::as_array).into_iter().flatten()
    {
        let mut resource_attrs = BTreeMap::new();
        parse_key_values(get(resource_span, &["resource"]).and_then(|r| get(r, &["attributes"])), &mut resource_attrs);
        let scope_spans =
            get(resource_span, &["scopeSpans", "scope_spans", "instrumentationLibrarySpans"]).and_then(Value::as_array);
        for scope_span in scope_spans.into_iter().flatten() {
            let scope = get(scope_span, &["scope", "instrumentationLibrary"]);
            let scope_name = scope.and_then(|s| get(s, &["name"])).and_then(Value::as_str).map(ToString::to_string);
            let scope_version =
                scope.and_then(|s| get(s, &["version"])).and_then(Value::as_str).map(ToString::to_string);
            for span in get(scope_span, &["spans"]).and_then(Value::as_array).into_iter().flatten() {
                let mut parsed = OtlpSpanRecord {
                    resource: resource_attrs.clone(),
                    scope_name: scope_name.clone(),
                    scope_version: scope_version.clone(),
                    ..OtlpSpanRecord::default()
                };
                parsed.trace_id = non_zero_hex(get(span, &["traceId", "trace_id"]));
                parsed.span_id = non_zero_hex(get(span, &["spanId", "span_id"]));
                parsed.parent_span_id = non_zero_hex(get(span, &["parentSpanId", "parent_span_id"]));
                parsed.name = get(span, &["name"]).and_then(Value::as_str).unwrap_or_default().to_string();
                parsed.kind = get(span, &["kind"]).and_then(as_i32).unwrap_or(0);
                parsed.start_time_unix_nano =
                    get(span, &["startTimeUnixNano", "start_time_unix_nano"]).and_then(as_u64);
                parsed.end_time_unix_nano = get(span, &["endTimeUnixNano", "end_time_unix_nano"]).and_then(as_u64);
                let status = get(span, &["status"]);
                parsed.status_code = status.and_then(|s| get(s, &["code"])).and_then(as_i32).unwrap_or(0);
                parsed.status_message = status
                    .and_then(|s| get(s, &["message"]))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .filter(|s| !s.is_empty());
                parse_key_values(get(span, &["attributes"]), &mut parsed.attributes);
                parsed.dropped_attributes_count =
                    as_u32(get(span, &["droppedAttributesCount", "dropped_attributes_count"]));
                parsed.dropped_events_count = as_u32(get(span, &["droppedEventsCount", "dropped_events_count"]));
                parsed.dropped_links_count = as_u32(get(span, &["droppedLinksCount", "dropped_links_count"]));
                out.push(parsed);
            }
        }
    }
    if out.is_empty() && !object.contains_key("resourceSpans") && !object.contains_key("resource_spans") {
        debug!("OTLP/JSON traces 请求体不含 resourceSpans（空导出或非 traces 信号）");
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// OTLP/Protobuf（手写 wire-format 解码）
// ---------------------------------------------------------------------------

/// `ExportTraceServiceRequest`（字段 1 = repeated ResourceSpans）。
///
/// # Errors
/// wire-format 非法。
pub fn parse_traces_protobuf(body: &[u8]) -> DomainResult<Vec<OtlpSpanRecord>> {
    let mut reader = proto::Reader::new(body);
    let mut out = Vec::new();
    while let Some((field, wire)) = reader.tag()? {
        if field == 1 && wire == proto::WIRE_LEN {
            decode_resource_spans(reader.bytes()?, &mut out)?;
        } else {
            reader.skip(wire)?;
        }
    }
    Ok(out)
}

/// `ResourceSpans`（1 resource / 2 scopeSpans）。
fn decode_resource_spans(buf: &[u8], out: &mut Vec<OtlpSpanRecord>) -> DomainResult<()> {
    let mut reader = proto::Reader::new(buf);
    let mut resource: BTreeMap<String, String> = BTreeMap::new();
    let mut scope_spans: Vec<Vec<u8>> = Vec::new();
    while let Some((field, wire)) = reader.tag()? {
        match (field, wire) {
            (1, proto::WIRE_LEN) => decode_resource(reader.bytes()?, &mut resource)?,
            (2, proto::WIRE_LEN) => scope_spans.push(reader.bytes()?.to_vec()),
            (_, other) => reader.skip(other)?,
        }
    }
    for scope in scope_spans {
        decode_scope_spans(&scope, &resource, out)?;
    }
    Ok(())
}

/// `ScopeSpans`（1 scope / 2 spans）。
fn decode_scope_spans(
    buf: &[u8],
    resource: &BTreeMap<String, String>,
    out: &mut Vec<OtlpSpanRecord>,
) -> DomainResult<()> {
    let mut reader = proto::Reader::new(buf);
    let mut scope_name = None;
    let mut scope_version = None;
    let mut spans: Vec<Vec<u8>> = Vec::new();
    while let Some((field, wire)) = reader.tag()? {
        match (field, wire) {
            (1, proto::WIRE_LEN) => {
                let (name, version) = decode_scope(reader.bytes()?)?;
                scope_name = name;
                scope_version = version;
            }
            (2, proto::WIRE_LEN) => spans.push(reader.bytes()?.to_vec()),
            (_, other) => reader.skip(other)?,
        }
    }
    for span in spans {
        out.push(decode_span(&span, resource, scope_name.clone(), scope_version.clone())?);
    }
    Ok(())
}

/// `Span`（字段号与 `opentelemetry-proto` v1.x 一致：1 traceId / 2 spanId / 4 parentSpanId /
/// 5 name / 6 kind / 7 start / 8 end / 9 attributes / 10 droppedAttributes /
/// 12 droppedEvents / 14 droppedLinks / 15 status）。
fn decode_span(
    buf: &[u8],
    resource: &BTreeMap<String, String>,
    scope_name: Option<String>,
    scope_version: Option<String>,
) -> DomainResult<OtlpSpanRecord> {
    let mut reader = proto::Reader::new(buf);
    let mut span =
        OtlpSpanRecord { resource: resource.clone(), scope_name, scope_version, ..OtlpSpanRecord::default() };
    while let Some((field, wire)) = reader.tag()? {
        match field {
            1 => {
                let hex = proto::to_hex(reader.bytes()?);
                span.trace_id = Some(hex).filter(|s| !proto::is_zero_hex(s));
            }
            2 => {
                let hex = proto::to_hex(reader.bytes()?);
                span.span_id = Some(hex).filter(|s| !proto::is_zero_hex(s));
            }
            4 => {
                let hex = proto::to_hex(reader.bytes()?);
                span.parent_span_id = Some(hex).filter(|s| !proto::is_zero_hex(s));
            }
            5 => span.name = reader.string()?,
            6 => span.kind = i32::try_from(reader.varint()?).unwrap_or(0),
            7 => span.start_time_unix_nano = Some(proto::read_time(&mut reader, wire)?).filter(|v| *v > 0),
            8 => span.end_time_unix_nano = Some(proto::read_time(&mut reader, wire)?).filter(|v| *v > 0),
            9 => {
                let (key, value) = decode_key_value(reader.bytes()?)?;
                span.attributes.insert(key, value);
            }
            10 => span.dropped_attributes_count = u32::try_from(reader.varint()?).unwrap_or(u32::MAX),
            12 => span.dropped_events_count = u32::try_from(reader.varint()?).unwrap_or(u32::MAX),
            14 => span.dropped_links_count = u32::try_from(reader.varint()?).unwrap_or(u32::MAX),
            15 => decode_status(reader.bytes()?, &mut span)?,
            // 未知字段（含 events/links 的 11/13 与未来字段）按规范跳过，保证前向兼容
            _ => reader.skip(wire)?,
        }
    }
    Ok(span)
}

/// `Status`（2 message / 3 code）。
fn decode_status(buf: &[u8], span: &mut OtlpSpanRecord) -> DomainResult<()> {
    let mut reader = proto::Reader::new(buf);
    while let Some((field, wire)) = reader.tag()? {
        match (field, wire) {
            (2, proto::WIRE_LEN) => span.status_message = Some(reader.string()?).filter(|s| !s.is_empty()),
            (3, _) => span.status_code = i32::try_from(reader.varint()?).unwrap_or(0),
            (_, other) => reader.skip(other)?,
        }
    }
    Ok(())
}

/// 按 `Content-Type` 分派解析；缺省按 JSON（规范里 JSON 是最低要求）。
///
/// # Errors
/// 编码不受支持或解析失败。
pub fn parse_traces(body: &[u8], content_type: Option<&str>) -> DomainResult<Vec<OtlpSpanRecord>> {
    match super::supported_media(content_type)? {
        "application/json" => parse_traces_json(body),
        _ => parse_traces_protobuf(body),
    }
}
