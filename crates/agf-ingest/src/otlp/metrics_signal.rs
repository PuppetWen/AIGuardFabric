//! OTLP/HTTP metrics 接入（`POST /v1/metrics`）：DataPoint → Event（`event.category='metric'`）。
//!
//! 与 [`super::logs`] / [`super::traces`] 同源：JSON 与 Protobuf 双编码、`Content-Encoding: gzip`、
//! 单请求上限与解压上限保护、`partialSuccess.rejectedDataPoints` 如实回填。
//!
//! ## 支持的五类指标（`opentelemetry-proto` v1.x `Metric.data` oneof）
//!
//! | 字段号 | 类型 | 说明 |
//! |---|---|---|
//! | 5 | `Gauge` | 瞬时值 |
//! | 7 | `Sum` | 累计/增量（含 `is_monotonic`、`aggregation_temporality`） |
//! | 9 | `Histogram` | 如实透出 count/sum（桶结构不展开） |
//! | 10 | `ExponentialHistogram` | 如实透出 count/sum（桶结构不展开） |
//! | 11 | `Summary` | 如实透出 count/sum（分位值不展开） |
//!
//! 每个 data point 归一化为一条事件，携带 `metric.name`/`metric.type`/`metric.value`（数值型
//! `as_double` 优先，否则 `as_int`）、`metric.unit`、`attributes`/`resource`（保持 OTLP 原文）。

use std::collections::BTreeMap;

use agf_core::error::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::debug;

use super::{decode_key_value, decode_resource, decode_scope, get, parse_key_values, proto, string_map};

/// OTLP/HTTP metrics 端点路径（规范固定值）。
pub const OTLP_METRICS_PATH: &str = "/v1/metrics";

/// 一条 metric data point（ResourceMetrics / ScopeMetrics / Metric 上下文已内联展开）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OtlpMetricRecord {
    /// 指标名。
    pub name: String,
    /// 指标描述。
    pub description: Option<String>,
    /// 单位（UCUM）。
    pub unit: Option<String>,
    /// 指标类型（`gauge`/`sum`/`histogram`/`exponential_histogram`/`summary`）。
    pub metric_type: String,
    /// 时间戳（纳秒）。
    pub time_unix_nano: Option<u64>,
    /// 起始时间（纳秒，累计型有意义）。
    pub start_time_unix_nano: Option<u64>,
    /// 数值（`as_double` 优先，否则 `as_int`；histogram/summary 取 `sum`）。
    pub value: Option<f64>,
    /// 计数（histogram/summary 的 `count`）。
    pub count: Option<u64>,
    /// 是否单调递增（仅 `Sum` 有意义）。
    pub is_monotonic: Option<bool>,
    /// 聚合时间性（1=DELTA 2=CUMULATIVE）。
    pub aggregation_temporality: Option<i32>,
    /// data point 属性。
    pub attributes: BTreeMap<String, String>,
    /// Resource 属性。
    pub resource: BTreeMap<String, String>,
    /// InstrumentationScope 名称。
    pub scope_name: Option<String>,
    /// scope 版本。
    pub scope_version: Option<String>,
}

impl OtlpMetricRecord {
    /// RFC3339（带纳秒）时间戳。
    #[must_use]
    pub fn timestamp_rfc3339(&self) -> Option<String> {
        let nanos = self.time_unix_nano.filter(|v| *v > 0)?;
        let secs = i64::try_from(nanos / 1_000_000_000).ok()?;
        let sub = u32::try_from(nanos % 1_000_000_000).unwrap_or(0);
        let dt = chrono::DateTime::from_timestamp(secs, sub)?;
        Some(dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
    }

    /// 事件来源（`service.name` → `scope.name` → 兜底）。
    #[must_use]
    pub fn origin(&self) -> String {
        self.resource
            .get("service.name")
            .cloned()
            .or_else(|| self.scope_name.clone())
            .unwrap_or_else(|| "otlp-metrics".to_string())
    }

    /// 归一化载荷（交给既有解析流水线的 JSON 文本）。
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        let mut root = Map::new();
        if let Some(ts) = self.timestamp_rfc3339() {
            root.insert("@timestamp".to_string(), Value::from(ts));
        }
        root.insert("event.category".to_string(), Value::from("metric"));
        root.insert("metric.name".to_string(), Value::from(self.name.clone()));
        root.insert("metric.type".to_string(), Value::from(self.metric_type.clone()));
        root.insert("message".to_string(), Value::from(format!("metric {}", self.name)));
        if let Some(v) = self.value {
            if let Some(n) = serde_json::Number::from_f64(v) {
                root.insert("metric.value".to_string(), Value::Number(n));
            }
        }
        if let Some(c) = self.count {
            root.insert("metric.count".to_string(), Value::from(c));
        }
        if let Some(u) = &self.unit {
            root.insert("metric.unit".to_string(), Value::from(u.clone()));
        }
        if let Some(d) = &self.description {
            root.insert("metric.description".to_string(), Value::from(d.clone()));
        }
        if let Some(m) = self.is_monotonic {
            root.insert("metric.is_monotonic".to_string(), Value::from(m));
        }
        if let Some(t) = self.aggregation_temporality {
            root.insert("metric.aggregation_temporality".to_string(), Value::from(t));
        }
        if !self.resource.is_empty() {
            root.insert("resource".to_string(), Value::Object(string_map(&self.resource)));
        }
        if !self.attributes.is_empty() {
            root.insert("attributes".to_string(), Value::Object(string_map(&self.attributes)));
        }
        if self.scope_name.is_some() || self.scope_version.is_some() {
            let mut scope = Map::new();
            if let Some(n) = &self.scope_name {
                scope.insert("name".to_string(), Value::from(n.clone()));
            }
            if let Some(v) = &self.scope_version {
                scope.insert("version".to_string(), Value::from(v.clone()));
            }
            root.insert("scope".to_string(), Value::Object(scope));
        }
        root.insert("service.name".to_string(), Value::from(self.origin()));
        root.entry("event.action".to_string()).or_insert_with(|| Value::from("metric"));
        Value::Object(root).to_string().into_bytes()
    }
}
// ---------------------------------------------------------------------------
// OTLP/JSON
// ---------------------------------------------------------------------------

/// OTLP/JSON 的 `int64-as-string` 与裸数字都要能读。
fn as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<u64>().ok()))
        .or_else(|| value.as_i64().and_then(|v| u64::try_from(v).ok()))
}

/// 数值字段（`asDouble` / `asInt` / 裸数字 / 字符串数字）。
fn as_f64(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<f64>().ok()))
        .or_else(|| value.as_bool().map(|b| if b { 1.0 } else { 0.0 }))
}

/// OTLP/JSON：`resourceMetrics → scopeMetrics → metrics → dataPoints`。
///
/// # Errors
/// JSON 非法或顶层不是对象。
pub fn parse_metrics_json(body: &[u8]) -> DomainResult<Vec<OtlpMetricRecord>> {
    let root: Value =
        serde_json::from_slice(body).map_err(|e| DomainError::Parse(format!("OTLP/JSON metrics 解析失败: {e}")))?;
    let Some(object) = root.as_object() else {
        return Err(DomainError::Parse("OTLP/JSON 顶层必须是对象（ExportMetricsServiceRequest）".to_string()));
    };
    let mut out = Vec::new();
    for resource_metric in
        get(&root, &["resourceMetrics", "resource_metrics"]).and_then(Value::as_array).into_iter().flatten()
    {
        let mut resource_attrs = BTreeMap::new();
        parse_key_values(
            get(resource_metric, &["resource"]).and_then(|r| get(r, &["attributes"])),
            &mut resource_attrs,
        );
        let scope_metrics = get(resource_metric, &["scopeMetrics", "scope_metrics", "instrumentationLibraryMetrics"])
            .and_then(Value::as_array);
        for scope_metric in scope_metrics.into_iter().flatten() {
            let scope = get(scope_metric, &["scope", "instrumentationLibrary"]);
            let scope_name = scope.and_then(|s| get(s, &["name"])).and_then(Value::as_str).map(ToString::to_string);
            let scope_version =
                scope.and_then(|s| get(s, &["version"])).and_then(Value::as_str).map(ToString::to_string);
            for metric in get(scope_metric, &["metrics"]).and_then(Value::as_array).into_iter().flatten() {
                let name = get(metric, &["name"]).and_then(Value::as_str).unwrap_or_default().to_string();
                let description = get(metric, &["description"])
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .filter(|s| !s.is_empty());
                let unit =
                    get(metric, &["unit"]).and_then(Value::as_str).map(ToString::to_string).filter(|s| !s.is_empty());
                for (metric_type, points) in json_data_points(metric) {
                    for point in points {
                        let mut parsed = OtlpMetricRecord {
                            name: name.clone(),
                            description: description.clone(),
                            unit: unit.clone(),
                            metric_type: metric_type.to_string(),
                            resource: resource_attrs.clone(),
                            scope_name: scope_name.clone(),
                            scope_version: scope_version.clone(),
                            ..OtlpMetricRecord::default()
                        };
                        json_fill_point(&mut parsed, &point);
                        // Sum 的 is_monotonic / temporality 挂在 data 上而非 dataPoint 上
                        if metric_type == "sum" {
                            parsed.is_monotonic =
                                get(metric, &["isMonotonic", "is_monotonic"]).and_then(Value::as_bool);
                            parsed.aggregation_temporality =
                                get(metric, &["aggregationTemporality", "aggregation_temporality"])
                                    .and_then(Value::as_i64)
                                    .and_then(|v| i32::try_from(v).ok());
                        }
                        out.push(parsed);
                    }
                }
            }
        }
    }
    if out.is_empty() && !object.contains_key("resourceMetrics") && !object.contains_key("resource_metrics") {
        debug!("OTLP/JSON metrics 请求体不含 resourceMetrics（空导出或非 metrics 信号）");
    }
    Ok(out)
}

/// 从 `Metric` 里取出 `(类型, dataPoints)`（按 oneof 字段名兼容 `dataPoints`/`data_points`）。
fn json_data_points(metric: &Value) -> Vec<(&'static str, Vec<Value>)> {
    let candidates = [
        ("gauge", vec!["gauge"]),
        ("sum", vec!["sum"]),
        ("histogram", vec!["histogram"]),
        ("exponential_histogram", vec!["exponentialHistogram", "exponential_histogram"]),
        ("summary", vec!["summary"]),
    ];
    let mut out = Vec::new();
    for (kind, keys) in candidates {
        let Some(data) = get(metric, &keys) else { continue };
        let points = get(data, &["dataPoints", "data_points"]).and_then(Value::as_array).cloned().unwrap_or_default();
        out.push((kind, points));
    }
    out
}

/// 填充 data point 的通用字段（数值/时间/计数/属性）。
fn json_fill_point(record: &mut OtlpMetricRecord, point: &Value) {
    record.time_unix_nano = get(point, &["timeUnixNano", "time_unix_nano"]).and_then(as_u64);
    record.start_time_unix_nano = get(point, &["startTimeUnixNano", "start_time_unix_nano"]).and_then(as_u64);
    record.value = get(point, &["asDouble", "as_double"])
        .and_then(as_f64)
        .or_else(|| get(point, &["asInt", "as_int"]).and_then(as_f64))
        // histogram / summary 没有 asDouble，用 sum 作为数值代表
        .or_else(|| get(point, &["sum"]).and_then(as_f64));
    record.count = get(point, &["count"]).and_then(as_u64);
    parse_key_values(get(point, &["attributes"]), &mut record.attributes);
}
// ---------------------------------------------------------------------------
// OTLP/Protobuf（手写 wire-format 解码）
// ---------------------------------------------------------------------------

/// `ExportMetricsServiceRequest`（字段 1 = repeated ResourceMetrics）。
///
/// # Errors
/// wire-format 非法。
pub fn parse_metrics_protobuf(body: &[u8]) -> DomainResult<Vec<OtlpMetricRecord>> {
    let mut reader = proto::Reader::new(body);
    let mut out = Vec::new();
    while let Some((field, wire)) = reader.tag()? {
        if field == 1 && wire == proto::WIRE_LEN {
            decode_resource_metrics(reader.bytes()?, &mut out)?;
        } else {
            reader.skip(wire)?;
        }
    }
    Ok(out)
}

/// `ResourceMetrics`（1 resource / 2 scopeMetrics）。
fn decode_resource_metrics(buf: &[u8], out: &mut Vec<OtlpMetricRecord>) -> DomainResult<()> {
    let mut reader = proto::Reader::new(buf);
    let mut resource: BTreeMap<String, String> = BTreeMap::new();
    let mut scope_metrics: Vec<Vec<u8>> = Vec::new();
    while let Some((field, wire)) = reader.tag()? {
        match (field, wire) {
            (1, proto::WIRE_LEN) => decode_resource(reader.bytes()?, &mut resource)?,
            (2, proto::WIRE_LEN) => scope_metrics.push(reader.bytes()?.to_vec()),
            (_, other) => reader.skip(other)?,
        }
    }
    for scope in scope_metrics {
        decode_scope_metrics(&scope, &resource, out)?;
    }
    Ok(())
}

/// `ScopeMetrics`（1 scope / 2 metrics）。
fn decode_scope_metrics(
    buf: &[u8],
    resource: &BTreeMap<String, String>,
    out: &mut Vec<OtlpMetricRecord>,
) -> DomainResult<()> {
    let mut reader = proto::Reader::new(buf);
    let mut scope_name = None;
    let mut scope_version = None;
    let mut metrics: Vec<Vec<u8>> = Vec::new();
    while let Some((field, wire)) = reader.tag()? {
        match (field, wire) {
            (1, proto::WIRE_LEN) => {
                let (name, version) = decode_scope(reader.bytes()?)?;
                scope_name = name;
                scope_version = version;
            }
            (2, proto::WIRE_LEN) => metrics.push(reader.bytes()?.to_vec()),
            (_, other) => reader.skip(other)?,
        }
    }
    for metric in metrics {
        decode_metric(&metric, resource, scope_name.clone(), scope_version.clone(), out)?;
    }
    Ok(())
}
/// `Metric`（1 name / 2 description / 3 unit / 5 gauge / 7 sum / 9 histogram /
/// 10 exponentialHistogram / 11 summary；`Sum` 的 6 isMonotonic / 8 temporality）。
fn decode_metric(
    buf: &[u8],
    resource: &BTreeMap<String, String>,
    scope_name: Option<String>,
    scope_version: Option<String>,
    out: &mut Vec<OtlpMetricRecord>,
) -> DomainResult<()> {
    let mut reader = proto::Reader::new(buf);
    let mut name = String::new();
    let mut description = None;
    let mut unit = None;
    let mut is_monotonic = None;
    let mut temporality = None;
    let mut data: Option<(&'static str, Vec<u8>)> = None;
    while let Some((field, wire)) = reader.tag()? {
        match (field, wire) {
            (1, proto::WIRE_LEN) => name = reader.string()?,
            (2, proto::WIRE_LEN) => description = Some(reader.string()?).filter(|s| !s.is_empty()),
            (3, proto::WIRE_LEN) => unit = Some(reader.string()?).filter(|s| !s.is_empty()),
            (5, proto::WIRE_LEN) => data = Some(("gauge", reader.bytes()?.to_vec())),
            (6, _) => is_monotonic = Some(reader.varint()? != 0),
            (7, proto::WIRE_LEN) => data = Some(("sum", reader.bytes()?.to_vec())),
            (8, _) => temporality = i32::try_from(reader.varint()?).ok(),
            (9, proto::WIRE_LEN) => data = Some(("histogram", reader.bytes()?.to_vec())),
            (10, proto::WIRE_LEN) => data = Some(("exponential_histogram", reader.bytes()?.to_vec())),
            (11, proto::WIRE_LEN) => data = Some(("summary", reader.bytes()?.to_vec())),
            (_, other) => reader.skip(other)?,
        }
    }
    let Some((metric_type, data_buf)) = data else {
        return Ok(());
    };
    for point in decode_data_points(&data_buf)? {
        let mut record = OtlpMetricRecord {
            name: name.clone(),
            description: description.clone(),
            unit: unit.clone(),
            metric_type: metric_type.to_string(),
            resource: resource.clone(),
            scope_name: scope_name.clone(),
            scope_version: scope_version.clone(),
            ..OtlpMetricRecord::default()
        };
        decode_number_data_point(&point, &mut record)?;
        if metric_type == "sum" {
            record.is_monotonic = is_monotonic;
            record.aggregation_temporality = temporality;
        }
        out.push(record);
    }
    Ok(())
}

/// 取 `dataPoints`（repeated message，字段号 1）。
fn decode_data_points(buf: &[u8]) -> DomainResult<Vec<Vec<u8>>> {
    let mut reader = proto::Reader::new(buf);
    let mut points = Vec::new();
    while let Some((field, wire)) = reader.tag()? {
        if field == 1 && wire == proto::WIRE_LEN {
            points.push(reader.bytes()?.to_vec());
        } else {
            reader.skip(wire)?;
        }
    }
    Ok(points)
}

/// `NumberDataPoint` / `HistogramDataPoint` / `SummaryDataPoint` 的通用字段。
///
/// 口径：`NumberDataPoint` 的 4 = `as_double`(fixed64) / 6 = `as_int`(varint)；
/// `Histogram|SummaryDataPoint` 的 4 = `count`(varint) / 5 = `sum`(double)。
/// 两者共用 2 startTime / 3 time / 7 attributes。
fn decode_number_data_point(buf: &[u8], record: &mut OtlpMetricRecord) -> DomainResult<()> {
    let mut reader = proto::Reader::new(buf);
    let mut as_double = None;
    let mut as_int = None;
    let mut sum = None;
    while let Some((field, wire)) = reader.tag()? {
        match (field, wire) {
            (2, _) => record.start_time_unix_nano = Some(proto::read_time(&mut reader, wire)?).filter(|v| *v > 0),
            (3, _) => record.time_unix_nano = Some(proto::read_time(&mut reader, wire)?).filter(|v| *v > 0),
            (4, proto::WIRE_I64) => as_double = Some(f64::from_bits(reader.fixed64()?)),
            (4, _) => record.count = Some(reader.varint()?),
            (5, proto::WIRE_I64) => sum = Some(f64::from_bits(reader.fixed64()?)),
            (6, proto::WIRE_VARINT) => as_int = i64::try_from(reader.varint()?).ok(),
            (7, proto::WIRE_LEN) => {
                let (key, value) = decode_key_value(reader.bytes()?)?;
                record.attributes.insert(key, value);
            }
            (_, other) => reader.skip(other)?,
        }
    }
    record.value = as_double.or_else(|| as_int.map(|v| v as f64)).or(sum);
    Ok(())
}

/// 按 `Content-Type` 分派解析；缺省按 JSON。
///
/// # Errors
/// 编码不受支持或解析失败。
pub fn parse_metrics(body: &[u8], content_type: Option<&str>) -> DomainResult<Vec<OtlpMetricRecord>> {
    match super::supported_media(content_type)? {
        "application/json" => parse_metrics_json(body),
        _ => parse_metrics_protobuf(body),
    }
}
