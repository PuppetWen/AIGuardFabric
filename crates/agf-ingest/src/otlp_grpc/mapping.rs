//! 协议映射：`ExportLogsServiceRequest` → OTLP/HTTP JSON 与 `OtlpLogRecord`，以及响应构造（含 `partialSuccess`）。

use super::*;

/// `ExportLogsServiceRequest` → OTLP/JSON 字节（`opentelemetry-proto` 的 `with-serde`
/// 与 OTLP/JSON 规范一致：camelCase、`int64`/纳秒时间戳为字符串、`trace_id`/`span_id` 为 hex）。
///
/// # Errors
/// 序列化失败（理论上不会发生；仍如实返回而不是 `unwrap`）。
pub fn request_to_json(request: &ExportLogsServiceRequest) -> DomainResult<Vec<u8>> {
    serde_json::to_vec(request).map_err(|e| DomainError::Parse(format!("OTLP/gRPC 请求转 OTLP/JSON 失败: {e}")))
}

/// `ExportLogsServiceRequest` → [`OtlpLogRecord`]（**复用** [`crate::otlp::parse_json`] 的字段映射）。
///
/// # Errors
/// 序列化或 JSON 映射失败。
pub fn request_to_records(request: &ExportLogsServiceRequest) -> DomainResult<Vec<OtlpLogRecord>> {
    crate::otlp::parse_json(&request_to_json(request)?)
}

/// 请求里的 `LogRecord` 总数（整包拒绝时用它如实回填 `rejected_log_records`，不猜数字）。
#[must_use]
pub fn count_log_records(request: &ExportLogsServiceRequest) -> usize {
    request
        .resource_logs
        .iter()
        .flat_map(|resource| resource.scope_logs.iter())
        .map(|scope| scope.log_records.len())
        .sum()
}

/// 接入结果 → OTLP 响应（`rejected = 0` 时不设 `partial_success`）。
#[must_use]
pub fn report_to_response(report: &OtlpIngestReport) -> ExportLogsServiceResponse {
    if report.rejected == 0 {
        return ExportLogsServiceResponse { partial_success: None };
    }
    partial_success_response(
        report.rejected,
        report.error_message.clone().unwrap_or_else(|| "部分日志记录未能接入".to_string()),
    )
}

/// 构造带 `partial_success` 的响应。
#[must_use]
pub fn partial_success_response(rejected: usize, message: String) -> ExportLogsServiceResponse {
    ExportLogsServiceResponse {
        partial_success: Some(ExportLogsPartialSuccess {
            rejected_log_records: i64::try_from(rejected).unwrap_or(i64::MAX),
            error_message: message,
        }),
    }
}

/// 交给 [`OtlpLogsReceiver::ingest_logs`] 的请求头（固定 JSON：gRPC 侧已在 [`request_to_json`]
/// 里完成 protobuf → OTLP/JSON 的转换，接收器只需走同一条 JSON 解析路径）。
pub(super) fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers
}

// ---------------------------------------------------------------------------
// gRPC 服务
// ---------------------------------------------------------------------------
