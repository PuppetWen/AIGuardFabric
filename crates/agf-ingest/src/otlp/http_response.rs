//! OTLP transport responses, retry classification and truthful partial-success accounting.
use agf_core::error::DomainError;
use axum::{
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use prost::Message;
use serde_json::Value;

// All three Export responses use field 1 for partial_success; each partial message
// uses int64 field 1 for the rejected count and string field 2 for its explanation.
#[derive(Clone, PartialEq, Message)]
struct ExportResponse {
    #[prost(message, optional, tag = "1")]
    partial_success: Option<PartialSuccess>,
}
#[derive(Clone, PartialEq, Message)]
struct PartialSuccess {
    #[prost(int64, tag = "1")]
    rejected: i64,
    #[prost(string, tag = "2")]
    error_message: String,
}
#[derive(Clone, PartialEq, Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
}

fn protobuf(headers: &HeaderMap) -> bool {
    headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|value| {
        let media = value.split(';').next().unwrap_or_default().trim();
        media.eq_ignore_ascii_case("application/x-protobuf") || media.eq_ignore_ascii_case("application/protobuf")
    })
}

pub(crate) fn success(headers: &HeaderMap, value: Value) -> Response {
    if !protobuf(headers) {
        return axum::Json(value).into_response();
    }
    let partial_success = value.get("partialSuccess").map(|partial| PartialSuccess {
        rejected: ["rejectedLogRecords", "rejectedSpans", "rejectedDataPoints"]
            .iter()
            .find_map(|key| partial.get(key).and_then(Value::as_i64))
            .unwrap_or(0),
        error_message: partial["errorMessage"].as_str().unwrap_or_default().chars().take(1024).collect(),
    });
    (StatusCode::OK, [(CONTENT_TYPE, "application/x-protobuf")], ExportResponse { partial_success }.encode_to_vec())
        .into_response()
}

/// Transient storage failures must be retryable, otherwise exporters discard the batch.
pub(crate) fn grpc_error(error: &DomainError) -> tonic::Status {
    let message: String = error.to_string().chars().take(1024).collect();
    match error.status_code() {
        401 => tonic::Status::unauthenticated(message),
        403 => tonic::Status::permission_denied(message),
        404 => tonic::Status::not_found(message),
        412 => tonic::Status::failed_precondition(message),
        501 => tonic::Status::unimplemented(message),
        429 | 500..=599 => tonic::Status::unavailable("Telemetry storage or processing is temporarily unavailable"),
        _ => tonic::Status::invalid_argument(message),
    }
}

pub(crate) fn error(headers: &HeaderMap, error: &DomainError) -> Response {
    let grpc = grpc_error(error);
    let code = grpc.code() as i32;
    let status = if grpc.code() == tonic::Code::Unavailable {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::BAD_REQUEST)
    };
    let message = grpc.message().to_string();
    if protobuf(headers) {
        (status, [(CONTENT_TYPE, "application/x-protobuf")], RpcStatus { code, message }.encode_to_vec())
            .into_response()
    } else {
        (status, axum::Json(serde_json::json!({"code":code,"message":message}))).into_response()
    }
}

pub(crate) fn count_rejections(
    outcomes: &[crate::pipeline::IngestOutcome],
    rejected: &mut usize,
    message: &mut Option<String>,
) {
    let failed = outcomes.iter().filter(|outcome| !outcome.persisted).count();
    *rejected = rejected.saturating_add(failed);
    if failed > 0 && message.is_none() {
        *message = Some(format!("{failed} records exceeded pipeline limits or failed validation"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn binary_responses_match_otlp_wire_and_transient_errors_are_retryable() {
        use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceResponse;
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/x-protobuf".parse().unwrap());
        let response = success(
            &headers,
            serde_json::json!({"partialSuccess":{"rejectedLogRecords":7,"errorMessage":"over limit"}}),
        );
        assert_eq!(response.headers()[CONTENT_TYPE], "application/x-protobuf");
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let decoded = ExportLogsServiceResponse::decode(bytes).unwrap();
        assert_eq!(decoded.partial_success.unwrap().rejected_log_records, 7);
        let failure = DomainError::DependencyUnavailable { dependency: "postgres".into(), cause: "fixture".into() };
        assert_eq!(grpc_error(&failure).code(), tonic::Code::Unavailable);
        let response = error(&headers, &failure);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(RpcStatus::decode(bytes).unwrap().code, 14);
        assert_eq!(grpc_error(&DomainError::Validation("bad payload".into())).code(), tonic::Code::InvalidArgument);
    }
}
