//! RFC 9457 `application/problem+json` 错误响应（§8 API 约定）。
//!
//! `DomainError` 的三个既有方法直接复用，不重复映射表：
//! - [`DomainError::problem_type`] → `type`（错误文档 URI 锚点）
//! - [`DomainError::status_code`] → `status`
//! - [`DomainError::code`] → `code`（前端 i18n 与告警规则依赖的稳定值）
//!
//! 未实现端点使用 [`ApiError::not_implemented`]：状态码固定 **501**（`DomainError::NotImplemented`
//! 自身映射为 500，属"服务器内部未实现"语义），并在响应里带 `todo` 扩展字段指向 TODO 锚点。

use agf_core::error::DomainError;
use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

tokio::task_local! {
    // 请求 id 的任务局部存储（由 crate::middleware 的 request-id 中间件写入）。
    pub static REQUEST_ID: String;
}

/// 读取当前请求 id（不在请求上下文中时返回 `None`）。
#[must_use]
pub fn current_request_id() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// RFC 9457 问题详情。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ProblemDetails {
    /// 错误类型 URI（来自 [`DomainError::problem_type`]）。
    #[serde(rename = "type")]
    pub problem_type: String,
    /// 人类可读标题。
    pub title: String,
    /// HTTP 状态码。
    pub status: u16,
    /// 具体说明。
    pub detail: String,
    /// 稳定机器可读错误码（来自 [`DomainError::code`]）。
    pub code: String,
    /// 出错请求的路径（若已知）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// 请求 id（与 `X-Request-Id` 响应头一致）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// TODO 锚点（仅 501 未实现端点携带）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub todo: Option<String>,
}

/// 状态码对应的规范标题。
#[must_use]
const fn title_for(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// API 错误：领域错误 + 可选状态码覆盖 + 可选 TODO 锚点。
#[derive(Debug, PartialEq, Eq)]
pub struct ApiError {
    /// 领域错误（提供 type/code/detail 语义）。
    pub error: DomainError,
    /// 实际返回的状态码（默认取 [`DomainError::status_code`]）。
    pub status: u16,
    /// TODO 锚点（如 `api-correlate-aggregate`）。
    pub todo_anchor: Option<&'static str>,
    /// 附加响应头（如 429 的 `Retry-After`）。
    pub headers: Vec<(&'static str, String)>,
    /// 出错路径。
    pub instance: Option<String>,
}

impl ApiError {
    /// 由领域错误构造（状态码取 [`DomainError::status_code`]）。
    #[must_use]
    pub fn new(error: DomainError) -> Self {
        Self { status: error.status_code(), error, todo_anchor: None, headers: Vec::new(), instance: None }
    }

    /// 未实现端点错误（**501** + TODO 锚点）。
    ///
    /// `anchor` 形如 `api-correlate-aggregate`，源码中必须存在对应的
    /// `TODO(api-correlate-aggregate)` 注释，便于静态检索。
    #[must_use]
    pub fn not_implemented(anchor: &'static str, what: impl Into<String>) -> Self {
        Self {
            error: DomainError::NotImplemented(format!("{}（TODO({anchor})）", what.into())),
            status: 501,
            todo_anchor: Some(anchor),
            headers: Vec::new(),
            instance: None,
        }
    }

    /// 附加响应头。
    #[must_use]
    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    /// 补充出错路径。
    #[must_use]
    pub fn with_instance(mut self, instance: &str) -> Self {
        self.instance = Some(instance.to_string());
        self
    }

    /// 覆盖状态码（少量场景需要，如 413 Payload Too Large）。
    #[must_use]
    pub const fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// 稳定错误码。
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.error.code()
    }

    /// 转问题详情（补齐请求 id）。
    #[must_use]
    pub fn to_problem(&self) -> ProblemDetails {
        ProblemDetails {
            problem_type: self.error.problem_type().to_string(),
            title: title_for(self.status).to_string(),
            status: self.status,
            detail: self.error.to_string(),
            code: self.error.code().to_string(),
            instance: self.instance.clone(),
            request_id: current_request_id(),
            todo: self.todo_anchor.map(ToString::to_string),
        }
    }
}

impl From<DomainError> for ApiError {
    fn from(value: DomainError) -> Self {
        Self::new(value)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(value: serde_json::Error) -> Self {
        Self::new(DomainError::Parse(format!("json: {value}")))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{} {}] {}", self.status, self.error.code(), self.error)
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let problem = self.to_problem();
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = (status, Json(problem)).into_response();
        for (name, value) in &self.headers {
            if let (Ok(header_name), Ok(header_value)) =
                (axum::http::HeaderName::try_from(*name), HeaderValue::from_str(value))
            {
                response.headers_mut().insert(header_name, header_value);
            }
        }
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/problem+json; charset=utf-8"));
        response
    }
}

/// 便捷别名。
pub type ApiResult<T> = Result<T, ApiError>;
