//! 外部系统真实传输层（HTTP 往返 + 响应映射）。
//!
//! 本模块是"适配器编码产物 → 真实外部系统"的**唯一出口**：
//! [`crate::vendor::VendorSpec::encode`] 产出确定性的 [`VendorRequest`]（可离线断言），
//! 本模块负责把它真正发出去并把结果映射回领域错误。
//!
//! ## 设计要点
//!
//! 1. **超时来自配置**：`AdapterSettings::timeout_secs` 直接作为 `reqwest` 请求超时，
//!    超时映射为 [`agf_core::error::DomainError::Timeout`]（可重试，见 `invoke_with_policy`）；
//! 2. **状态码分类决定是否重试**：5xx → `DependencyUnavailable`（可重试）；
//!    4xx → `Validation`/`Unauthenticated`/`Forbidden`/`RateLimited`（**不重试**，业务错误重试无意义）；
//! 3. **凭据绝不进错误文本**：`reqwest` 的 `Error` 会内嵌完整 URL（Webhook URL 本身即凭据），
//!    因此一律经 `Error::without_url()` 剥离，并对目标地址再走 [`redact_url`] 掩码；
//! 4. **响应体截断**：错误信息里只带 [`MAX_BODY_SNIPPET`] 个字符，避免把上游大响应写进日志。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 适配器判定为 `Unconfigured`（缺 URL/凭据/必需设置） | [`crate::vendor::VendorAdapterImpl::send`] 在进入本模块前即返回 `Config` 错误，**不建连、不发包** |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 走 Mock 回执，**本模块不会被调用**（零网络） |
//! | endpoint 非法 / 请求头名非法 | 编码阶段或本模块构造请求阶段返回 `Config`/`Validation`，不发出半成品请求 |
//! | 上游超时 | `Timeout` 错误（可重试）；连续失败由熔断器开路 |
//! | 上游 5xx | `DependencyUnavailable`（可重试，按 `RetryConfig`） |
//! | 上游 4xx | `Validation`/`Unauthenticated`/`Forbidden`/`RateLimited`（不重试） |

use std::time::Duration;

use agf_core::error::{DomainError, DomainResult};
use serde_json::Value;

use crate::settings::AdapterSettings;
use crate::transport::{VendorRequest, redact_url};

/// 错误信息中保留的响应体字符数上限。
pub const MAX_BODY_SNIPPET: usize = 200;

/// 通用远端 id 提取候选路径（按顺序命中，`None` 表示上游未返回 id 属正常）。
pub const DEFAULT_ID_CANDIDATES: &[&str] =
    &["data.id", "data.task_id", "data.sys_id", "id", "task_id", "sys_id", "key", "data.key"];

/// HTTP 响应（状态码 + 文本体）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpResponse {
    /// HTTP 状态码。
    pub status: u16,
    /// 响应体（文本形态；非 UTF-8 时由 `reqwest` 做有损替换）。
    pub body: String,
}

impl HttpResponse {
    /// 是否 2xx。
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// 是否为 HTTP 动词（非 HTTP 通道如 Syslog/SMTP 用自描述动词，见 [`VendorRequest::channel`]）。
#[must_use]
pub fn is_http_method(method: &str) -> bool {
    matches!(method.to_ascii_uppercase().as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD")
}

/// 截断响应体为可安全写日志的片段。
#[must_use]
pub fn snippet(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.chars().count() <= MAX_BODY_SNIPPET {
        return trimmed.to_string();
    }
    let mut out: String = trimmed.chars().take(MAX_BODY_SNIPPET).collect();
    out.push('…');
    out
}

/// 状态码 → 领域错误（2xx 通过）。
///
/// 分类刻意与 `DomainError::is_degradable()` 对齐：
/// 只有 5xx 是"可重试的外部依赖不可用"，4xx 属业务错误，重试不会变好。
///
/// # Errors
/// 非 2xx 时返回对应领域的错误（402/404 等统一归 `Validation`）。
pub fn ensure_success(vendor: &str, endpoint: &str, status: u16, body: &str) -> DomainResult<()> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    let target = redact_url(endpoint);
    let detail = format!("{vendor} 上游返回 HTTP {status}（{target}）: {}", snippet(body));
    Err(match status {
        401 => DomainError::Unauthenticated(detail),
        403 => DomainError::Forbidden(detail),
        429 => DomainError::RateLimited(detail),
        400..=499 => DomainError::Validation(detail),
        _ => DomainError::DependencyUnavailable { dependency: vendor.to_string(), cause: detail },
    })
}

/// 按候选路径（支持 `a.b.c` 点分嵌套）从 JSON 响应体提取远端 id。
///
/// 支持字符串与整数形态（工单号多为字符串，禅道为整数）。
#[must_use]
pub fn extract_id(body: &str, candidates: &[&str]) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    candidates.iter().find_map(|path| lookup_path(&value, path).and_then(scalar_to_id))
}

/// 点分路径查找。
fn lookup_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(value, |current, segment| current.get(segment))
}

/// 标量 → id 文本（空白字符串视为未提供）。
fn scalar_to_id(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return (!text.trim().is_empty()).then(|| text.to_string());
    }
    value.as_i64().map(|n| n.to_string()).or_else(|| value.as_u64().map(|n| n.to_string()))
}

/// 构造带超时的 HTTP 客户端。
///
/// # Errors
/// TLS 后端缺失等客户端构造失败时返回 `DomainError::Internal`。
fn client(timeout_secs: u64) -> DomainResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| DomainError::Internal(format!("HTTP 客户端构造失败: {}", e.without_url())))
}

/// 底层错误 → 领域错误（URL 已剥离，凭据不进入错误文本）。
fn map_error(vendor: &str, endpoint: &str, error: reqwest::Error) -> DomainError {
    // `is_timeout()` 借用、`without_url()` 取所有权：先判定再消费
    let timed_out = error.is_timeout();
    let cause = error.without_url().to_string();
    if timed_out {
        return DomainError::Timeout(format!("{vendor} 上游超时: {cause}（目标 {}）", redact_url(endpoint)));
    }
    DomainError::DependencyUnavailable {
        dependency: vendor.to_string(),
        cause: format!("{cause}（目标 {}）", redact_url(endpoint)),
    }
}

/// 执行一次真实 HTTP 往返（编码产物 → 上游）。
///
/// # Errors
/// - 非 HTTP 动词（Syslog/SMTP 等专属通道误入）：`DomainError::Validation`；
/// - 请求头名/值非法：`DomainError::Config`（**不发出半成品请求**）；
/// - 网络失败：`DependencyUnavailable`；超时：`Timeout`；
/// - 非 2xx：见 [`ensure_success`]。
pub async fn execute(vendor: &str, req: &VendorRequest, settings: &AdapterSettings) -> DomainResult<HttpResponse> {
    if !is_http_method(&req.method) {
        return Err(DomainError::Validation(format!(
            "{vendor}：动词 {} 不属于 HTTP 通道，请使用厂商专属传输实现",
            req.method
        )));
    }
    let method = reqwest::Method::from_bytes(req.method.as_bytes())
        .map_err(|e| DomainError::Config(format!("{vendor}：HTTP 方法非法 {}: {e}", req.method)))?;
    let bodyless = matches!(method, reqwest::Method::GET | reqwest::Method::HEAD);
    let mut builder = client(settings.timeout_secs)?.request(method, &req.endpoint);
    for (name, value) in &req.headers {
        let header = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| DomainError::Config(format!("{vendor}：请求头名非法 {name:?}: {e}")))?;
        let header_value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|_| DomainError::Config(format!("{vendor}：请求头 {name} 的值非法（含不可见字符）")))?;
        builder = builder.header(header, header_value);
    }
    if !req.content_type.is_empty() {
        builder = builder.header(reqwest::header::CONTENT_TYPE, req.content_type.clone());
    }
    if !matches!(req.body, Value::Null) && !bodyless {
        let payload = serde_json::to_string(&req.body)
            .map_err(|e| DomainError::Validation(format!("{vendor}：请求体序列化失败: {e}")))?;
        builder = builder.body(payload);
    }
    let response = builder.send().await.map_err(|e| map_error(vendor, &req.endpoint, e))?;
    let status = response.status().as_u16();
    let body = response.text().await.map_err(|e| map_error(vendor, &req.endpoint, e))?;
    ensure_success(vendor, &req.endpoint, status, &body)?;
    Ok(HttpResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_method_detection_covers_verbs_and_channels() {
        for verb in ["GET", "post", "Patch", "PUT", "DELETE", "HEAD"] {
            assert!(is_http_method(verb), "{verb} 应判为 HTTP 动词");
        }
        for channel in ["SEND", "SMTP-SEND", "NOTIFY", ""] {
            assert!(!is_http_method(channel), "{channel} 不应判为 HTTP 动词");
        }
    }

    #[test]
    fn snippet_truncates_long_bodies() {
        assert_eq!(snippet("  ok \n"), "ok");
        let long = "x".repeat(MAX_BODY_SNIPPET + 50);
        let cut = snippet(&long);
        assert_eq!(cut.chars().count(), MAX_BODY_SNIPPET + 1, "截断后应带省略号");
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn success_matrix_maps_status_to_retryability() {
        assert!(ensure_success("jira", "https://jira.example.invalid/x", 200, "{}").is_ok());
        assert!(ensure_success("jira", "https://jira.example.invalid/x", 204, "").is_ok());
        for status in [400, 401, 403, 404, 429] {
            let error =
                ensure_success("jira", "https://jira.example.invalid/x", status, "bad").expect_err("4xx 必须报错");
            assert!(!error.is_degradable(), "{status} 属业务错误，不得重试: {error}");
            assert!(matches!(
                error,
                DomainError::Validation(_)
                    | DomainError::Unauthenticated(_)
                    | DomainError::Forbidden(_)
                    | DomainError::RateLimited(_)
            ));
        }
        for status in [500, 502, 503, 504] {
            let error =
                ensure_success("jira", "https://jira.example.invalid/x", status, "boom").expect_err("5xx 必须报错");
            assert!(error.is_degradable(), "{status} 必须可重试（按 RetryConfig）");
            assert!(matches!(error, DomainError::DependencyUnavailable { .. }));
        }
    }

    #[test]
    fn error_text_never_contains_webhook_token() {
        let token = "9f8e7d6c5b4a3210";
        let endpoint = format!("https://oapi.dingtalk.com/robot/send?access_token={token}");
        let error = ensure_success("dingtalk", &endpoint, 500, "server error").expect_err("5xx 必须报错");
        let text = error.to_string();
        assert!(!text.contains(token), "错误文本不得泄露 Webhook token: {text}");
        assert!(text.contains("access_token="), "但应保留键名便于排障");
    }

    #[test]
    fn extract_id_handles_nested_and_numeric_shapes() {
        assert_eq!(extract_id(r#"{"key":"SEC-1","id":"10001"}"#, &["key", "id"]).as_deref(), Some("SEC-1"));
        assert_eq!(extract_id(r#"{"data":{"sys_id":"abc123"}}"#, DEFAULT_ID_CANDIDATES).as_deref(), Some("abc123"));
        assert_eq!(extract_id(r#"{"id":42}"#, DEFAULT_ID_CANDIDATES).as_deref(), Some("42"));
        assert_eq!(extract_id(r#"{"id":"   "}"#, DEFAULT_ID_CANDIDATES), None, "空白 id 视为未提供");
        assert_eq!(extract_id("not json", DEFAULT_ID_CANDIDATES), None);
        assert_eq!(extract_id("[]", DEFAULT_ID_CANDIDATES), None);
    }

    #[test]
    fn response_success_helper() {
        assert!(HttpResponse { status: 200, body: String::new() }.is_success());
        assert!(!HttpResponse { status: 302, body: String::new() }.is_success());
        let roundtrip = serde_json::to_string(&HttpResponse { status: 200, body: "ok".into() }).unwrap_or_default();
        let back: Option<HttpResponse> = serde_json::from_str(&roundtrip).ok();
        assert_eq!(back.map(|r| r.body), Some("ok".to_string()));
    }

    #[tokio::test]
    async fn non_http_channel_is_rejected_before_any_io() {
        let req = VendorRequest::channel("SEND", "syslog://10.0.0.1:514", serde_json::Value::Null);
        let settings = AdapterSettings::defaults(&crate::contract::AdapterMetadata::new(
            "x",
            "X",
            "t",
            crate::contract::AdapterCategory::SecurityPlatform,
        ));
        let error = execute("x", &req, &settings).await.expect_err("非 HTTP 通道必须被拒绝");
        assert!(matches!(error, DomainError::Validation(_)));
        assert!(error.to_string().contains("SEND"));
    }

    #[tokio::test]
    async fn invalid_header_name_is_rejected_before_any_io() {
        let req = VendorRequest::post("http://127.0.0.1:1/x", "application/json", serde_json::json!({}))
            .with_header("Bad Header", "v");
        let settings = AdapterSettings::defaults(&crate::contract::AdapterMetadata::new(
            "x",
            "X",
            "t",
            crate::contract::AdapterCategory::Notification,
        ));
        let error = execute("x", &req, &settings).await.expect_err("非法头名必须被拒绝");
        assert!(matches!(error, DomainError::Config(_)));
    }
}
