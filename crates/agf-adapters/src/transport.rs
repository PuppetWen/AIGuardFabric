//! 厂商请求编码载体与确定性工具。
//!
//! **编码与传输分离**：[`VendorRequest`] 是"将要发出的请求"的完整、确定性描述
//! （方法/地址/头/体），由 [`crate::vendor::VendorSpec::encode`] 纯函数产出，
//! 因此可在离线环境被完整断言——这正是 `docs/adapter-spec.md` §6.1 第 13 条"离线可测"的落点；
//! 真实发送由 [`crate::http::execute`]（HTTP）或厂商覆写的
//! [`crate::vendor::VendorSpec::invoke_live`]（Syslog UDP/TCP、SMTP）完成。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | `settings.secret("*")` 可解析出的 endpoint 缺失 | 编码即返回 `DomainError::Config`，不进入发送流程（**不建连**） |
//! | 需要日志输出 endpoint | 一律用 [`redact_url`] 脱敏（Webhook URL / token 常内嵌在 URL 中） |

use std::collections::BTreeMap;

use agf_core::secret::mask_default;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// 厂商请求（编码产物）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VendorRequest {
    /// HTTP 方法（Syslog 等非 HTTP 通道用 `SEND`/`NOTIFY` 等自描述动词）。
    pub method: String,
    /// 目标地址（已脱敏形态请用 [`redact_url`]，本字段保留原值供真实发送使用）。
    pub endpoint: String,
    /// Content-Type。
    pub content_type: String,
    /// 请求头。
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// 请求体。
    pub body: serde_json::Value,
}

impl VendorRequest {
    /// 构造 POST 请求。
    #[must_use]
    pub fn post(endpoint: impl Into<String>, content_type: &str, body: serde_json::Value) -> Self {
        Self {
            method: "POST".to_string(),
            endpoint: endpoint.into(),
            content_type: content_type.to_string(),
            headers: BTreeMap::new(),
            body,
        }
    }

    /// 构造自定义动词请求（非 HTTP 通道）。
    #[must_use]
    pub fn channel(method: &str, endpoint: impl Into<String>, body: serde_json::Value) -> Self {
        Self {
            method: method.to_string(),
            endpoint: endpoint.into(),
            content_type: "application/json".to_string(),
            headers: BTreeMap::new(),
            body,
        }
    }

    /// 追加请求头（链式）。
    #[must_use]
    pub fn with_header(mut self, key: &str, value: impl Into<String>) -> Self {
        self.headers.insert(key.to_string(), value.into());
        self
    }

    /// 脱敏后的 endpoint（可安全写日志/落库）。
    #[must_use]
    pub fn masked_endpoint(&self) -> String {
        redact_url(&self.endpoint)
    }

    /// 请求体 JSON 文本（确定性：`serde_json` 启用 `preserve_order`，字段顺序稳定）。
    #[must_use]
    pub fn body_text(&self) -> String {
        self.body.to_string()
    }
}

/// 由内容派生的确定性短令牌（SHA-256 → URL-safe base64 前 12 字节）。
///
/// 用途：Mock 回执 id、幂等键、离线队列键。**不含随机源**，因此同一输入恒等。
#[must_use]
pub fn deterministic_token(namespace: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..12])
}

/// URL 脱敏：查询串取值、UserInfo 与疑似令牌的末段路径全部掩码。
///
/// 例：`https://open.feishu.cn/open-apis/bot/v2/hook/9f8e...` →
/// `https://open.feishu.cn/open-apis/bot/v2/hook/9f8****cdef`。
#[must_use]
pub fn redact_url(url: &str) -> String {
    let (base, query) = url.split_once('?').map_or((url, None), |(b, q)| (b, Some(q)));
    let mut out = redact_base(base);
    if let Some(query) = query {
        out.push('?');
        let parts: Vec<String> = query
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) if !v.is_empty() => format!("{k}={}", mask_default(v)),
                _ => pair.to_string(),
            })
            .collect();
        out.push_str(&parts.join("&"));
    }
    out
}

/// 掩码 URL 的 UserInfo 与末段路径。
fn redact_base(base: &str) -> String {
    let (scheme, rest) = base.split_once("://").map_or(("", base), |(s, r)| (s, r));
    // 去掉 UserInfo（user:pass@host）
    let rest = match rest.split_once('@') {
        Some((_userinfo, host)) => host.to_string(),
        None => rest.to_string(),
    };
    let mut segments: Vec<String> = rest.split('/').map(ToString::to_string).collect();
    if let Some(last) = segments.last_mut() {
        if last.chars().count() >= 16 && last.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            *last = mask_default(last);
        }
    }
    let joined = segments.join("/");
    if scheme.is_empty() { joined } else { format!("{scheme}://{joined}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_token_is_stable_and_namespaced() {
        let a = deterministic_token("ns", "key");
        assert_eq!(a, deterministic_token("ns", "key"));
        assert_ne!(a, deterministic_token("ns2", "key"));
        assert_ne!(a, deterministic_token("ns", "key2"));
        assert_eq!(a.len(), 16, "12 字节 base64url 无填充 = 16 字符");
    }

    #[test]
    fn redact_url_masks_query_values() {
        let masked = redact_url("https://oapi.dingtalk.com/robot/send?access_token=abcdef1234567890");
        assert!(!masked.contains("abcdef1234567890"), "查询串令牌必须被掩码: {masked}");
        assert!(masked.starts_with("https://oapi.dingtalk.com/robot/send?access_token="));
    }

    #[test]
    fn redact_url_masks_long_final_segment_and_userinfo() {
        let masked = redact_url("https://open.feishu.cn/open-apis/bot/v2/hook/9f8e7d6c5b4a3210");
        assert!(!masked.contains("9f8e7d6c5b4a3210"), "{masked}");
        let with_userinfo = redact_url("smtp://user:secretpass@mail.example.com:587");
        assert!(!with_userinfo.contains("secretpass"), "{with_userinfo}");
        assert!(with_userinfo.contains("mail.example.com:587"));
    }

    #[test]
    fn redact_url_keeps_short_paths_intact() {
        let url = "https://jira.example.com/rest/api/2/issue";
        assert_eq!(redact_url(url), url);
    }

    #[test]
    fn vendor_request_builders_and_body_text() {
        let req = VendorRequest::post("https://x/y", "application/json", serde_json::json!({"a": 1}))
            .with_header("X-Test", "1");
        assert_eq!(req.method, "POST");
        assert_eq!(req.headers.get("X-Test").map(String::as_str), Some("1"));
        assert_eq!(req.body_text(), r#"{"a":1}"#);
        assert_eq!(req.masked_endpoint(), "https://x/y");
        let ch = VendorRequest::channel("SEND", "syslog://10.0.0.1:514", serde_json::Value::Null);
        assert_eq!(ch.method, "SEND");
    }

    #[test]
    fn vendor_request_serde_roundtrip() {
        let req = VendorRequest::post("https://x/y", "application/json", serde_json::json!({"a": [1, 2]}));
        let json = serde_json::to_string(&req).unwrap_or_default();
        let back: Option<VendorRequest> = serde_json::from_str(&json).ok();
        assert_eq!(back, Some(req));
    }
}
