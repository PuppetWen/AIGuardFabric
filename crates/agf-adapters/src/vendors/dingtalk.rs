//! 钉钉机器人适配器。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | 自定义机器人 Webhook（真实 HTTP `POST /robot/send?access_token=<token>`） |
//! | 凭据 | `webhook_url`（必需，**URL 本身即凭据**）、`signing_secret`（可选，开启加签时必需） |
//! | 设置 | `allow_custom_host`（可选，默认 `false`；专有钉钉/网关代理时放行自定义域名） |
//! | 报文 | `msgtype=markdown`（标题 + 正文 + 等级标记） |
//! | 加签 | `sign = urlencode(base64(HMAC-SHA256(key = secret, data = "{timestamp}\n{secret}")))`，随查询串提交 |
//! | 响应 | HTTP 200 + 业务码 `errcode`（0 为成功）；`processQueryKey` 存在时作为远端 id |
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `webhook_url` | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包**；事件照常落库 |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock 回执，**绝不发起真实请求** |
//! | 未配置 `signing_secret` | 按"不加签"发送（与钉钉机器人"加签/关键词"两种安全设置兼容） |
//! | Webhook 域名非钉钉且未开 `allow_custom_host` | `init()` 阶段返回 `Config`，旧配置保持不变 |
//! | 上游返回 `errcode != 0` / 5xx / 超时 | 如实返回 `Validation`（不重试）/ `DependencyUnavailable`（按 `RetryConfig` 重试）/ `Timeout` |

use agf_core::error::DomainResult;
use serde_json::json;

use crate::contract::{AdapterCategory, AdapterMessage, AdapterMetadata};
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec;

/// 钉钉适配器标记类型。
#[derive(Debug)]
pub struct DingTalk;

impl DingTalk {
    /// 加签：钉钉自定义机器人签名算法（返回 base64 原文，未 URL 编码）。
    ///
    /// `string_to_sign = "{timestamp}\n{secret}"`，`sign = base64(HMAC-SHA256(key = secret, data = string_to_sign))`。
    #[must_use]
    pub fn sign(timestamp: i64, secret: &str) -> Option<String> {
        if secret.is_empty() {
            return None;
        }
        crate::vendors::hmac_sha256_b64(secret, &format!("{timestamp}\n{secret}"))
    }

    /// 把 `timestamp` / `sign` 追加到 Webhook URL（保留原有 `access_token` 查询串）。
    #[must_use]
    pub fn signed_endpoint(endpoint: &str, timestamp: i64, secret: &str) -> String {
        let Some(sign) = Self::sign(timestamp, secret) else {
            return endpoint.to_string();
        };
        let encoded: String = url::form_urlencoded::byte_serialize(sign.as_bytes()).collect();
        let separator = if endpoint.contains('?') { '&' } else { '?' };
        format!("{endpoint}{separator}timestamp={timestamp}&sign={encoded}")
    }

    /// Markdown 报文。
    #[must_use]
    pub fn markdown_body(msg: &AdapterMessage) -> serde_json::Value {
        json!({
            "msgtype": "markdown",
            "markdown": {
                "title": msg.title,
                "text": format!("### {} {}\n\n{}", crate::vendors::severity_marker(msg.severity), msg.title, msg.render_text()),
            },
            "at": { "isAtAll": false },
        })
    }
}

impl VendorSpec for DingTalk {
    const NAME: &'static str = "dingtalk";
    const REAL_TRANSPORT: bool = true;

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("dingtalk", "钉钉机器人", "阿里巴巴", AdapterCategory::Notification)
            .with_secrets(&["webhook_url"], &["signing_secret"])
            .with_capabilities(crate::vendors::notify_capabilities())
            .with_semantics(crate::contract::SemanticProfile::send_only(
                crate::vendors::NOTIFY_PUSH_UNSUPPORTED,
                crate::vendors::NOTIFY_PULL_UNSUPPORTED,
                crate::vendors::NOTIFY_SYNC_UNSUPPORTED,
            ))
            .with_degradation(
                "未配置 Webhook 时不下发任何钉钉通知（事件照常落库并在控制台可见）；\
                 加签密钥缺失时按不加签发送，不影响其它通知渠道",
            )
            .with_mock_location("crates/agf-adapters/src/vendors/dingtalk.rs#MockDingTalkAdapter")
            .with_real_transport(true)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        if let Some(url) = settings.secret_raw("webhook_url") {
            crate::vendors::validate_vendor_webhook_with(settings, url, &["dingtalk.com"], "/robot/send")?;
        }
        Ok(())
    }

    /// 校验钉钉业务码（`errcode`，0 为成功），命中时返回 `processQueryKey` 作为远端 id。
    ///
    /// # Errors
    /// 业务码非 0 或响应体缺 `errcode` 时返回 `DomainError::Validation`。
    fn parse_response(status: u16, body: &str) -> DomainResult<Option<String>> {
        crate::vendors::ensure_business_ok("dingtalk", status, body, &["errcode"], &["errmsg"])?;
        Ok(crate::http::extract_id(body, &["processQueryKey", "data.processQueryKey"]))
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let endpoint = settings.resolve_endpoint(Some("webhook_url"))?;
        let endpoint = match crate::vendors::optional_secret(settings, "signing_secret") {
            // 签名使用发送时的毫秒时间戳；历史告警重发不能沿用事件发生时间。
            Some(secret) => Self::signed_endpoint(&endpoint, agf_core::time::Timestamp::now().unix_millis(), &secret),
            None => endpoint,
        };
        Ok(VendorRequest::post(endpoint, "application/json", Self::markdown_body(msg)))
    }
}

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockDingTalkAdapter = crate::vendor::VendorAdapterImpl<DingTalk>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{AdapterMessage, VendorAdapter};
    use crate::settings::AdapterMode;
    use crate::test_support::settings_for;
    use agf_core::enums::Severity;

    const WEBHOOK: &str = "https://oapi.dingtalk.com/robot/send?access_token=abcdef1234567890";

    fn message() -> AdapterMessage {
        AdapterMessage::notification("高危提示词注入", "命中规则 PA-INJ-007")
            .with_severity(Severity::High)
            .with_asset("cursor@host2")
    }

    #[test]
    fn markdown_body_shape() {
        let body = DingTalk::markdown_body(&message());
        assert_eq!(body["msgtype"], "markdown");
        assert_eq!(body["markdown"]["title"], "高危提示词注入");
        assert!(body["markdown"]["text"].as_str().unwrap_or_default().contains("PA-INJ-007"));
        assert_eq!(body["at"]["isAtAll"], false);
    }

    #[test]
    fn signature_matches_dingtalk_algorithm() {
        let remote = DingTalk::sign(1_700_000_000, "SECdeadbeef").unwrap_or_default();
        let expected = crate::vendors::hmac_sha256_b64("SECdeadbeef", "1700000000\nSECdeadbeef").unwrap_or_default();
        assert_eq!(remote, expected);
        assert_eq!(DingTalk::sign(1_700_000_000, "SECdeadbeef"), DingTalk::sign(1_700_000_000, "SECdeadbeef"));
        assert!(DingTalk::sign(1, "").is_none());
    }

    #[test]
    fn signed_endpoint_appends_query_and_percent_encodes() {
        let url = DingTalk::signed_endpoint(WEBHOOK, 1_700_000_000, "SECdeadbeef");
        assert!(url.contains("timestamp=1700000000"), "{url}");
        assert!(url.contains("&sign="), "已有查询串时必须以 & 追加: {url}");
        assert!(url.contains("access_token=abcdef1234567890"), "原有 token 必须保留");
        assert!(!url.contains('+'), "base64 的 + 必须被 URL 编码: {url}");
        let no_query = DingTalk::signed_endpoint("https://oapi.dingtalk.com/robot/send", 1, "k");
        assert!(no_query.contains("?timestamp=1"));
        assert_eq!(DingTalk::signed_endpoint(WEBHOOK, 1, ""), WEBHOOK, "无密钥时不加签");
    }

    #[test]
    fn encode_uses_signed_endpoint_when_secret_present() {
        let settings =
            settings_for(&DingTalk::metadata(), &[], &[("webhook_url", WEBHOOK), ("signing_secret", "SECdeadbeef")])
                .expect("测试设置必须可构造");
        let req = DingTalk::encode(&message(), &settings).expect("编码应成功");
        assert!(req.endpoint.contains("sign="));
        let url = url::Url::parse(&req.endpoint).expect("URL");
        let timestamp: i64 =
            url.query_pairs().find(|(key, _)| key == "timestamp").expect("timestamp").1.parse().expect("millis");
        assert!((agf_core::time::Timestamp::now().unix_millis() - timestamp).abs() < 5000);
        assert_eq!(req.method, "POST");

        let unsigned = settings_for(&DingTalk::metadata(), &[], &[("webhook_url", WEBHOOK)]).expect("设置");
        let req = DingTalk::encode(&message(), &unsigned).expect("编码应成功");
        assert!(!req.endpoint.contains("sign="));
    }

    #[test]
    fn rejects_non_dingtalk_webhook() {
        let bad = settings_for(
            &DingTalk::metadata(),
            &[],
            &[("webhook_url", "https://open.feishu.cn/open-apis/bot/v2/hook/abcdef1234567890")],
        )
        .expect("设置");
        assert!(DingTalk::validate_settings(&bad).is_err());
        let good = settings_for(&DingTalk::metadata(), &[], &[("webhook_url", WEBHOOK)]).expect("设置");
        assert!(DingTalk::validate_settings(&good).is_ok());
    }

    #[tokio::test]
    async fn mock_receipt_is_deterministic() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<DingTalk>::mocked();
        let first = adapter.send(&message()).await.expect("Mock 发送");
        let second = adapter.send(&message()).await.expect("Mock 发送");
        assert_eq!(first.remote_id, second.remote_id);
        assert_eq!(adapter.mode(), AdapterMode::Mocked);
    }

    #[tokio::test]
    async fn live_mode_is_enabled_with_real_transport() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<DingTalk>::new();
        let lookup = crate::test_support::secrets(&[("webhook_url", WEBHOOK)]);
        adapter
            .init_with(&crate::test_support::config_for("dingtalk", &[], false), &lookup, false)
            .await
            .expect("合法配置");
        assert_eq!(adapter.mode(), AdapterMode::Live);
        assert!(adapter.descriptor().real_implementation, "钉钉已实现真实 HTTP 传输");
        assert!(adapter.encode(&message()).is_ok(), "编码本身必须可用");
        assert!(!adapter.build_record().message.unwrap_or_default().contains("TODO("));
    }

    #[test]
    fn parse_response_maps_errcode_and_process_query_key() {
        assert_eq!(DingTalk::parse_response(200, r#"{"errcode":0,"errmsg":"ok"}"#).ok(), Some(None));
        assert_eq!(
            DingTalk::parse_response(200, r#"{"errcode":0,"errmsg":"ok","processQueryKey":"pqk-1"}"#)
                .ok()
                .flatten()
                .as_deref(),
            Some("pqk-1")
        );
        let error =
            DingTalk::parse_response(200, r#"{"errcode":310000,"errmsg":"sign not match"}"#).expect_err("必须报错");
        assert!(error.to_string().contains("310000"), "{error}");
        assert!(!error.is_degradable(), "业务错误码不得重试");
    }

    #[test]
    fn allow_custom_host_enables_privatized_deployment() {
        let privatized = settings_for(
            &DingTalk::metadata(),
            &[("allow_custom_host", json!(true))],
            &[("webhook_url", "https://dingtalk.internal.example/robot/send?access_token=abcdef1234567890")],
        )
        .expect("设置");
        assert!(DingTalk::validate_settings(&privatized).is_ok());
    }
}
