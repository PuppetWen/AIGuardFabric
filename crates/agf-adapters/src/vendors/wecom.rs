//! 企业微信机器人适配器。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | 群机器人 Webhook（真实 HTTP `POST /cgi-bin/webhook/send?key=<key>`） |
//! | 凭据 | `webhook_url`（必需，**URL 本身即凭据**） |
//! | 设置 | `allow_custom_host`（可选，默认 `false`；私有化企业微信/网关代理时放行自定义域名） |
//! | 报文 | `msgtype=markdown`（企业微信限制正文 4096 字符，超长**尾部截断**并标记） |
//! | 响应 | HTTP 200 + 业务码 `errcode`（0 为成功）；非 0 报 `Validation`（不重试） |
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `webhook_url` | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包** |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock 回执，**绝不发起真实请求** |
//! | 正文超长 | 按官方 4096 字符限制截断（附 `……（内容已截断）`）而非发送失败，保证"重要结论先送达" |
//! | Webhook 域名非企业微信且未开 `allow_custom_host` | `init()` 阶段返回 `Config`，旧配置保持不变 |
//! | 上游返回 `errcode != 0` / 5xx / 超时 | 如实返回 `Validation` / `DependencyUnavailable`（按 `RetryConfig` 重试）/ `Timeout` |

use agf_core::error::DomainResult;
use serde_json::json;

use crate::contract::{AdapterCategory, AdapterMessage, AdapterMetadata};
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec;

/// 企业微信 markdown 正文上限（字符数，官方限制 4096 字节，这里按字符保守处理）。
pub const MAX_CONTENT_CHARS: usize = 4096;

/// 截断标记。
pub const TRUNCATED_SUFFIX: &str = "……（内容已截断，完整内容见控制台）";

/// 企业微信适配器标记类型。
#[derive(Debug)]
pub struct WeCom;

impl WeCom {
    /// 按字符数截断（UTF-8 安全，不产生半个字符）。
    #[must_use]
    pub fn truncate_markdown(text: &str, limit: usize) -> String {
        let count = text.chars().count();
        if count <= limit {
            return text.to_string();
        }
        let keep = limit.saturating_sub(TRUNCATED_SUFFIX.chars().count());
        let mut out: String = text.chars().take(keep).collect();
        out.push_str(TRUNCATED_SUFFIX);
        out
    }

    /// Markdown 报文。
    #[must_use]
    pub fn markdown_body(msg: &AdapterMessage) -> serde_json::Value {
        let content = format!(
            "### {} {}\n> 等级：{}\n\n{}",
            crate::vendors::severity_marker(msg.severity),
            msg.title,
            msg.severity.as_str(),
            msg.render_text()
        );
        json!({
            "msgtype": "markdown",
            "markdown": { "content": Self::truncate_markdown(&content, MAX_CONTENT_CHARS) },
        })
    }
}

impl VendorSpec for WeCom {
    const NAME: &'static str = "wecom";
    const REAL_TRANSPORT: bool = true;

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("wecom", "企业微信机器人", "腾讯", AdapterCategory::Notification)
            .with_secrets(&["webhook_url"], &[])
            .with_capabilities(crate::vendors::notify_capabilities())
            .with_semantics(crate::contract::SemanticProfile::send_only(
                crate::vendors::NOTIFY_PUSH_UNSUPPORTED,
                crate::vendors::NOTIFY_PULL_UNSUPPORTED,
                crate::vendors::NOTIFY_SYNC_UNSUPPORTED,
            ))
            .with_degradation(
                "未配置 Webhook 时不下发任何企业微信通知（事件照常落库并在控制台可见）；\
                 超长正文按官方 4096 字符限制截断，不因长度失败",
            )
            .with_mock_location("crates/agf-adapters/src/vendors/wecom.rs#MockWeComAdapter")
            .with_real_transport(true)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        if let Some(url) = settings.secret_raw("webhook_url") {
            crate::vendors::validate_vendor_webhook_with(
                settings,
                url,
                &["qyapi.weixin.qq.com", "weixin.qq.com"],
                "/cgi-bin/webhook",
            )?;
        }
        Ok(())
    }

    /// 校验企业微信业务码（`errcode`，0 为成功）。
    ///
    /// # Errors
    /// 业务码非 0 或响应体缺 `errcode` 时返回 `DomainError::Validation`。
    fn parse_response(status: u16, body: &str) -> DomainResult<Option<String>> {
        crate::vendors::ensure_business_ok("wecom", status, body, &["errcode"], &["errmsg"])?;
        Ok(None)
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let endpoint = settings.resolve_endpoint(Some("webhook_url"))?;
        Ok(VendorRequest::post(endpoint, "application/json", Self::markdown_body(msg)))
    }
}

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockWeComAdapter = crate::vendor::VendorAdapterImpl<WeCom>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::VendorAdapter;
    use crate::settings::AdapterMode;
    use crate::test_support::settings_for;
    use agf_core::enums::Severity;

    const WEBHOOK: &str = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abcdef1234567890";

    fn message() -> AdapterMessage {
        AdapterMessage::notification("凭证泄露", "发现 sk- 开头的明文密钥").with_severity(Severity::Critical)
    }

    #[test]
    fn markdown_body_has_severity_and_title() {
        let body = WeCom::markdown_body(&message());
        assert_eq!(body["msgtype"], "markdown");
        let content = body["markdown"]["content"].as_str().unwrap_or_default();
        assert!(content.contains("凭证泄露"));
        assert!(content.contains("critical"));
    }

    #[test]
    fn truncation_keeps_limit_and_marks() {
        let long = "a".repeat(MAX_CONTENT_CHARS + 500);
        let truncated = WeCom::truncate_markdown(&long, MAX_CONTENT_CHARS);
        assert_eq!(truncated.chars().count(), MAX_CONTENT_CHARS);
        assert!(truncated.ends_with(TRUNCATED_SUFFIX));
        let short = WeCom::truncate_markdown("短文本", MAX_CONTENT_CHARS);
        assert_eq!(short, "短文本");
    }

    #[test]
    fn truncation_is_utf8_safe() {
        let cjk = "中".repeat(MAX_CONTENT_CHARS + 10);
        let truncated = WeCom::truncate_markdown(&cjk, MAX_CONTENT_CHARS);
        assert_eq!(truncated.chars().count(), MAX_CONTENT_CHARS);
        assert!(truncated.starts_with('中'));
        assert!(truncated.ends_with(TRUNCATED_SUFFIX));
    }

    #[test]
    fn rejects_non_wecom_host() {
        let bad = settings_for(
            &WeCom::metadata(),
            &[],
            &[("webhook_url", "https://open.feishu.cn/open-apis/bot/v2/hook/abc")],
        )
        .expect("设置");
        assert!(WeCom::validate_settings(&bad).is_err());
        let good = settings_for(&WeCom::metadata(), &[], &[("webhook_url", WEBHOOK)]).expect("设置");
        assert!(WeCom::validate_settings(&good).is_ok());
    }

    #[tokio::test]
    async fn encode_and_live_mode_are_real() {
        let settings = settings_for(&WeCom::metadata(), &[], &[("webhook_url", WEBHOOK)]).expect("设置");
        let req = WeCom::encode(&message(), &settings).expect("编码应成功");
        assert_eq!(req.endpoint, WEBHOOK);
        assert_eq!(req.content_type, "application/json");

        let mut adapter = crate::vendor::VendorAdapterImpl::<WeCom>::new();
        adapter
            .init_with(
                &crate::test_support::config_for("wecom", &[], false),
                &crate::test_support::secrets(&[("webhook_url", WEBHOOK)]),
                false,
            )
            .await
            .expect("合法配置");
        assert_eq!(adapter.mode(), AdapterMode::Live);
        assert!(adapter.descriptor().real_implementation, "企业微信已实现真实 HTTP 传输");
        assert!(!adapter.build_record().message.unwrap_or_default().contains("TODO("));
    }

    #[test]
    fn parse_response_maps_errcode() {
        assert_eq!(WeCom::parse_response(200, r#"{"errcode":0,"errmsg":"ok"}"#).ok(), Some(None));
        let error = WeCom::parse_response(200, r#"{"errcode":93000,"errmsg":"invalid webhook url"}"#)
            .expect_err("业务错误码必须报错");
        assert!(error.to_string().contains("93000"), "{error}");
    }

    #[tokio::test]
    async fn unconfigured_reports_missing_secret() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<WeCom>::mocked();
        let receipt = adapter.send(&message()).await.expect("Mock 发送");
        assert!(receipt.mocked);
        let mut fresh = crate::vendor::VendorAdapterImpl::<WeCom>::new();
        fresh
            .init_with(&crate::test_support::config_for("wecom", &[], false), &crate::settings::NoSecrets, false)
            .await
            .expect("未配置不得失败");
        assert!(fresh.send(&message()).await.is_err());
    }
}
