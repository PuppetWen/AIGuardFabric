//! Slack 适配器（Incoming Webhook 投递 + Web API 消息更新/撤回）。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | Incoming Webhook（真实 HTTP `POST /services/T.../B.../<token>`）；`push` 走 Web API |
//! | 凭据 | `webhook_url`（必需，**URL 本身即凭据**）、`bot_token`（可选，`xoxb-`，仅 `push` 需要） |
//! | 设置 | `channel`（可选，覆盖默认频道）、`api_base`（可选，默认 `https://slack.com`）、`allow_custom_host`（可选，默认 `false`） |
//! | 报文 | `text` + Block Kit（`header` + `section` + `context`），`mrkdwn` 片段 |
//! | 响应 | Incoming Webhook 成功返回纯文本 `ok`；Web API 返回 `{"ok":true,...}` |
//! | `push` | `POST {api_base}/api/chat.update`（更新已投递消息）、`POST {api_base}/api/chat.delete`（撤回） |
//! | `pull`/`sync` | **Unsupported**：Slack 侧可读取频道历史，但那属于 `conversation.*` 域，不在对账语义内 |
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `webhook_url` | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包** |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock 回执，**绝不发起真实请求** |
//! | `channel` 缺失/非法 | 缺失时使用 Webhook 默认频道；非法（含空白）时 `init()` 返回 `Config` |
//! | `push` 缺 `bot_token` | `Config` 错误（`send` 主路径不受影响）——Incoming Webhook 无更新/撤回权限 |
//! | `push` 缺 `ts`/`channel` | `Validation`：不知道改哪条消息 |
//! | 超长 `text` | 由平台侧摘要字段控制（本适配器不截断 Block 结构，避免渲染错乱） |
//! | 上游返回非 `ok` / 5xx / 超时 | 如实返回 `Validation` / `DependencyUnavailable`（按 `RetryConfig` 重试）/ `Timeout` |

use agf_core::adapter::PushPayload;
use agf_core::error::DomainResult;
use serde_json::json;

use crate::contract::{AdapterCategory, AdapterMessage, AdapterMetadata, SemanticProfile};
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec;

/// Slack 适配器标记类型。
#[derive(Debug)]
pub struct Slack;

impl Slack {
    /// Block Kit 报文。
    #[must_use]
    pub fn blocks_body(msg: &AdapterMessage, channel: Option<&str>) -> serde_json::Value {
        let mut blocks = vec![
            json!({
                "type": "header",
                "text": { "type": "plain_text", "text": format!("{} {}", crate::vendors::severity_marker(msg.severity), msg.title), "emoji": true },
            }),
            json!({
                "type": "section",
                "text": { "type": "mrkdwn", "text": msg.summary },
            }),
        ];
        let mut context: Vec<String> =
            vec![format!("severity={}", msg.severity.as_str()), format!("event={}", msg.event_type)];
        if let Some(asset) = &msg.asset {
            context.push(format!("asset={asset}"));
        }
        context.extend(msg.labels.iter().map(|(k, v)| format!("{k}={v}")));
        blocks.push(json!({
            "type": "context",
            "elements": [{ "type": "mrkdwn", "text": context.join("  |  ") }],
        }));
        let mut body = json!({
            "text": format!("【{}】{}", msg.severity.as_str(), msg.title),
            "blocks": blocks,
        });
        if let Some(channel) = channel {
            if let Some(object) = body.as_object_mut() {
                object.insert("channel".to_string(), json!(channel));
            }
        }
        body
    }
}

impl VendorSpec for Slack {
    const NAME: &'static str = "slack";
    const REAL_TRANSPORT: bool = true;

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("slack", "Slack Incoming Webhook", "Salesforce", AdapterCategory::Notification)
            .with_secrets(&["webhook_url"], &["bot_token"])
            .with_capabilities(crate::vendors::notify_capabilities())
            .with_semantics(SemanticProfile::push_only(
                crate::vendors::MESSAGE_API_PULL_UNSUPPORTED,
                crate::vendors::MESSAGE_API_SYNC_UNSUPPORTED,
            ))
            .with_degradation(
                "未配置 Webhook 时不下发任何 Slack 消息（事件照常落库并在控制台可见）；\
                 频道覆盖设置缺失时使用 Webhook 默认频道；\
                 消息更新/撤回需额外配置 bot_token，缺失时 push 返回 Config（send 主路径不受影响）",
            )
            .with_mock_location("crates/agf-adapters/src/vendors/slack.rs#MockSlackAdapter")
            .with_real_transport(true)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        if let Some(url) = settings.secret_raw("webhook_url") {
            crate::vendors::validate_vendor_webhook_with(settings, url, &["hooks.slack.com"], "/services/")?;
        }
        if let Some(channel) = settings.get_str("channel") {
            if channel.trim().is_empty() || channel.contains(char::is_whitespace) {
                return Err(agf_core::error::DomainError::Config(format!("Slack 频道名非法: {channel:?}")));
            }
        }
        if let Some(api_base) = settings.get_str("api_base") {
            // 复用 webhook 的"厂商域名 + 自定义主机开关"口径：push 不得把 bot_token 发往任意主机
            crate::vendors::validate_vendor_webhook_with(settings, api_base, &["slack.com"], "/")?;
        }
        if let Some(token) = settings.secret_raw("bot_token") {
            if !token.trim().starts_with("xoxb-") {
                return Err(agf_core::error::DomainError::Config(
                    "Slack bot_token 形态非法（应为 xoxb- 前缀的 Bot User OAuth Token）".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// 消息维度回写（`chat.update` / `chat.delete`）。
    ///
    /// # Errors
    /// 实体名不支持、缺 `ts`/频道/`bot_token` 时返回错误（见 [`Slack::encode_push_requests`]）。
    fn encode_push(payload: &PushPayload, settings: &AdapterSettings) -> DomainResult<Vec<VendorRequest>> {
        Self::encode_push_requests(payload, settings)
    }

    /// Web API 回写响应：`{"ok":true,...}` / `{"ok":false,"error":"..."}`。
    ///
    /// # Errors
    /// `ok` 非 `true` 或响应体非 JSON 时返回 `DomainError::Validation`。
    fn parse_push_response(status: u16, body: &str) -> DomainResult<Option<String>> {
        Self::parse_push_response(status, body)
    }

    /// Incoming Webhook 的成功响应是纯文本 `ok`。
    ///
    /// # Errors
    /// 响应体不是 `ok` 时返回 `DomainError::Validation`。
    fn parse_response(status: u16, body: &str) -> DomainResult<Option<String>> {
        let trimmed = body.trim();
        if trimmed.eq_ignore_ascii_case("ok") || trimmed.is_empty() {
            return Ok(None);
        }
        Err(agf_core::error::DomainError::Validation(format!(
            "slack 上游返回 HTTP {status} 但响应不是 ok: {}",
            crate::http::snippet(trimmed)
        )))
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let endpoint = settings.resolve_endpoint(Some("webhook_url"))?;
        let channel = settings.get_str("channel");
        Ok(VendorRequest::post(endpoint, "application/json", Self::blocks_body(msg, channel)))
    }
}

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockSlackAdapter = crate::vendor::VendorAdapterImpl<Slack>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::VendorAdapter;
    use crate::settings::AdapterMode;
    use crate::test_support::settings_for;
    use agf_core::enums::Severity;

    // Intentionally invalid Slack credential; configuration validation only needs the /services/ prefix.
    const HOOK: &str = "https://hooks.slack.com/services/test-only";

    fn message() -> AdapterMessage {
        AdapterMessage::event(
            "ai.model.endpoint.changed",
            Severity::Medium,
            "模型端点变更",
            "base_url 由 A 改为 B",
            json!({}),
        )
        .with_asset("gpt-4o@gateway")
        .with_label("env", "prod")
    }

    #[test]
    fn blocks_body_contains_header_section_and_context() {
        let body = Slack::blocks_body(&message(), None);
        assert_eq!(body["text"], "【medium】模型端点变更");
        let blocks = body["blocks"].as_array().cloned().unwrap_or_default();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0]["type"], "header");
        assert_eq!(blocks[1]["type"], "section");
        assert_eq!(blocks[2]["type"], "context");
        let context = blocks[2]["elements"][0]["text"].as_str().unwrap_or_default();
        assert!(context.contains("severity=medium"));
        assert!(context.contains("asset=gpt-4o@gateway"));
        assert!(context.contains("env=prod"));
    }

    #[test]
    fn channel_override_is_included_only_when_present() {
        let with_channel = Slack::blocks_body(&message(), Some("#sec-alerts"));
        assert_eq!(with_channel["channel"], "#sec-alerts");
        let without = Slack::blocks_body(&message(), None);
        assert!(without.get("channel").is_none());
    }

    #[test]
    fn encode_uses_channel_setting() {
        let settings = settings_for(&Slack::metadata(), &[("channel", json!("#sec-alerts"))], &[("webhook_url", HOOK)])
            .expect("设置");
        let req = Slack::encode(&message(), &settings).expect("编码应成功");
        assert_eq!(req.body["channel"], "#sec-alerts");
        assert_eq!(req.endpoint, HOOK);
    }

    #[test]
    fn validation_matrix() {
        let bad_host = settings_for(
            &Slack::metadata(),
            &[],
            &[("webhook_url", "https://hooks.example.invalid/services/T1/B2/abcdefghijklmnopqrstuvwx")],
        )
        .expect("设置");
        assert!(Slack::validate_settings(&bad_host).is_err());
        let bad_channel =
            settings_for(&Slack::metadata(), &[("channel", json!("bad channel"))], &[("webhook_url", HOOK)])
                .expect("设置");
        assert!(Slack::validate_settings(&bad_channel).is_err());
        let good =
            settings_for(&Slack::metadata(), &[("channel", json!("#ok"))], &[("webhook_url", HOOK)]).expect("设置");
        assert!(Slack::validate_settings(&good).is_ok());
    }

    #[tokio::test]
    async fn mock_and_live_modes() {
        let mut mock = crate::vendor::VendorAdapterImpl::<Slack>::mocked();
        let receipt = mock.send(&message()).await.expect("Mock 发送");
        assert!(receipt.mocked && receipt.accepted);
        assert_eq!(receipt.adapter, "slack");

        let mut live = crate::vendor::VendorAdapterImpl::<Slack>::new();
        live.init_with(
            &crate::test_support::config_for("slack", &[], false),
            &crate::test_support::secrets(&[("webhook_url", HOOK)]),
            false,
        )
        .await
        .expect("合法配置");
        assert_eq!(live.mode(), AdapterMode::Live);
        assert!(live.descriptor().real_implementation, "Slack 已实现真实 HTTP 传输");
        // 真实传输已落地，健康态不再标注为"未实现"
        assert_eq!(live.build_record().status, crate::health::HealthStatus::Available);
        assert!(!live.build_record().message.unwrap_or_default().contains("TODO("));
    }

    #[test]
    fn parse_response_requires_ok_body() {
        assert_eq!(Slack::parse_response(200, "ok").ok(), Some(None));
        assert_eq!(Slack::parse_response(200, "  ok\n").ok(), Some(None));
        let error = Slack::parse_response(200, "invalid_payload").expect_err("非 ok 必须报错");
        assert!(error.to_string().contains("invalid_payload"), "{error}");
        assert!(!error.is_degradable(), "业务错误不得重试");
    }
}
