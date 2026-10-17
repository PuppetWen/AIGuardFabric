//! 飞书（Lark）机器人适配器。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | 自定义机器人 Webhook（真实 HTTP `POST /open-apis/bot/v2/hook/<token>`） |
//! | 凭据 | `webhook_url`（必需，**URL 本身即凭据**）、`signing_secret`（可选，开启加签时必需） |
//! | 设置 | `allow_custom_host`（可选，默认 `false`；私有化部署/反向代理网关时放行自定义域名） |
//! | 报文 | 低等级 → `msg_type=text`；`high`/`critical` → `msg_type=interactive` 卡片（带颜色模板） |
//! | 加签 | `sign = base64(HMAC-SHA256(key = "{timestamp}\n{secret}", data = ""))`，随 body 提交 |
//! | 响应 | HTTP 200 + 业务码 `code`（新版）/ `StatusCode`（旧版）；`0` 为成功，非 0 报 `Validation` |
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `webhook_url` | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包**；事件照常落库、控制台可见，不影响主流程与其它通知渠道 |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock 回执（`mocked=true`），**绝不发起真实请求** |
//! | 未配置 `signing_secret` | 不下发签名（`sign`/`timestamp` 字段缺省），按"仅 Webhook 校验"的机器人配置发送 |
//! | Webhook 域名非飞书且未开 `allow_custom_host` | `init()` 阶段返回 `Config`（拒绝把凭据发往非预期主机），旧配置保持不变 |
//! | 上游返回业务错误码 / 5xx / 超时 | 如实返回 `Validation`（不重试）/ `DependencyUnavailable`（按 `RetryConfig` 重试）/ `Timeout`，绝不假装成功 |

use agf_core::error::DomainResult;
use serde_json::json;

use crate::contract::{AdapterCategory, AdapterMessage, AdapterMetadata};
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec;

/// 飞书适配器标记类型。
#[derive(Debug)]
pub struct Feishu;

impl Feishu {
    /// 加签：飞书自定义机器人签名算法。
    ///
    /// `string_to_sign = "{timestamp}\n{secret}"`，`sign = base64(HMAC-SHA256(key = string_to_sign, data = ""))`。
    /// 密钥为空时返回 `None`（调用方不加签字段）。
    #[must_use]
    pub fn sign(timestamp: i64, secret: &str) -> Option<String> {
        if secret.is_empty() {
            return None;
        }
        crate::vendors::hmac_sha256_b64(&format!("{timestamp}\n{secret}"), "")
    }

    /// 纯文本报文。
    #[must_use]
    pub fn text_body(msg: &AdapterMessage) -> serde_json::Value {
        json!({
            "msg_type": "text",
            "content": { "text": format!("{} {}", crate::vendors::severity_marker(msg.severity), msg.render_text()) },
        })
    }

    /// 交互卡片报文（高等级使用，颜色随等级变化）。
    #[must_use]
    pub fn card_body(msg: &AdapterMessage) -> serde_json::Value {
        let mut elements = vec![json!({
            "tag": "markdown",
            "content": msg.summary,
        })];
        if let Some(asset) = &msg.asset {
            elements.push(json!({ "tag": "markdown", "content": format!("**资产**：{asset}") }));
        }
        if !msg.labels.is_empty() {
            let labels: Vec<String> = msg.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
            elements.push(json!({ "tag": "markdown", "content": labels.join("  ") }));
        }
        json!({
            "msg_type": "interactive",
            "card": {
                "config": { "wide_screen_mode": true },
                "header": {
                    "template": crate::vendors::severity_color(msg.severity),
                    "title": { "tag": "plain_text", "content": format!("【{}】{}", msg.severity.as_str(), msg.title) },
                },
                "elements": elements,
            },
        })
    }
}

impl VendorSpec for Feishu {
    const NAME: &'static str = "feishu";
    const REAL_TRANSPORT: bool = true;

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("feishu", "飞书机器人（Lark）", "字节跳动", AdapterCategory::Notification)
            .with_secrets(&["webhook_url"], &["signing_secret"])
            .with_capabilities(crate::vendors::notify_capabilities())
            .with_semantics(crate::contract::SemanticProfile::send_only(
                crate::vendors::NOTIFY_PUSH_UNSUPPORTED,
                crate::vendors::NOTIFY_PULL_UNSUPPORTED,
                crate::vendors::NOTIFY_SYNC_UNSUPPORTED,
            ))
            .with_degradation(
                "未配置 Webhook 时不下发任何飞书通知（事件照常落库并在控制台可见）；\
                 不影响主流程与其它通知渠道，恢复配置后可由死信队列补发",
            )
            .with_mock_location("crates/agf-adapters/src/vendors/feishu.rs#MockFeishuAdapter")
            .with_real_transport(true)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        if let Some(url) = settings.secret_raw("webhook_url") {
            crate::vendors::validate_vendor_webhook_with(
                settings,
                url,
                &["feishu.cn", "larksuite.com"],
                "/open-apis/bot",
            )?;
        }
        Ok(())
    }

    /// 校验飞书业务码（`code` / `StatusCode`，0 为成功）。
    ///
    /// # Errors
    /// 业务码非 0 或响应体缺业务码时返回 `DomainError::Validation`。
    fn parse_response(status: u16, body: &str) -> DomainResult<Option<String>> {
        crate::vendors::ensure_business_ok("feishu", status, body, &["code", "StatusCode"], &["msg", "StatusMessage"])?;
        // 飞书自定义机器人不回传消息 id，receipt.remote_id 如实为 None
        Ok(None)
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let endpoint = settings.resolve_endpoint(Some("webhook_url"))?;
        let mut body = match msg.severity {
            agf_core::enums::Severity::Critical | agf_core::enums::Severity::High => Self::card_body(msg),
            _ => Self::text_body(msg),
        };
        if let Some(secret) = crate::vendors::optional_secret(settings, "signing_secret") {
            let timestamp = agf_core::time::Timestamp::now().unix_secs();
            if let Some(sign) = Self::sign(timestamp, &secret) {
                if let Some(object) = body.as_object_mut() {
                    object.insert("timestamp".to_string(), json!(timestamp.to_string()));
                    object.insert("sign".to_string(), json!(sign));
                }
            }
        }
        Ok(VendorRequest::post(endpoint, "application/json", body))
    }
}

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockFeishuAdapter = crate::vendor::VendorAdapterImpl<Feishu>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{AdapterMessage, VendorAdapter};
    use crate::settings::AdapterMode;
    use crate::test_support::settings_for;
    use agf_core::enums::Severity;
    use agf_core::time::Timestamp;

    fn notification(severity: Severity) -> AdapterMessage {
        AdapterMessage::notification("提示词注入命中", "规则 PA-INJ-001 命中 claude-code@host1")
            .with_severity(severity)
            .with_asset("claude-code@host1")
            .with_label("rule", "PA-INJ-001")
    }

    fn settings(severity_secret: &str) -> AdapterSettings {
        settings_for(
            &Feishu::metadata(),
            &[],
            &[("webhook_url", severity_secret), ("signing_secret", "s3cr3t-signing-key")],
        )
        .expect("测试设置必须可构造")
    }

    #[test]
    fn low_severity_uses_text_message() {
        let body = Feishu::text_body(&notification(Severity::Medium));
        assert_eq!(body["msg_type"], "text");
        assert!(body["content"]["text"].as_str().unwrap_or_default().contains("提示词注入命中"));
    }

    #[test]
    fn high_severity_uses_interactive_card_with_color() {
        let body = Feishu::card_body(&notification(Severity::Critical));
        assert_eq!(body["msg_type"], "interactive");
        assert_eq!(body["card"]["header"]["template"], "red");
        let elements = body["card"]["elements"].as_array().cloned().unwrap_or_default();
        assert!(elements.len() >= 3, "摘要 + 资产 + 标签都应进入卡片");
    }

    #[test]
    fn encode_selects_body_by_severity_and_signs() {
        let settings = settings("https://open.feishu.cn/open-apis/bot/v2/hook/abcdef1234567890");
        let low = Feishu::encode(&notification(Severity::Low), &settings).expect("编码应成功");
        assert_eq!(low.body["msg_type"], "text");
        let mut high_msg = notification(Severity::High);
        high_msg.occurred_at = Timestamp::from_unix_secs(1_700_000_000).expect("时间戳");
        let before = Timestamp::now().unix_secs();
        let high = Feishu::encode(&high_msg, &settings).expect("编码应成功");
        assert_eq!(high.body["msg_type"], "interactive");
        let timestamp: i64 = high.body["timestamp"].as_str().expect("timestamp").parse().expect("Unix 秒");
        assert!((before..=Timestamp::now().unix_secs()).contains(&timestamp), "重发旧告警使用发送时间加签");
        let expected = Feishu::sign(timestamp, "s3cr3t-signing-key").expect("有密钥必须产生签名");
        assert_eq!(high.body["sign"], serde_json::json!(expected));
    }

    #[test]
    fn encode_without_signing_secret_omits_signature() {
        let settings = settings_for(
            &Feishu::metadata(),
            &[],
            &[("webhook_url", "https://open.feishu.cn/open-apis/bot/v2/hook/abcdef1234567890")],
        )
        .expect("测试设置必须可构造");
        let req = Feishu::encode(&notification(Severity::High), &settings).expect("编码应成功");
        assert!(req.body.get("sign").is_none(), "未配置加签密钥时不得带 sign 字段");
        assert!(req.body.get("timestamp").is_none());
    }

    #[test]
    fn signature_is_deterministic_and_key_dependent() {
        let a = Feishu::sign(1_700_000_000, "key-a");
        let b = Feishu::sign(1_700_000_000, "key-a");
        let c = Feishu::sign(1_700_000_000, "key-b");
        assert!(a.is_some());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(Feishu::sign(1_700_000_000, "").is_none());
    }

    #[test]
    fn rejects_webhook_of_other_vendor() {
        let bad = settings("https://oapi.dingtalk.com/robot/send?access_token=abcdef1234567890");
        assert!(Feishu::validate_settings(&bad).is_err(), "非飞书域名必须被拒绝");
        let good = settings("https://open.feishu.cn/open-apis/bot/v2/hook/abcdef1234567890");
        assert!(Feishu::validate_settings(&good).is_ok());
    }

    #[test]
    fn allow_custom_host_enables_privatized_deployment() {
        let custom = settings_for(
            &Feishu::metadata(),
            &[("allow_custom_host", serde_json::json!(true))],
            &[("webhook_url", "https://feishu.internal.example/open-apis/bot/v2/hook/abcdef1234567890")],
        )
        .expect("测试设置必须可构造");
        assert!(Feishu::validate_settings(&custom).is_ok(), "私有化部署需放行自定义域名");
        let strict = settings_for(
            &Feishu::metadata(),
            &[],
            &[("webhook_url", "https://feishu.internal.example/open-apis/bot/v2/hook/abcdef1234567890")],
        )
        .expect("测试设置必须可构造");
        assert!(Feishu::validate_settings(&strict).is_err(), "默认仍须拒绝非厂商域名");
    }

    #[test]
    fn parse_response_maps_business_code() {
        assert_eq!(Feishu::parse_response(200, r#"{"code":0,"msg":"success"}"#).ok(), Some(None));
        assert_eq!(Feishu::parse_response(200, r#"{"StatusCode":0,"StatusMessage":"success"}"#).ok(), Some(None));
        let error =
            Feishu::parse_response(200, r#"{"code":19021,"msg":"sign match fail"}"#).expect_err("业务错误码必须报错");
        assert!(error.to_string().contains("19021"), "{error}");
        assert!(error.to_string().contains("sign match fail"), "{error}");
        assert!(Feishu::parse_response(200, "<html>502</html>").is_err(), "非 JSON 响应不得视为成功");
    }

    #[tokio::test]
    async fn mock_mode_send_is_deterministic_and_accepted() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<Feishu>::mocked();
        assert_eq!(adapter.mode(), AdapterMode::Mocked);
        let msg = notification(Severity::High);
        let first = adapter.send(&msg).await.expect("Mock 发送成功");
        let second = adapter.send(&msg).await.expect("Mock 发送成功");
        assert!(first.mocked);
        assert_eq!(first.remote_id, second.remote_id);
        assert!(first.remote_id.unwrap_or_default().starts_with("mock-"));
        let descriptor = adapter.descriptor();
        assert_eq!(descriptor.name, "feishu");
        assert!(descriptor.real_implementation, "飞书已实现真实 HTTP 传输，必须如实登记");
    }

    #[tokio::test]
    async fn missing_webhook_url_degrades_to_unconfigured() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<Feishu>::new();
        adapter
            .init_with(&crate::test_support::config_for("feishu", &[], false), &crate::settings::NoSecrets, false)
            .await
            .expect("未配置不得导致 init 失败");
        assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
        let error = adapter.send(&notification(Severity::High)).await.expect_err("未配置必须明确失败");
        assert!(error.to_string().contains("webhook_url"));
    }

    #[tokio::test]
    async fn live_mode_encodes_real_request_without_todo_anchor() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<Feishu>::new();
        let lookup = crate::test_support::secrets(&[(
            "webhook_url",
            "https://open.feishu.cn/open-apis/bot/v2/hook/abcdef1234567890",
        )]);
        adapter
            .init_with(&crate::test_support::config_for("feishu", &[], false), &lookup, false)
            .await
            .expect("合法配置应成功");
        assert_eq!(adapter.mode(), AdapterMode::Live);
        // 真实传输已落地：模式为 Live 且健康态不再是"未实现"，编码产物可直接发往飞书
        let request = adapter.encode(&notification(Severity::High)).expect("编码应成功");
        assert_eq!(request.method, "POST");
        assert_eq!(request.endpoint, "https://open.feishu.cn/open-apis/bot/v2/hook/abcdef1234567890");
        assert!(!adapter.build_record().message.unwrap_or_default().contains("TODO("));
    }

    #[test]
    fn timestamp_is_unix_seconds_of_occurrence() {
        let msg = notification(Severity::Medium);
        let timestamp = msg.occurred_at.unix_secs();
        let sign = Feishu::sign(timestamp, "k").unwrap_or_default();
        assert!(!sign.is_empty());
        assert!(Timestamp::now().since_secs(&msg.occurred_at) < 5);
    }
}
