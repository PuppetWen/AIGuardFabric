//! 通用 Webhook 适配器（对接自建系统 / SOAR / 中间件）。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | 真实 HTTP `POST <webhook_url>`，`application/json` |
//! | 凭据 | `webhook_url`（必需）、`auth_header_value`（可选，自定义鉴权头的值） |
//! | 设置 | `auth_header_name`（可选，默认 `Authorization`） |
//! | 报文 | 稳定信封：`source` / `kind` / `event_type` / `severity` / `title` / `summary` / `asset` / `labels` / `payload` / `idempotency_key` / `occurred_at` |
//! | 幂等 | 同时写入 `Idempotency-Key` 头（`agf-core::constants::HEADER_IDEMPOTENCY_KEY`） |
//! | 响应 | 2xx 即接受；响应体若含 `id`/`task_id`/`data.id` 等字段则作为远端 id |
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 URL | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包**；事件照常落库 |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock 回执，**绝不发起真实请求** |
//! | 鉴权头值缺失 | 按无鉴权发送（需下游自行校验来源）；鉴权头名非法时 `init()` 返回 `Config` |
//! | URL 非 http/https | `init()` 阶段返回 `Config`（拒绝把凭据发往非 HTTP 通道） |
//! | 上游 5xx / 超时 | `DependencyUnavailable` / `Timeout`，**按 `RetryConfig` 重试**（指数退避）；连续失败由熔断器开路 |
//! | 上游 4xx | `Validation`/`Unauthenticated`/`Forbidden`/`RateLimited`，**不重试**（重试不会变好） |
//!
//! 信封结构**向后兼容**：新增字段一律追加，不重命名既有字段，避免下游解析器失效。

use agf_core::error::DomainResult;
use serde_json::json;

use crate::contract::{AdapterCategory, AdapterMessage, AdapterMetadata};
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec;

/// 信封协议版本（下游可据此判断字段语义）。
pub const ENVELOPE_VERSION: &str = "agf.webhook.v1";

/// 事件类型请求头。
pub const HEADER_EVENT_TYPE: &str = "X-AGF-Event-Type";

/// 通用 Webhook 适配器标记类型。
#[derive(Debug)]
pub struct Webhook;

impl Webhook {
    /// 构造稳定信封（字段顺序由 `serde_json` 的 `preserve_order` 保证）。
    #[must_use]
    pub fn envelope(msg: &AdapterMessage) -> serde_json::Value {
        json!({
            "schema": ENVELOPE_VERSION,
            "source": "aiguardfabric",
            "kind": msg.kind.as_str(),
            "event_type": msg.event_type,
            "severity": msg.severity.as_str(),
            "title": msg.title,
            "summary": msg.summary,
            "asset": msg.asset,
            "labels": msg.labels,
            "occurred_at": msg.occurred_at.to_rfc3339(),
            "idempotency_key": msg.idempotency_key,
            "payload": msg.body,
        })
    }
}

impl VendorSpec for Webhook {
    const NAME: &'static str = "webhook";
    const REAL_TRANSPORT: bool = true;

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("webhook", "通用 Webhook", "自建/第三方", AdapterCategory::Notification)
            .with_secrets(&["webhook_url"], &["auth_header_value"])
            .with_capabilities(crate::vendors::notify_capabilities())
            .with_semantics(crate::contract::SemanticProfile::send_only(
                crate::vendors::WEBHOOK_PUSH_UNSUPPORTED,
                crate::vendors::NOTIFY_PULL_UNSUPPORTED,
                crate::vendors::NOTIFY_SYNC_UNSUPPORTED,
            ))
            .with_degradation(
                "未配置 Webhook URL 时不下发任何回调（事件照常落库并在控制台可见）；\
                 鉴权头缺失时按无鉴权发送，需下游自行校验来源",
            )
            .with_mock_location("crates/agf-adapters/src/vendors/webhook.rs#MockWebhookAdapter")
            .with_real_transport(true)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        if let Some(url) = settings.secret_raw("webhook_url") {
            crate::settings::validate_endpoint(url)?;
            let parsed = url::Url::parse(url)
                .map_err(|e| agf_core::error::DomainError::Config(format!("Webhook URL 非法: {e}")))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(agf_core::error::DomainError::Config(format!(
                    "通用 Webhook 只支持 http/https，收到 {}",
                    parsed.scheme()
                )));
            }
        }
        if let Some(name) = settings.get_str("auth_header_name") {
            if name.trim().is_empty() || name.contains(char::is_whitespace) {
                return Err(agf_core::error::DomainError::Config(format!("鉴权头名非法: {name:?}")));
            }
        }
        Ok(())
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let endpoint = settings.resolve_endpoint(Some("webhook_url"))?;
        let mut request = VendorRequest::post(endpoint, "application/json", Self::envelope(msg))
            .with_header(HEADER_EVENT_TYPE, msg.event_type.clone())
            .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, msg.idempotency_key.clone())
            .with_header("X-AGF-Severity", msg.severity.as_str());
        if let Some(value) = crate::vendors::optional_secret(settings, "auth_header_value") {
            let name = settings.get_str("auth_header_name").unwrap_or("Authorization");
            request = request.with_header(name, value);
        }
        Ok(request)
    }
}

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockWebhookAdapter = crate::vendor::VendorAdapterImpl<Webhook>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::VendorAdapter;
    use crate::settings::AdapterMode;
    use crate::test_support::settings_for;
    use agf_core::enums::Severity;

    const HOOK: &str = "https://soar.example.invalid/hooks/agf?token=abcdef1234567890";

    fn message() -> AdapterMessage {
        AdapterMessage::event(
            "ai.asset.discovered",
            Severity::High,
            "发现未纳管 Agent",
            "cursor@host1 未登记",
            json!({"asset": "cursor@host1", "kind": "agent"}),
        )
        .with_asset("cursor@host1")
        .with_label("team", "red-team")
    }

    #[test]
    fn envelope_is_stable_and_complete() {
        let msg = message();
        let envelope = Webhook::envelope(&msg);
        assert_eq!(envelope["schema"], ENVELOPE_VERSION);
        assert_eq!(envelope["kind"], "event");
        assert_eq!(envelope["event_type"], "ai.asset.discovered");
        assert_eq!(envelope["severity"], "high");
        assert_eq!(envelope["asset"], "cursor@host1");
        assert_eq!(envelope["labels"]["team"], "red-team");
        assert_eq!(envelope["payload"]["kind"], "agent");
        assert!(envelope["idempotency_key"].as_str().is_some_and(|k| !k.is_empty()));
        // 同一消息重试时信封必须完全一致；新消息自带独立发生时间。
        assert_eq!(envelope, Webhook::envelope(&msg));
    }

    #[test]
    fn encode_sets_idempotency_and_event_headers() {
        let settings = settings_for(&Webhook::metadata(), &[], &[("webhook_url", HOOK)]).expect("设置");
        let msg = message();
        let req = Webhook::encode(&msg, &settings).expect("编码应成功");
        assert_eq!(req.headers.get(HEADER_EVENT_TYPE).map(String::as_str), Some("ai.asset.discovered"));
        assert_eq!(req.headers.get("Idempotency-Key").map(String::as_str), Some(msg.idempotency_key.as_str()));
        assert_eq!(req.headers.get("X-AGF-Severity").map(String::as_str), Some("high"));
        assert!(!req.headers.contains_key("Authorization"), "未配置鉴权头时不得发送该头");
    }

    #[test]
    fn encode_adds_custom_auth_header_without_leaking_it_in_debug() {
        let settings = settings_for(
            &Webhook::metadata(),
            &[("auth_header_name", json!("X-AGF-Token"))],
            &[("webhook_url", HOOK), ("auth_header_value", "Bearer super-secret-token")],
        )
        .expect("设置");
        let req = Webhook::encode(&message(), &settings).expect("编码应成功");
        assert_eq!(req.headers.get("X-AGF-Token").map(String::as_str), Some("Bearer super-secret-token"));
        let text = format!("{settings:?}");
        assert!(!text.contains("super-secret-token"), "设置 Debug 不得泄露鉴权值");
        assert!(!req.body_text().contains("super-secret-token"), "请求体不得包含鉴权值");
    }

    #[test]
    fn invalid_auth_header_name_is_rejected() {
        let settings =
            settings_for(&Webhook::metadata(), &[("auth_header_name", json!("Bad Header"))], &[("webhook_url", HOOK)])
                .expect("设置");
        assert!(Webhook::validate_settings(&settings).is_err());
    }

    #[test]
    fn non_http_webhook_is_rejected() {
        let settings =
            settings_for(&Webhook::metadata(), &[], &[("webhook_url", "syslog://10.0.0.1:514")]).expect("设置");
        assert!(Webhook::validate_settings(&settings).is_err(), "通用 Webhook 不接受非 HTTP 通道");
    }

    #[tokio::test]
    async fn mock_send_is_deterministic_and_live_uses_real_transport() {
        let mut mock = crate::vendor::VendorAdapterImpl::<Webhook>::mocked();
        let first = mock.send(&message()).await.expect("Mock 发送");
        assert_eq!(first.remote_id, mock.send(&message()).await.expect("Mock 发送").remote_id);

        let mut live = crate::vendor::VendorAdapterImpl::<Webhook>::new();
        live.init_with(
            &crate::test_support::config_for("webhook", &[], false),
            &crate::test_support::secrets(&[("webhook_url", HOOK)]),
            false,
        )
        .await
        .expect("合法配置");
        assert_eq!(live.mode(), AdapterMode::Live);
        assert!(live.descriptor().real_implementation, "通用 Webhook 已实现真实 HTTP 传输");
        assert!(!live.build_record().message.unwrap_or_default().contains("TODO("));
        // 编码产物即为真实发出的请求（方法/头/体一致）
        let request = live.encode(&message()).expect("编码应成功");
        assert_eq!(request.method, "POST");
        assert_eq!(request.endpoint, HOOK);
    }

    #[test]
    fn parse_response_extracts_common_id_fields() {
        assert_eq!(Webhook::parse_response(202, r#"{"id":"run-1"}"#).ok().flatten().as_deref(), Some("run-1"));
        assert_eq!(
            Webhook::parse_response(200, r#"{"data":{"task_id":"t-9"}}"#).ok().flatten().as_deref(),
            Some("t-9")
        );
        assert_eq!(Webhook::parse_response(204, "").ok(), Some(None), "空响应体属正常接受");
    }

    #[tokio::test]
    async fn webhook_url_must_be_configured_to_leave_unconfigured_state() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<Webhook>::new();
        adapter
            .init_with(&crate::test_support::config_for("webhook", &[], false), &crate::settings::NoSecrets, false)
            .await
            .expect("未配置不得失败");
        assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
        let record = adapter.build_record();
        assert!(!record.configured);
        assert!(record.message.unwrap_or_default().contains("webhook_url"));
    }
}
