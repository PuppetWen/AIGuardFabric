//! 通知类的**消息维度回写**（Slack Web API）：`chat.update` 更新、`chat.delete` 撤回。
//!
//! 群机器人 Webhook（飞书/钉钉/企业微信）只有投递权限，**没有**更新或撤回接口，
//! 因此它们登记为 [`crate::contract::SemanticSupport::Unsupported`]（原因见
//! [`super::NOTIFY_PUSH_UNSUPPORTED`]）；Slack 则确有 Web API 可用，于是真的实现：
//!
//! | 实体 | 请求 | 凭据 |
//! |---|---|---|
//! | `message.update` | `POST {api_base}/api/chat.update`（`channel` + `ts` + `text`/`blocks`） | `bot_token`（`xoxb-`，**可选凭据**：只有用 push 时才需要） |
//! | `message.revoke` | `POST {api_base}/api/chat.delete`（`channel` + `ts`） | 同上 |
//!
//! `api_base` 默认 `https://slack.com`（`allow_custom_host=true` 时可用于企业网关/本地假服务端）。
//! `entity_id` 即 Slack 消息 `ts`——用 Incoming Webhook 投递时上游不回传 `ts`，
//! 调用方需从 `chat.postMessage` 获取；这也是 `send` 与 `push` 分工的体现
//! （见 [`crate::contract::semantics`] 不变式 1）。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 缺 `bot_token` | `Config` 错误并列出缺项（**不建连**）；`send` 主路径不受影响 |
//! | 缺 `ts`（`entity_id`）/`channel` | `Validation`：没有目标消息或频道，不发请求 |
//! | 实体名不支持 | `Validation`（列出支持项） |
//! | 上游 `ok=false` | `Validation`（Slack 的业务错误码，**不重试**） |

use agf_core::adapter::PushPayload;
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json};

use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec as _;

use super::slack::Slack;
use super::{body_str, push_idempotency_key, require_entity, require_remote_id};

/// Slack Web API 默认主机。
pub const SLACK_API_BASE: &str = "https://slack.com";

/// 支持回写的实体。
pub const MESSAGE_PUSH_ENTITIES: [&str; 2] = ["message.update", "message.revoke"];

impl Slack {
    /// 解析 `api_base` 设置（默认 [`SLACK_API_BASE`]，末尾斜杠归一）。
    ///
    /// 只校验**主机**与 endpoint 合法性（`/api/<method>` 由本模块自己拼），
    /// 因此路径标记用 `/`：`api_base` 本身就是 Web API 的根。
    ///
    /// # Errors
    /// 值非法或非 `slack.com` 主机且未开 `allow_custom_host` 时返回 `DomainError::Config`。
    pub(crate) fn api_base(settings: &AdapterSettings) -> DomainResult<String> {
        let raw = settings.get_str("api_base").map(str::trim).filter(|v| !v.is_empty()).unwrap_or(SLACK_API_BASE);
        crate::vendors::validate_vendor_webhook_with(settings, raw, &["slack.com"], "/")?;
        Ok(raw.trim_end_matches('/').to_string())
    }

    /// 编码消息回写请求（纯函数）。
    ///
    /// # Errors
    /// 实体名不支持、`entity_id`（`ts`）缺失、缺频道/`bot_token`、`api_base` 非法时返回错误。
    pub(crate) fn encode_push_requests(
        payload: &PushPayload,
        settings: &AdapterSettings,
    ) -> DomainResult<Vec<VendorRequest>> {
        let entity = require_entity(Self::NAME, payload, &MESSAGE_PUSH_ENTITIES)?;
        let ts = require_remote_id(Self::NAME, payload)?;
        let channel = body_str(&payload.body, "channel")
            .or_else(|| settings.get_str("channel").map(str::to_string))
            .ok_or_else(|| {
                DomainError::Validation(
                    "slack：消息回写需要频道（payload.body.channel 或设置项 channel），否则不知道要改哪条消息"
                        .to_string(),
                )
            })?;
        let (path, body) = match entity {
            "message.revoke" => ("chat.delete", json!({ "channel": channel, "ts": ts })),
            _ => {
                let text = body_str(&payload.body, "text").ok_or_else(|| {
                    DomainError::Validation("slack：message.update 必须在 payload.body.text 给出新正文".to_string())
                })?;
                let mut body = json!({ "channel": channel, "ts": ts, "text": text });
                if let Some(blocks) = payload.body.get("blocks").filter(|v| !v.is_null()) {
                    if let Some(object) = body.as_object_mut() {
                        object.insert("blocks".to_string(), blocks.clone());
                    }
                }
                ("chat.update", body)
            }
        };
        let token = settings.secret_raw("bot_token").map(str::trim).filter(|v| !v.is_empty()).ok_or_else(|| {
            DomainError::Config(
                "slack：消息回写需要凭据 bot_token（Slack Web API `xoxb-` 令牌）；\
                 仅 Incoming Webhook 无法更新/撤回消息（send 主路径不受影响）"
                    .to_string(),
            )
        })?;
        let endpoint = format!("{}/api/{path}", Self::api_base(settings)?);
        Ok(vec![
            VendorRequest::post(endpoint, "application/json", body)
                .with_header("Authorization", format!("Bearer {token}"))
                .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, push_idempotency_key(Self::NAME, payload)),
        ])
    }

    /// 解析 Web API 回写响应：`{"ok":true,...}` / `{"ok":false,"error":"..."}`。
    ///
    /// # Errors
    /// `ok` 非 `true` 或响应体非 JSON 时返回 `DomainError::Validation`（业务错误，不重试）。
    pub(crate) fn parse_push_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        let value: Value = serde_json::from_str(body).map_err(|e| {
            DomainError::Validation(format!("slack 回写响应不是合法 JSON: {e}；{}", crate::http::snippet(body)))
        })?;
        match value.get("ok").and_then(Value::as_bool) {
            Some(true) => Ok(value.get("ts").and_then(Value::as_str).map(str::to_string)),
            Some(false) => {
                let error = value.get("error").and_then(Value::as_str).unwrap_or("unknown_error");
                Err(DomainError::Validation(format!("slack 回写被上游拒绝: {error}")))
            }
            None => Err(DomainError::Validation(format!(
                "slack 回写响应缺少 ok 字段（无法确认结果）: {}",
                crate::http::snippet(body)
            ))),
        }
    }
}
