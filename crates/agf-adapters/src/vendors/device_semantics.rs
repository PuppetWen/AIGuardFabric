//! 设备类（EDR）的**状态回写**与**增量拉取**：AGF 与 EDR 网关的接口约定，纯函数。
//!
//! 与 [`crate::vendors::edr`] 的隔离指令（`POST /v1/hosts/{host}/isolate`）保持同一套约定：
//! 同一个 `endpoint` 设置项、同一个 `Authorization: Bearer <api_token>`、
//! 同一个 `X-AGF-EDR-Vendor` 头，以及**同样的 dry-run 保护**（默认 `dry_run=true`）。
//!
//! | 语义 | 请求 |
//! |---|---|
//! | `push`（`host.isolation`） | `PATCH {endpoint}/v1/hosts/{host}/isolation`，体含 `action`（`isolate`/`release`）/`reason`/`case_id`/`dry_run` |
//! | `pull`（`hosts`） | `GET {endpoint}/v1/hosts?updated_since=<cursor>&limit=N` |
//! | `pull`（`events`） | `GET {endpoint}/v1/events?since=<cursor>&limit=N` |
//!
//! ## 状态归一化（`sync` 对账的前提）
//!
//! 主机条目的 `agf_state` 只放**与 `push` 同键**的可回写子集：`{"action": "isolate"|"release"}`，
//! 由 EDR 侧的 `isolation_state` 推导（`isolated`/`isolating` ⇒ `isolate`，其余 ⇒ `release`）。
//! 因此"本地期望隔离、EDR 上仍未隔离"会被如实识别为差异，并按冲突策略裁决。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 资源名不在白名单 | `Validation`（列出支持项），不发请求 |
//! | `entity_id`（主机）缺失/非法 | `Validation`：绝不对模糊目标下发处置动作 |
//! | `action` 非 `isolate`/`release` | `Validation`（不猜动作） |
//! | 缺 endpoint/凭据 | `Config`（列出缺项），不建连 |
//! | `dry_run=true`（默认） | 请求照发但携带 dry-run 标记（由 EDR 侧解释为"预演不落地"） |

use agf_core::adapter::PullRequest;
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json};

use crate::contract::PullPage;
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec as _;

use super::body_str;
use super::edr::EdrIsolation;
use super::pull_limit;
use super::pull_resource;
use super::push_idempotency_key;
use super::require_entity;
use super::require_remote_id;
use super::require_safe_id;
use super::with_query;

/// 支持回写的实体。
pub const EDR_PUSH_ENTITIES: [&str; 2] = ["host.isolation", "host.status"];

/// 支持的拉取资源。
pub const EDR_PULL_RESOURCES: [&str; 2] = ["hosts", "events"];

/// 默认单页条目数。
pub const EDR_DEFAULT_LIMIT: u32 = 50;

/// 单页条目数上限。
pub const EDR_MAX_LIMIT: u32 = 200;

/// 处置动作（与隔离指令同一词表）。
pub const ACTION_RELEASE: &str = "release";

impl EdrIsolation {
    /// 主机隔离状态回写接口。
    #[must_use]
    pub fn isolation_endpoint(endpoint: &str, host: &str) -> String {
        format!("{}/v1/hosts/{host}/isolation", endpoint.trim_end_matches('/'))
    }

    /// 主机清单接口。
    #[must_use]
    pub fn hosts_endpoint(endpoint: &str) -> String {
        format!("{}/v1/hosts", endpoint.trim_end_matches('/'))
    }

    /// 设备事件接口。
    #[must_use]
    pub fn events_endpoint(endpoint: &str) -> String {
        format!("{}/v1/events", endpoint.trim_end_matches('/'))
    }

    /// 由 EDR 侧 `isolation_state` 推导处置动作（归一口径见模块文档）。
    #[must_use]
    pub fn action_of_state(isolation_state: &str) -> &'static str {
        match isolation_state.trim().to_ascii_lowercase().as_str() {
            "isolated" | "isolating" | "quarantined" => super::edr::ACTION_ISOLATE,
            _ => ACTION_RELEASE,
        }
    }

    /// 编码状态回写请求（纯函数）。
    ///
    /// # Errors
    /// 实体名不支持、主机缺失/非法、`action` 非法、缺 endpoint/凭据时返回错误。
    pub(crate) fn encode_push_requests(
        payload: &agf_core::adapter::PushPayload,
        settings: &AdapterSettings,
    ) -> DomainResult<Vec<VendorRequest>> {
        require_entity(Self::NAME, payload, &EDR_PUSH_ENTITIES)?;
        let raw_host = require_remote_id(Self::NAME, payload)?;
        let host = require_safe_id(Self::NAME, &raw_host, "host id")?;
        let endpoint = crate::vendors::require_setting(settings, "endpoint")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let dry_run = settings.get_bool("dry_run", true);
        let vendor = settings.get_str("vendor").unwrap_or("generic-edr");
        let action = body_str(&payload.body, "action").ok_or_else(|| {
            DomainError::Validation(
                "edr-isolation：回写必须在 payload.body.action 给出处置动作（isolate/release）".to_string(),
            )
        })?;
        if action != super::edr::ACTION_ISOLATE && action != ACTION_RELEASE {
            return Err(DomainError::Validation(format!(
                "edr-isolation：不支持的回写动作 {action:?}（只接受 isolate / release）"
            )));
        }
        let idempotency = push_idempotency_key(Self::NAME, payload);
        let body = json!({
            "action": action,
            "host_id": host,
            "reason": body_str(&payload.body, "reason").unwrap_or_else(|| "aiguardfabric 状态回写".to_string()),
            "case_id": payload.body.get("case_id").cloned().unwrap_or(Value::Null),
            "requested_by": "aiguardfabric",
            "dry_run": dry_run,
            "idempotency_key": idempotency,
        });
        Ok(vec![
            VendorRequest::channel("PATCH", Self::isolation_endpoint(&endpoint, &host), body)
                .with_header("Authorization", format!("Bearer {token}"))
                .with_header("X-AGF-EDR-Vendor", vendor)
                .with_header("X-AGF-Dry-Run", dry_run.to_string())
                .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, idempotency),
        ])
    }

    /// 编码增量拉取请求（纯函数）。
    ///
    /// # Errors
    /// 资源名不支持、缺 endpoint/凭据、URL 非法时返回错误。
    pub(crate) fn encode_pull_request(req: &PullRequest, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let resource = pull_resource(Self::NAME, req, &EDR_PULL_RESOURCES, "hosts")?;
        let endpoint = crate::vendors::require_setting(settings, "endpoint")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let dry_run = settings.get_bool("dry_run", true);
        let vendor = settings.get_str("vendor").unwrap_or("generic-edr");
        let limit = pull_limit(req, EDR_DEFAULT_LIMIT, EDR_MAX_LIMIT);
        let since_key = if resource == "events" { "since" } else { "updated_since" };
        let cursor = req.cursor.clone().unwrap_or_default();
        let base =
            if resource == "events" { Self::events_endpoint(&endpoint) } else { Self::hosts_endpoint(&endpoint) };
        let url = with_query(&base, &[(since_key, cursor), ("limit", limit.to_string())])?;
        Ok(VendorRequest::channel("GET", url, Value::Null)
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("X-AGF-EDR-Vendor", vendor)
            .with_header("X-AGF-Dry-Run", dry_run.to_string())
            .with_header("Accept", "application/json"))
    }

    /// 解析拉取响应（纯函数）：`hosts` 与 `events` 两种结构。
    ///
    /// # Errors
    /// 响应体非 JSON、缺少对应数组或条目缺少 id 时返回 `DomainError::Validation`。
    pub(crate) fn parse_pull(_status: u16, body: &str, req: &PullRequest) -> DomainResult<PullPage> {
        let resource = pull_resource(Self::NAME, req, &EDR_PULL_RESOURCES, "hosts")?;
        let value: Value = serde_json::from_str(body).map_err(|e| {
            DomainError::Validation(format!("edr-isolation 拉取响应不是合法 JSON: {e}；{}", crate::http::snippet(body)))
        })?;
        let key = if resource == "events" { "events" } else { "hosts" };
        let entries = value.get(key).and_then(Value::as_array).ok_or_else(|| {
            DomainError::Validation(format!("edr-isolation 拉取响应缺少 {key} 数组: {}", crate::http::snippet(body)))
        })?;
        let mut items = Vec::with_capacity(entries.len());
        for entry in entries {
            let id = if resource == "events" {
                entry.get("event_id").and_then(Value::as_str).unwrap_or_default().trim().to_string()
            } else {
                entry.get("host_id").and_then(Value::as_str).unwrap_or_default().trim().to_string()
            };
            if id.is_empty() {
                return Err(DomainError::Validation(format!(
                    "edr-isolation 拉取条目缺少 {}: {}",
                    if resource == "events" { "event_id" } else { "host_id" },
                    crate::http::snippet(&entry.to_string())
                )));
            }
            let updated = entry
                .get("updated_at")
                .or_else(|| entry.get("occurred_at"))
                .and_then(Value::as_str)
                .filter(|text| agf_core::time::Timestamp::parse_rfc3339(text).is_ok());
            let state = if resource == "events" {
                json!({ "event_type": entry.get("event_type").cloned().unwrap_or(Value::Null) })
            } else {
                let isolation = entry.get("isolation_state").and_then(Value::as_str).unwrap_or_default();
                json!({ "action": Self::action_of_state(isolation) })
            };
            items.push(PullPage::normalize_item(entry.clone(), &id, updated, &state));
        }
        let next_cursor = value
            .get("next_cursor")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_string);
        Ok(PullPage::with_cursor(items, next_cursor))
    }

    /// 解析回写响应：`{"host_id":"...","isolation_state":"isolated"}`。
    ///
    /// # Errors
    /// 响应体非 JSON、缺少 `host_id` 或 `isolation_state` 时返回 `DomainError::Validation`。
    pub(crate) fn parse_push_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        if body.trim().is_empty() {
            return Ok(None);
        }
        let value: Value = serde_json::from_str(body).map_err(|e| {
            DomainError::Validation(format!("edr-isolation 回写响应不是合法 JSON: {e}；{}", crate::http::snippet(body)))
        })?;
        let host = value.get("host_id").and_then(Value::as_str).unwrap_or_default().trim();
        let state = value.get("isolation_state").and_then(Value::as_str).unwrap_or_default().trim();
        if host.is_empty() || state.is_empty() {
            return Err(DomainError::Validation(format!(
                "edr-isolation 回写响应缺少 host_id/isolation_state（无法确认处置结果）: {}",
                crate::http::snippet(body)
            )));
        }
        Ok(Some(host.to_string()))
    }
}
