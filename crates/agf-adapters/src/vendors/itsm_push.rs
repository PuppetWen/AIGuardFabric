//! 工单类（Jira / ServiceNow / 禅道）的**状态回写**编码：一厂商一段，全是纯函数。
//!
//! 回写实体与载荷契约（与 `send` 的分工见 [`crate::contract::semantics`]）：
//!
//! | 厂商 | 实体 | 载荷字段 | 真实请求 |
//! |---|---|---|---|
//! | `jira` | `ticket.status` / `ticket.update` / `ticket.comment` | `transition_id`（工作流推进）、`comment` | `PUT /rest/api/2/issue/{key}/transitions` + `POST /rest/api/2/issue/{key}/comment` |
//! | `servicenow` | `ticket.status` / `ticket.update` / `ticket.comment` | `state`、`work_notes`（或 `comment`） | `PATCH /api/now/table/{table}/{sys_id}` |
//! | `zentao` | `ticket.status` / `ticket.update` / `ticket.comment` | `status`、`comment` | `PUT /api.php/v1/bugs/{id}` |
//!
//! **多请求序列**：Jira 的"状态推进 + 评论"是一次回写两次调用，按固定顺序
//! （先状态、后评论）执行，末次响应用于提取回执 id——这是
//! [`crate::vendor::VendorSpec::encode_push`] 返回 `Vec<VendorRequest>` 的原因。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | `entity_id` 为空 | `Validation`：回写必须指向已存在对象（用 `send` 回执的 `remote_id`），**不建连** |
//! | 实体名不在上表 | `Validation`（列出支持项），不构造任何请求 |
//! | 载荷无 `comment` 也无状态字段 | `Validation`：回写载荷为空等于没回写，**不发空包** |
//! | 缺 base_url/凭据 | `Config`（列出缺项），不建连 |

use agf_core::adapter::PushPayload;
use agf_core::error::{DomainError, DomainResult};
use serde_json::json;

use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec as _;

use super::body_str;
use super::jira::Jira;
use super::push_idempotency_key;
use super::require_entity;
use super::require_remote_id;
use super::require_safe_id;
use super::servicenow::ServiceNow;
use super::zentao::Zentao;

/// 工单类支持的回写实体（三厂商一致，便于上层按统一实体派发）。
pub const TICKET_PUSH_ENTITIES: [&str; 3] = ["ticket.status", "ticket.update", "ticket.comment"];

impl Jira {
    /// Jira 评论接口（REST v2）。
    #[must_use]
    pub fn comment_endpoint(base_url: &str, key: &str) -> String {
        format!("{}/rest/api/2/issue/{key}/comment", base_url.trim_end_matches('/'))
    }

    /// Jira 工作流推进接口（REST v2）。
    #[must_use]
    pub fn transitions_endpoint(base_url: &str, key: &str) -> String {
        format!("{}/rest/api/2/issue/{key}/transitions", base_url.trim_end_matches('/'))
    }

    /// 编码回写请求序列（纯函数）。
    ///
    /// # Errors
    /// 实体名不支持、`entity_id` 缺失/非法、载荷无回写字段、缺 base_url/凭据时返回错误。
    pub(crate) fn encode_push_requests(
        payload: &PushPayload,
        settings: &AdapterSettings,
    ) -> DomainResult<Vec<VendorRequest>> {
        let entity = require_entity(Self::NAME, payload, &TICKET_PUSH_ENTITIES)?;
        let raw_key = require_remote_id(Self::NAME, payload)?;
        let key = require_safe_id(Self::NAME, &raw_key, "issue key")?;
        let base_url = crate::vendors::require_setting(settings, "base_url")?;
        let email = crate::vendors::require_secret(settings, "user_email")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let idempotency = push_idempotency_key(Self::NAME, payload);

        let transition = body_str(&payload.body, "transition_id");
        let comment = body_str(&payload.body, "comment").or_else(|| body_str(&payload.body, "work_notes"));
        if entity == "ticket.comment" && comment.is_none() {
            return Err(DomainError::Validation(
                "jira：ticket.comment 回写必须在 payload.body.comment 提供评论正文".to_string(),
            ));
        }
        let mut requests = Vec::new();
        if let Some(transition_id) = transition {
            requests.push(
                VendorRequest::channel(
                    "PUT",
                    Self::transitions_endpoint(&base_url, &key),
                    json!({"transition": {"id": transition_id}}),
                )
                .with_header("Authorization", Self::basic_auth(&email, &token))
                .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, idempotency.clone()),
            );
        }
        if let Some(comment) = comment {
            requests.push(
                VendorRequest::post(
                    Self::comment_endpoint(&base_url, &key),
                    "application/json",
                    json!({"body": comment}),
                )
                .with_header("Authorization", Self::basic_auth(&email, &token))
                .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, idempotency),
            );
        }
        if requests.is_empty() {
            return Err(DomainError::Validation(
                "jira：回写载荷必须提供 payload.body.comment（评论）或 payload.body.transition_id（工作流状态推进），\
                 否则等同于没有回写"
                    .to_string(),
            ));
        }
        Ok(requests)
    }

    /// 解析回写响应：评论返回 `{"id":"10001"}`；工作流推进返回 `204` 空体。
    ///
    /// # Errors
    /// 响应体含 `errors`/`errorMessages` 时返回 `DomainError::Validation`（上游拒绝，不重试）。
    pub(crate) fn parse_push_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        if body.trim().is_empty() {
            return Ok(None);
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
            let messages = value.get("errorMessages").and_then(serde_json::Value::as_array).map_or(0, Vec::len);
            let errors = value.get("errors").and_then(serde_json::Value::as_object).map_or(0, serde_json::Map::len);
            if messages > 0 || errors > 0 {
                return Err(DomainError::Validation(format!("jira 回写被上游拒绝: {}", crate::http::snippet(body))));
            }
        }
        Ok(crate::http::extract_id(body, &["id", "key"]))
    }
}

impl ServiceNow {
    /// 单条记录接口（Table API）。
    #[must_use]
    pub fn record_endpoint(instance_url: &str, table: &str, sys_id: &str) -> String {
        format!("{}/{sys_id}", Self::table_endpoint(instance_url, table))
    }

    /// 编码回写请求（Table API `PATCH`，纯函数）。
    ///
    /// # Errors
    /// 实体名不支持、`entity_id`（`sys_id`）缺失/非法、载荷无回写字段、缺 instance_url/凭据时返回错误。
    pub(crate) fn encode_push_requests(
        payload: &PushPayload,
        settings: &AdapterSettings,
    ) -> DomainResult<Vec<VendorRequest>> {
        let _ = require_entity(Self::NAME, payload, &TICKET_PUSH_ENTITIES)?;
        let raw_id = require_remote_id(Self::NAME, payload)?;
        if !is_sys_id(&raw_id) {
            return Err(DomainError::Validation(format!(
                "servicenow：回写必须使用 sys_id（32 位十六进制），收到 {raw_id:?}；\
                 单号（如 INC0010001）不是 Table API 的定位键，请先用 pull 以 sysparm_query=number=<单号> 换取 sys_id"
            )));
        }
        let sys_id = require_safe_id(Self::NAME, &raw_id, "sys_id")?;
        let instance = crate::vendors::require_setting(settings, "instance_url")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let table = Self::table(settings);
        let idempotency = push_idempotency_key(Self::NAME, payload);

        let mut body = serde_json::Map::new();
        if let Some(state) = body_str(&payload.body, "state") {
            body.insert("state".to_string(), json!(state));
        }
        if let Some(notes) = body_str(&payload.body, "work_notes").or_else(|| body_str(&payload.body, "comment")) {
            body.insert("work_notes".to_string(), json!(notes));
        }
        if body.is_empty() {
            return Err(DomainError::Validation(
                "servicenow：回写载荷必须提供 payload.body.state 或 work_notes/comment，否则等同于没有回写".to_string(),
            ));
        }
        Ok(vec![
            VendorRequest::channel(
                "PATCH",
                Self::record_endpoint(&instance, &table, &sys_id),
                serde_json::Value::Object(body),
            )
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("Accept", "application/json")
            .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, idempotency),
        ])
    }

    /// 解析回写响应：`{"result":{"sys_id":"...","number":"..."}}`。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 `result` 时返回 `DomainError::Validation`。
    pub(crate) fn parse_push_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        if body.trim().is_empty() {
            return Ok(None);
        }
        let id = crate::http::extract_id(body, &["result.sys_id", "result.number", "sys_id"]);
        if id.is_none() {
            return Err(DomainError::Validation(format!(
                "servicenow 回写响应缺少 result.sys_id: {}",
                crate::http::snippet(body)
            )));
        }
        Ok(id)
    }
}

/// ServiceNow `sys_id` 形态（32 位十六进制）。
#[must_use]
pub fn is_sys_id(value: &str) -> bool {
    value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit())
}

impl Zentao {
    /// 单条缺陷接口（禅道 REST v1）。
    #[must_use]
    pub fn bug_record_endpoint(base_url: &str, id: &str) -> String {
        format!("{}/{id}", Self::bug_endpoint(base_url))
    }

    /// 编码回写请求（`PUT /api.php/v1/bugs/{id}`，纯函数）。
    ///
    /// # Errors
    /// 实体名不支持、`entity_id` 缺失/非法、载荷无回写字段、缺 base_url/凭据时返回错误。
    pub(crate) fn encode_push_requests(
        payload: &PushPayload,
        settings: &AdapterSettings,
    ) -> DomainResult<Vec<VendorRequest>> {
        let _ = require_entity(Self::NAME, payload, &TICKET_PUSH_ENTITIES)?;
        let raw_id = require_remote_id(Self::NAME, payload)?;
        let id = require_safe_id(Self::NAME, &raw_id, "bug id")?;
        let base_url = crate::vendors::require_setting(settings, "base_url")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let idempotency = push_idempotency_key(Self::NAME, payload);

        let mut body = serde_json::Map::new();
        if let Some(status) = body_str(&payload.body, "status") {
            body.insert("status".to_string(), json!(status));
        }
        if let Some(comment) = body_str(&payload.body, "comment") {
            body.insert("comment".to_string(), json!(comment));
        }
        if body.is_empty() {
            return Err(DomainError::Validation(
                "zentao：回写载荷必须提供 payload.body.status 或 payload.body.comment，否则等同于没有回写".to_string(),
            ));
        }
        Ok(vec![
            VendorRequest::channel("PUT", Self::bug_record_endpoint(&base_url, &id), serde_json::Value::Object(body))
                .with_header("Token", token)
                .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, idempotency),
        ])
    }

    /// 解析回写响应：禅道返回更新后的 `{"id":123,...}`。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 `id` 时返回 `DomainError::Validation`。
    pub(crate) fn parse_push_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        if body.trim().is_empty() {
            return Ok(None);
        }
        let id = crate::http::extract_id(body, &["id", "data.id", "bug.id"]);
        if id.is_none() {
            return Err(DomainError::Validation(format!(
                "zentao 回写响应缺少 id 字段: {}",
                crate::http::snippet(body)
            )));
        }
        Ok(id)
    }
}
