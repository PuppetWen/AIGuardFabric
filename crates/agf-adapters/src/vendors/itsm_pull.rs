//! 工单类（Jira / ServiceNow / 禅道）的**增量拉取**编码与解析：一厂商一段，全是纯函数。
//!
//! ## 增量口径（`cursor` = `since`）
//!
//! | 厂商 | 请求 | 增量参数 | 游标推进 |
//! |---|---|---|---|
//! | `jira` | `GET /rest/api/2/search` | JQL `updated >= "<cursor>"` | 上游不给游标 ⇒ 取本页最大 `updated`（[`crate::vendor::IncrementalWindow`]） |
//! | `servicenow` | `GET /api/now/table/{table}` | `sysparm_query=sys_updated_on>=<cursor>^ORDERBYsys_updated_on` | 同上（取最大 `sys_updated_on`） |
//! | `zentao` | `GET /api.php/v1/bugs?product=<id>` | REST v1 无 `since` 参数 ⇒ **客户端过滤**（[`crate::vendor::filter_since`]） | 同上 |
//!
//! 归一化字段（`agf_remote_id` / `agf_updated_at` / `agf_state`）见
//! [`crate::contract::sync_types`]；`agf_state` 只放**可回写的状态子集**，
//! 因此它天然与 `push` 的 `body` 同键可比（`sync` 的比对与冲突裁决据此成立）。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 资源名不在白名单 | `Validation`（列出支持项），**不发请求** |
//! | 缺 base_url/instance_url/product_id/凭据 | `Config`（列出缺项），不建连 |
//! | 上游返回 4xx | `Validation`/`Forbidden`/`Unauthenticated`，**不重试** |
//! | 条目缺 id / 响应结构不符 | `Validation`（不猜、不静默丢弃） |

use agf_core::adapter::PullRequest;
use agf_core::error::{DomainError, DomainResult};
use agf_core::time::Timestamp;
use serde_json::{Value, json};

use crate::contract::PullPage;
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec as _;
use crate::vendor::filter_since;

use super::jira::Jira;
use super::pull_limit;
use super::pull_resource;
use super::servicenow::ServiceNow;
use super::with_query;
use super::zentao::Zentao;

/// 默认单页条目数。
pub const DEFAULT_PULL_LIMIT: u32 = 50;

/// 单页条目数上限。
pub const MAX_PULL_LIMIT: u32 = 200;

/// Jira 支持的拉取资源。
pub const JIRA_PULL_RESOURCES: [&str; 2] = ["issues", "ticket"];

/// ServiceNow 默认拉取资源（表名）。
pub const SERVICENOW_PULL_RESOURCES: [&str; 3] = ["incident", "ticket", "records"];

/// 禅道支持的拉取资源。
pub const ZENTAO_PULL_RESOURCES: [&str; 2] = ["bugs", "bug"];

impl Jira {
    /// 搜索接口（REST v2）。
    #[must_use]
    pub fn search_endpoint(base_url: &str) -> String {
        format!("{}/rest/api/2/search", base_url.trim_end_matches('/'))
    }

    /// 增量拉取的 JQL（纯函数，可离线断言）。
    #[must_use]
    pub fn pull_jql(project_key: &str, cursor: Option<&str>, extra: Option<&str>) -> String {
        let mut jql = format!("project = \"{project_key}\"");
        if let Some(since) = cursor.map(str::trim).filter(|c| !c.is_empty()) {
            jql.push_str(&format!(" AND updated >= \"{since}\""));
        }
        if let Some(extra) = extra.map(str::trim).filter(|c| !c.is_empty()) {
            jql.push_str(&format!(" AND ({extra})"));
        }
        jql.push_str(" ORDER BY updated ASC");
        jql
    }

    /// 编码增量拉取请求（纯函数）。
    ///
    /// # Errors
    /// 资源名不支持、缺 base_url/project_key/凭据、URL 非法时返回错误。
    pub(crate) fn encode_pull_request(req: &PullRequest, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        pull_resource(Self::NAME, req, &JIRA_PULL_RESOURCES, "issues")?;
        let base_url = crate::vendors::require_setting(settings, "base_url")?;
        let project_key = crate::vendors::require_setting(settings, "project_key")?;
        let email = crate::vendors::require_secret(settings, "user_email")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let limit = pull_limit(req, DEFAULT_PULL_LIMIT, MAX_PULL_LIMIT);
        let jql = Self::pull_jql(&project_key, req.cursor.as_deref(), req.filter.get("jql").map(String::as_str));
        let endpoint = with_query(
            &Self::search_endpoint(&base_url),
            &[
                ("jql", jql),
                ("maxResults", limit.to_string()),
                ("fields", "summary,status,updated,labels,priority".to_string()),
            ],
        )?;
        Ok(VendorRequest::channel("GET", endpoint, Value::Null)
            .with_header("Authorization", Self::basic_auth(&email, &token))
            .with_header("Accept", "application/json"))
    }

    /// 解析搜索响应（纯函数）。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 `issues` 数组时返回 `DomainError::Validation`。
    pub(crate) fn parse_pull(_status: u16, body: &str, _req: &PullRequest) -> DomainResult<PullPage> {
        let value: Value = serde_json::from_str(body).map_err(|e| {
            DomainError::Validation(format!("jira 拉取响应不是合法 JSON: {e}；{}", crate::http::snippet(body)))
        })?;
        let issues = value.get("issues").and_then(Value::as_array).ok_or_else(|| {
            DomainError::Validation(format!("jira 拉取响应缺少 issues 数组: {}", crate::http::snippet(body)))
        })?;
        let mut items = Vec::with_capacity(issues.len());
        for issue in issues {
            let key = issue.get("key").and_then(Value::as_str).unwrap_or_default().trim();
            if key.is_empty() {
                return Err(DomainError::Validation(format!(
                    "jira 拉取条目缺少 key（无法作为远端对象 id）: {}",
                    crate::http::snippet(&issue.to_string())
                )));
            }
            let fields = issue.get("fields");
            let updated =
                fields.and_then(|f| f.get("updated")).and_then(Value::as_str).and_then(parse_flexible_datetime);
            let status = fields
                .and_then(|f| f.get("status"))
                .and_then(|s| s.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            // state 只放可回写子集（与 push 的 body 同键），sync 的比对才有意义
            let state = json!({ "status": status });
            let updated_text = updated.map(|stamp| stamp.to_rfc3339());
            items.push(PullPage::normalize_item(issue.clone(), key, updated_text.as_deref(), &state));
        }
        Ok(PullPage::new(items))
    }
}

impl ServiceNow {
    /// 表查询接口（Table API，无 `sys_id`）。
    #[must_use]
    pub fn query_endpoint(instance_url: &str, table: &str) -> String {
        Self::table_endpoint(instance_url, table)
    }

    /// 增量查询条件（`sysparm_query`；`sys_updated_on` 用实例的显示格式）。
    #[must_use]
    pub fn pull_query(cursor: Option<&str>) -> String {
        match cursor.and_then(parse_sysparm_datetime) {
            Some(since) => format!("sys_updated_on>={}^ORDERBYsys_updated_on", format_sysparm_datetime(since)),
            None => "ORDERBYsys_updated_on".to_string(),
        }
    }

    /// 编码增量拉取请求（纯函数）。
    ///
    /// # Errors
    /// 资源名不支持、缺 instance_url/凭据、URL 非法时返回错误。
    pub(crate) fn encode_pull_request(req: &PullRequest, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let resource = pull_resource(Self::NAME, req, &SERVICENOW_PULL_RESOURCES, "incident")?;
        let instance = crate::vendors::require_setting(settings, "instance_url")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let table = if resource == "records" { Self::table(settings) } else { resource.to_string() };
        let limit = pull_limit(req, DEFAULT_PULL_LIMIT, MAX_PULL_LIMIT);
        let endpoint = with_query(
            &Self::query_endpoint(&instance, &table),
            &[
                ("sysparm_query", Self::pull_query(req.cursor.as_deref())),
                ("sysparm_limit", limit.to_string()),
                ("sysparm_fields", "sys_id,number,state,sys_updated_on,short_description".to_string()),
            ],
        )?;
        Ok(VendorRequest::channel("GET", endpoint, Value::Null)
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("Accept", "application/json"))
    }

    /// 解析表查询响应（纯函数）。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 `result` 数组时返回 `DomainError::Validation`。
    pub(crate) fn parse_pull(_status: u16, body: &str, _req: &PullRequest) -> DomainResult<PullPage> {
        let value: Value = serde_json::from_str(body).map_err(|e| {
            DomainError::Validation(format!("servicenow 拉取响应不是合法 JSON: {e}；{}", crate::http::snippet(body)))
        })?;
        let records = value.get("result").and_then(Value::as_array).ok_or_else(|| {
            DomainError::Validation(format!("servicenow 拉取响应缺少 result 数组: {}", crate::http::snippet(body)))
        })?;
        let mut items = Vec::with_capacity(records.len());
        for record in records {
            let sys_id = record.get("sys_id").and_then(Value::as_str).unwrap_or_default().trim();
            if sys_id.is_empty() {
                return Err(DomainError::Validation(format!(
                    "servicenow 拉取条目缺少 sys_id: {}",
                    crate::http::snippet(&record.to_string())
                )));
            }
            let updated = record.get("sys_updated_on").and_then(Value::as_str).and_then(parse_sysparm_datetime);
            let state = record.get("state").and_then(Value::as_str).unwrap_or_default();
            let normalized = json!({ "state": state });
            let updated_text = updated.map(|stamp| stamp.to_rfc3339());
            items.push(PullPage::normalize_item(record.clone(), sys_id, updated_text.as_deref(), &normalized));
        }
        Ok(PullPage::new(items))
    }
}

impl Zentao {
    /// 增量拉取请求（禅道 REST v1 无 `since` 参数 ⇒ 只按产品 + 上限取页，增量在客户端过滤）。
    ///
    /// # Errors
    /// 资源名不支持、缺 base_url/product_id/凭据、URL 非法时返回错误。
    pub(crate) fn encode_pull_request(req: &PullRequest, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        pull_resource(Self::NAME, req, &ZENTAO_PULL_RESOURCES, "bugs")?;
        let base_url = crate::vendors::require_setting(settings, "base_url")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let product_id = settings
            .settings
            .get("product_id")
            .and_then(Value::as_u64)
            .ok_or_else(|| DomainError::Config("禅道 product_id 未配置或非数字".to_string()))?;
        let limit = pull_limit(req, DEFAULT_PULL_LIMIT, MAX_PULL_LIMIT);
        let endpoint = with_query(
            &Self::bug_endpoint(&base_url),
            &[("product", product_id.to_string()), ("limit", limit.to_string())],
        )?;
        Ok(VendorRequest::channel("GET", endpoint, Value::Null)
            .with_header("Token", token)
            .with_header("Accept", "application/json"))
    }

    /// 解析缺陷列表响应并按 `cursor` 做**客户端增量过滤**（纯函数）。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 `bugs` 数组时返回 `DomainError::Validation`。
    pub(crate) fn parse_pull(_status: u16, body: &str, req: &PullRequest) -> DomainResult<PullPage> {
        let value: Value = serde_json::from_str(body).map_err(|e| {
            DomainError::Validation(format!("zentao 拉取响应不是合法 JSON: {e}；{}", crate::http::snippet(body)))
        })?;
        let bugs = value.get("bugs").and_then(Value::as_array).ok_or_else(|| {
            DomainError::Validation(format!("zentao 拉取响应缺少 bugs 数组: {}", crate::http::snippet(body)))
        })?;
        let mut items = Vec::with_capacity(bugs.len());
        for bug in bugs {
            let id = crate::http::extract_id(&bug.to_string(), &["id", "bug.id"]).ok_or_else(|| {
                DomainError::Validation(format!("zentao 拉取条目缺少 id: {}", crate::http::snippet(&bug.to_string())))
            })?;
            let updated = bug
                .get("lastEditedDate")
                .or_else(|| bug.get("openedDate"))
                .and_then(Value::as_str)
                .and_then(parse_flexible_datetime);
            let status = bug.get("status").and_then(Value::as_str).unwrap_or_default();
            let state = json!({ "status": status });
            let updated_text = updated.map(|stamp| stamp.to_rfc3339());
            items.push(PullPage::normalize_item(bug.clone(), &id, updated_text.as_deref(), &state));
        }
        // REST v1 没有 since 参数：客户端过滤（无时间戳条目保留，不漏数据；重复交给增量窗口）
        Ok(PullPage::new(filter_since(&items, req.cursor.as_deref())))
    }
}

/// 解析 ServiceNow 的 `sys_updated_on`（`YYYY-MM-DD HH:MM:SS`，UTC；同时容忍 RFC3339）。
#[must_use]
pub fn parse_sysparm_datetime(value: &str) -> Option<Timestamp> {
    let trimmed = value.trim();
    if let Ok(stamp) = Timestamp::parse_rfc3339(trimmed) {
        return Some(stamp);
    }
    let naive = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S").ok()?;
    Some(Timestamp::from_datetime(chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc)))
}

/// 格式化为 ServiceNow 查询串接受的 `YYYY-MM-DD HH:MM:SS`（UTC）。
#[must_use]
pub fn format_sysparm_datetime(stamp: Timestamp) -> String {
    stamp.as_datetime().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// 宽容解析工单系统时间戳（RFC3339 / `YYYY-MM-DD HH:MM:SS` / `YYYY-MM-DD`）。
#[must_use]
pub fn parse_flexible_datetime(value: &str) -> Option<Timestamp> {
    let trimmed = value.trim();
    if let Ok(stamp) = Timestamp::parse_rfc3339(trimmed) {
        return Some(stamp);
    }
    if let Some(stamp) = parse_sysparm_datetime(trimmed) {
        return Some(stamp);
    }
    let date = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d").ok()?;
    let naive = date.and_hms_opt(0, 0, 0)?;
    Some(Timestamp::from_datetime(chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc)))
}
