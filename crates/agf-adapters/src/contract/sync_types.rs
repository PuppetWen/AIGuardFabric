//! `push` / `pull` / `sync` 的**数据形态**：拉取页、回写回执、本地快照与同步请求。
//!
//! ## 归一化字段（跨厂商对账的关键）
//!
//! 各厂商的工单/主机 JSON 字段名各不相同（`key` / `sys_id` / `id`，`updated` / `sys_updated_on` /
//! `lastEditedDate`）。为了让 `sync` 的"比对 + 冲突裁决"**不写成三套**，每个厂商的
//! `parse_pull` 在保留原始字段的同时注入三个 AGF 规范字段：
//!
//! | 字段 | 含义 |
//! |---|---|
//! | [`ITEM_REMOTE_ID`] | 远端对象 id（与 `send` 回执的 `remote_id` 同源，`push` 用它定位对象） |
//! | [`ITEM_UPDATED_AT`] | 远端最后更新时间（RFC3339；上游没给就不注入） |
//! | [`ITEM_STATE`] | 回写相关状态（`push` 的 `body` 同形态，可直接比对与回写） |
//!
//! ## 本地快照的来源
//!
//! `agf_core::adapter::Adapter::sync(direction, req)` 只提供一个 [`PullRequest`]，因此
//! [`SyncRequest::from_pull_request`] 把 `req.filter` 里以 `local.` 开头的条目解析为本地快照：
//!
//! ```text
//! filter["local.SEC-7"] = {"updated_at":"2026-02-01T10:00:00Z","state":{"status":"In Progress"}}
//! filter["local.SEC-8"] = {"status":"Done"}      // 只给 state 也接受（无时间戳 ⇒ 由策略裁决）
//! ```
//!
//! 其余 filter 条目按"厂商过滤条件"透传（[`SyncRequest::filter_value`]）。

use std::collections::BTreeMap;

use agf_core::adapter::PullRequest;
use agf_core::error::{DomainError, DomainResult};
use agf_core::time::Timestamp;
use serde_json::Value;

use crate::contract::ConflictPolicy;

/// 规范化：远端对象 id。
pub const ITEM_REMOTE_ID: &str = "agf_remote_id";

/// 规范化：远端最后更新时间（RFC3339）。
pub const ITEM_UPDATED_AT: &str = "agf_updated_at";

/// 规范化：回写相关状态。
pub const ITEM_STATE: &str = "agf_state";

/// 本地快照在 `PullRequest::filter` 中的键前缀。
pub const LOCAL_FILTER_PREFIX: &str = "local.";

/// 拉取到的一页条目（[`crate::vendor::VendorSpec::parse_pull`] 的产物）。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PullPage {
    /// 条目（含规范化字段，见模块文档）。
    pub items: Vec<Value>,
    /// 下一页游标（上游未提供时为 `None`，由调用方决定是否继续）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl PullPage {
    /// 空页。
    #[must_use]
    pub const fn empty() -> Self {
        Self { items: Vec::new(), next_cursor: None }
    }

    /// 由条目构造（无游标）。
    #[must_use]
    pub const fn new(items: Vec<Value>) -> Self {
        Self { items, next_cursor: None }
    }

    /// 由条目 + 游标构造。
    #[must_use]
    pub fn with_cursor(items: Vec<Value>, next_cursor: Option<String>) -> Self {
        Self { items, next_cursor }
    }

    /// 条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// 是否为空页。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// 注入规范化字段并构造条目（保留上游原始字段）。
    #[must_use]
    pub fn normalize_item(raw: Value, remote_id: &str, updated_at: Option<&str>, state: &Value) -> Value {
        let mut item = match raw {
            Value::Object(map) => map,
            other => {
                let mut map = serde_json::Map::new();
                map.insert("raw".to_string(), other);
                map
            }
        };
        item.insert(ITEM_REMOTE_ID.to_string(), Value::String(remote_id.to_string()));
        if let Some(updated_at) = updated_at {
            item.insert(ITEM_UPDATED_AT.to_string(), Value::String(updated_at.to_string()));
        }
        item.insert(ITEM_STATE.to_string(), state.clone());
        Value::Object(item)
    }
}

/// 条目的规范化远端 id。
#[must_use]
pub fn item_remote_id(item: &Value) -> Option<String> {
    item.get(ITEM_REMOTE_ID)
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| crate::http::extract_id(&item.to_string(), &["id", "key", "number", "sys_id"]))
}

/// 条目的规范化更新时间。
#[must_use]
pub fn item_updated_at(item: &Value) -> Option<Timestamp> {
    item.get(ITEM_UPDATED_AT).and_then(Value::as_str).and_then(|text| Timestamp::parse_rfc3339(text).ok())
}

/// 条目的规范化状态（缺失时退回整个条目，保证比对仍有意义）。
#[must_use]
pub fn item_state(item: &Value) -> Value {
    match item.get(ITEM_STATE) {
        Some(state) if !state.is_null() => state.clone(),
        _ => item.clone(),
    }
}

/// 条目的去重键（规范化 id 优先；缺 id 时用内容哈希，保证同一内容恒等）。
#[must_use]
pub fn item_key(item: &Value) -> String {
    if let Some(id) = item_remote_id(item) {
        return id;
    }
    crate::transport::deterministic_token("agf-pull-item", &item.to_string())
}

/// 回写回执（[`crate::contract::VendorAdapter::push`] 的产物）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PushOutcome {
    /// 实际发出的请求数（Jira 的"状态 + 评论"回写是多请求序列；Mock 下为 0）。
    pub requests: usize,
    /// 上游返回的对象/评论 id（上游未返回时为 `None`，如实登记）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,
    /// 是否 Mock（零网络）。
    #[serde(default)]
    pub mocked: bool,
    /// 实际尝试次数（含首次；>1 说明发生了重试）。
    pub attempts: u32,
    /// 耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 排障用来源（已脱敏 endpoint / `mock://<name>`）。
    pub origin: String,
    /// 完成时间。
    pub delivered_at: Timestamp,
}

impl PushOutcome {
    /// 真实回执。
    #[must_use]
    pub fn new(requests: usize, remote_id: Option<String>, attempts: u32, elapsed_ms: u64, origin: String) -> Self {
        Self { requests, remote_id, mocked: false, attempts, elapsed_ms, origin, delivered_at: Timestamp::now() }
    }

    /// Mock 回执（确定性，零网络）。
    #[must_use]
    pub fn mocked(adapter: &str, remote_id: String) -> Self {
        Self {
            requests: 0,
            remote_id: Some(remote_id),
            mocked: true,
            attempts: 1,
            elapsed_ms: 0,
            origin: format!("mock://{adapter}"),
            delivered_at: Timestamp::now(),
        }
    }
}

/// 本地快照（`sync` 对账的"本地一侧"）。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LocalSnapshot {
    /// 远端对象 id（与 `send` 回执的 `remote_id` 同源）。
    pub remote_id: String,
    /// 本地最后更新时间（缺省表示本地无法提供时间戳 ⇒ 由冲突策略裁决）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Timestamp>,
    /// 本地状态（与 [`ITEM_STATE`] 同形态，可直接作为 `push` 的 `body`）。
    pub state: Value,
}

impl LocalSnapshot {
    /// 由远端 id + 状态构造（无时间戳）。
    #[must_use]
    pub fn new(remote_id: impl Into<String>, state: Value) -> Self {
        Self { remote_id: remote_id.into(), updated_at: None, state }
    }

    /// 追加本地更新时间（链式）。
    #[must_use]
    pub fn with_updated_at(mut self, updated_at: Timestamp) -> Self {
        self.updated_at = Some(updated_at);
        self
    }

    /// 从 `PullRequest::filter` 的值文本解析。
    ///
    /// 接受两种形态：`{"updated_at":"<rfc3339>","state":{...}}` 与裸状态 `{...}`。
    ///
    /// # Errors
    /// 值不是合法 JSON 时返回 `DomainError::Validation`（提示调用方给出合法快照）。
    pub fn parse_filter_value(remote_id: &str, raw: &str) -> DomainResult<Self> {
        let value: Value = serde_json::from_str(raw).map_err(|e| {
            DomainError::Validation(format!(
                "sync 本地快照 {LOCAL_FILTER_PREFIX}{remote_id} 不是合法 JSON: {e}（期望 {{\"updated_at\":..,\"state\":..}} 或裸状态对象）"
            ))
        })?;
        let updated_at =
            value.get("updated_at").and_then(Value::as_str).and_then(|text| Timestamp::parse_rfc3339(text).ok());
        let state = value.get("state").cloned().unwrap_or_else(|| value.clone());
        Ok(Self { remote_id: remote_id.to_string(), updated_at, state })
    }
}

/// 同步请求（[`crate::contract::VendorAdapter::sync`] 的入参）。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SyncRequest {
    /// 资源类型（`issues` / `incident` / `bugs` / `hosts` / `events`）。
    pub resource: String,
    /// 增量游标（空表示首轮全量）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// 单页上限。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// 本地快照（对账的本地一侧）。
    #[serde(default)]
    pub local: Vec<LocalSnapshot>,
    /// 冲突策略覆盖（`None` ⇒ 用设置项 [`crate::contract::SETTING_CONFLICT_POLICY`]，默认外部优先）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict_policy: Option<ConflictPolicy>,
    /// 透传的厂商过滤条件（`PullRequest::filter` 中非 `local.` 前缀的条目）。
    #[serde(default)]
    pub filters: BTreeMap<String, String>,
}

impl SyncRequest {
    /// 由资源类型构造。
    #[must_use]
    pub fn new(resource: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            cursor: None,
            limit: None,
            local: Vec::new(),
            conflict_policy: None,
            filters: BTreeMap::new(),
        }
    }

    /// 设置增量游标（链式）。
    #[must_use]
    pub fn with_cursor(mut self, cursor: Option<String>) -> Self {
        self.cursor = cursor;
        self
    }

    /// 设置单页上限（链式）。
    #[must_use]
    pub fn with_limit(mut self, limit: Option<u32>) -> Self {
        self.limit = limit;
        self
    }

    /// 追加本地快照（链式）。
    #[must_use]
    pub fn with_local(mut self, local: Vec<LocalSnapshot>) -> Self {
        self.local = local;
        self
    }

    /// 覆盖冲突策略（链式）。
    #[must_use]
    pub fn with_conflict_policy(mut self, policy: ConflictPolicy) -> Self {
        self.conflict_policy = Some(policy);
        self
    }

    /// 读取透传过滤条件。
    #[must_use]
    pub fn filter_value(&self, key: &str) -> Option<&str> {
        self.filters.get(key).map(String::as_str)
    }

    /// 本地快照中是否存在该远端 id。
    #[must_use]
    pub fn local_snapshot(&self, remote_id: &str) -> Option<&LocalSnapshot> {
        self.local.iter().find(|snapshot| snapshot.remote_id == remote_id)
    }

    /// 由 `agf_core` 的 [`PullRequest`] 桥接（解析 `local.` 前缀的本地快照）。
    ///
    /// # Errors
    /// `local.<id>` 的值不是合法 JSON 时返回 `DomainError::Validation`。
    pub fn from_pull_request(req: &PullRequest) -> DomainResult<Self> {
        let mut local = Vec::new();
        let mut filters = BTreeMap::new();
        for (key, value) in &req.filter {
            match key.strip_prefix(LOCAL_FILTER_PREFIX) {
                Some(remote_id) if !remote_id.is_empty() => {
                    local.push(LocalSnapshot::parse_filter_value(remote_id, value)?);
                }
                _ => {
                    filters.insert(key.clone(), value.clone());
                }
            }
        }
        Ok(Self {
            resource: req.resource.clone(),
            cursor: req.cursor.clone(),
            limit: req.limit,
            local,
            conflict_policy: None,
            filters,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalized_item_keeps_vendor_fields_and_injects_agf_fields() {
        let item = PullPage::normalize_item(
            json!({"key": "SEC-7", "fields": {"summary": "x"}}),
            "SEC-7",
            Some("2026-02-01T10:00:00+00:00"),
            &json!({"status": "In Progress"}),
        );
        assert_eq!(item["key"], "SEC-7", "上游原始字段必须保留");
        assert_eq!(item_remote_id(&item).as_deref(), Some("SEC-7"));
        assert_eq!(item_updated_at(&item).map(|t| t.to_rfc3339()).as_deref(), Some("2026-02-01T10:00:00.000Z"));
        assert_eq!(item_state(&item), json!({"status": "In Progress"}));
        assert_eq!(item_key(&item), "SEC-7");
    }

    #[test]
    fn item_helpers_tolerate_missing_normalized_fields() {
        let bare = json!({"id": 42, "summary": "x"});
        assert_eq!(item_remote_id(&bare).as_deref(), Some("42"), "无规范化字段时回退到原始 id");
        assert!(item_updated_at(&bare).is_none());
        assert_eq!(item_state(&bare), bare, "无规范化状态时退回整个条目");
        let anonymous = json!({"nope": 1});
        assert_eq!(item_key(&anonymous), item_key(&anonymous), "无 id 时用内容哈希，必须确定性");
        assert_ne!(item_key(&anonymous), item_key(&json!({"nope": 2})));
        // 非对象条目也能归一化（不 panic）
        let scalar = PullPage::normalize_item(json!("plain"), "x-1", None, &Value::Null);
        assert_eq!(item_remote_id(&scalar).as_deref(), Some("x-1"));
    }

    #[test]
    fn local_snapshot_accepts_two_shapes() {
        let wrapped = LocalSnapshot::parse_filter_value(
            "SEC-7",
            r#"{"updated_at":"2026-02-01T10:00:00Z","state":{"status":"Done"}}"#,
        )
        .expect("合法快照");
        assert_eq!(wrapped.remote_id, "SEC-7");
        assert!(wrapped.updated_at.is_some());
        assert_eq!(wrapped.state, json!({"status": "Done"}));

        let bare = LocalSnapshot::parse_filter_value("SEC-8", r#"{"status":"Done"}"#).expect("裸状态也接受");
        assert!(bare.updated_at.is_none());
        assert_eq!(bare.state, json!({"status": "Done"}));

        let bad = LocalSnapshot::parse_filter_value("SEC-9", "not json");
        assert!(matches!(bad, Err(DomainError::Validation(_))));
    }

    #[test]
    fn sync_request_bridges_pull_request_filters() {
        let mut filter = BTreeMap::new();
        filter.insert("status".to_string(), "open".to_string());
        filter.insert("local.SEC-7".to_string(), r#"{"status":"Done"}"#.to_string());
        filter.insert(
            "local.SEC-8".to_string(),
            r#"{"updated_at":"2026-01-01T00:00:00Z","state":{"status":"New"}}"#.to_string(),
        );
        let req = PullRequest {
            resource: "issues".to_string(),
            filter,
            cursor: Some("2026-01-01T00:00:00Z".to_string()),
            limit: Some(50),
        };
        let sync = SyncRequest::from_pull_request(&req).expect("合法桥接");
        assert_eq!(sync.resource, "issues");
        assert_eq!(sync.cursor.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(sync.limit, Some(50));
        assert_eq!(sync.local.len(), 2, "local. 前缀条目必须解成本地快照");
        assert_eq!(sync.filter_value("status"), Some("open"), "非 local. 条目按厂商过滤条件透传");
        assert!(sync.local_snapshot("SEC-7").is_some());
        assert!(sync.conflict_policy.is_none(), "未显式指定时由设置项决定");

        let empty_local = SyncRequest::from_pull_request(&PullRequest {
            resource: "issues".to_string(),
            filter: BTreeMap::new(),
            ..PullRequest::default()
        })
        .expect("空过滤条件");
        assert!(empty_local.local.is_empty());
    }

    #[test]
    fn sync_request_bridge_rejects_bad_snapshot_json() {
        let mut filter = BTreeMap::new();
        filter.insert("local.SEC-7".to_string(), "{oops".to_string());
        let error = SyncRequest::from_pull_request(&PullRequest {
            resource: "issues".to_string(),
            filter,
            ..PullRequest::default()
        })
        .expect_err("非法快照必须报错");
        assert!(error.to_string().contains("SEC-7"), "{error}");
    }

    #[test]
    fn builders_and_serde_roundtrip() {
        let request = SyncRequest::new("bugs")
            .with_cursor(Some("2026-01-01T00:00:00Z".to_string()))
            .with_limit(Some(20))
            .with_local(vec![LocalSnapshot::new("7", json!({"status": "closed"}))])
            .with_conflict_policy(ConflictPolicy::LocalWins);
        assert_eq!(request.conflict_policy, Some(ConflictPolicy::LocalWins));
        let json_text = serde_json::to_string(&request).unwrap_or_default();
        let back: Option<SyncRequest> = serde_json::from_str(&json_text).ok();
        assert_eq!(back, Some(request));

        let outcome = PushOutcome::new(2, Some("10001".to_string()), 1, 12, "https://jira.example.invalid".to_string());
        assert_eq!(outcome.requests, 2);
        let round = serde_json::to_string(&outcome).unwrap_or_default();
        assert_eq!(serde_json::from_str::<Option<PushOutcome>>(&round).ok().flatten().map(|o| o.requests), Some(2));

        assert!(PullPage::empty().is_empty());
        assert_eq!(PullPage::with_cursor(vec![json!({"id": 1})], Some("c1".to_string())).len(), 1);
    }
}
