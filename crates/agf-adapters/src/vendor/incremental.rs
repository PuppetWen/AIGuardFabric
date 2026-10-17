//! 增量拉取的去重窗口与游标推进（**纯逻辑，可离线断言**）。
//!
//! `pull` 是增量语义：上游按 `cursor`/`since` 过滤，但分页边界、相等时间戳、
//! 厂商侧"重复返回最后一条"等行为会让同一条目在一次或多次拉取中重复出现。
//! [`IncrementalWindow`] 按 `resource` 维度记录已见条目的去重键
//! （[`crate::contract::item_key`]：规范化 id 优先，无 id 时用内容哈希），
//! 保证"同一个远端对象只交付一次"。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 本地无该资源的历史（首轮） | `seen` 为空 ⇒ 全部条目视为新条目（首轮全量） |
//! | 上游未返回游标（如禅道 REST v1） | 由本页 [`ITEM_UPDATED_AT`](crate::contract::ITEM_UPDATED_AT) 的**最大值**派生下一轮游标 |
//! | 条目不带时间戳 | 不进游标派生；服务端过滤不可用时的客户端过滤**保留**该条目（宁可重复交付，绝不漏数据） |

use std::collections::BTreeSet;

use agf_core::time::Timestamp;
use serde_json::Value;

use crate::contract::{ITEM_UPDATED_AT, PullPage, item_key, item_updated_at};

/// 单资源维度的增量窗口。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncrementalWindow {
    seen: BTreeSet<String>,
    cursor: Option<String>,
    duplicates: usize,
    delivered: usize,
}

impl IncrementalWindow {
    /// 空窗口（首轮全量）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 带游标构造（恢复上一轮位点）。
    #[must_use]
    pub fn with_cursor(cursor: Option<String>) -> Self {
        Self { cursor, ..Self::default() }
    }

    /// 过滤出**尚未交付过**的条目，并把它们记为已见。
    ///
    /// 返回 `(新条目, 本页重复条目数)`；顺序保持上游给出的顺序。
    pub fn accept(&mut self, page: &PullPage) -> (Vec<Value>, usize) {
        let mut fresh = Vec::with_capacity(page.items.len());
        let mut duplicates = 0_usize;
        for item in &page.items {
            let key = item_key(item);
            if self.seen.insert(key) {
                fresh.push(item.clone());
            } else {
                duplicates += 1;
            }
        }
        self.duplicates += duplicates;
        self.delivered += fresh.len();
        (fresh, duplicates)
    }

    /// 推进游标：上游游标优先，其次由本页条目的最大更新时间派生（RFC3339）。
    ///
    /// 返回推进后的游标（未推进时为原值）。
    pub fn advance(&mut self, page: &PullPage, items: &[Value]) -> Option<String> {
        if let Some(cursor) = page.next_cursor.clone().filter(|c| !c.trim().is_empty()) {
            self.cursor = Some(cursor);
            return self.cursor.clone();
        }
        if let Some(max) = max_updated_at(items) {
            self.cursor = Some(max);
        }
        self.cursor.clone()
    }

    /// 直接设置游标。
    pub fn set_cursor(&mut self, cursor: Option<String>) {
        self.cursor = cursor;
    }

    /// 当前游标（下一轮 `PullRequest::cursor` 的来源）。
    #[must_use]
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// 已见条目数（去重表规模）。
    #[must_use]
    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }

    /// 累计交付条数。
    #[must_use]
    pub const fn delivered(&self) -> usize {
        self.delivered
    }

    /// 累计被去重掉的重复条数。
    #[must_use]
    pub const fn duplicates(&self) -> usize {
        self.duplicates
    }

    /// 重置（丢弃去重表与游标）。
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// 一页条目里最大的更新时间（RFC3339 文本）。
#[must_use]
pub fn max_updated_at(items: &[Value]) -> Option<String> {
    items.iter().filter_map(item_updated_at).max().map(|stamp| stamp.to_rfc3339())
}

/// 客户端 `since` 过滤（服务端不支持增量参数时使用，如禅道 REST v1）。
///
/// 规则：条目时间戳 `>= since` 保留；**无时间戳或时间戳不可解析的条目一律保留**
/// （服务端没给过滤能力时，宁可重复交付也不漏数据；重复由 [`IncrementalWindow`] 兜住）。
#[must_use]
pub fn filter_since(items: &[Value], since: Option<&str>) -> Vec<Value> {
    let Some(since) = since.and_then(|text| Timestamp::parse_rfc3339(text).ok()) else {
        return items.to_vec();
    };
    items
        .iter()
        .filter(|item| {
            item.get(ITEM_UPDATED_AT)
                .and_then(Value::as_str)
                .and_then(|text| Timestamp::parse_rfc3339(text).ok())
                .is_none_or(|stamp| stamp >= since)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::PullPage;
    use serde_json::json;

    fn item(id: &str, updated: Option<&str>) -> Value {
        PullPage::normalize_item(json!({"id": id}), id, updated, &json!({"status": "open"}))
    }

    #[test]
    fn window_deduplicates_across_pages() {
        let mut window = IncrementalWindow::new();
        let first = PullPage::with_cursor(
            vec![item("1", Some("2026-01-01T00:00:00+00:00")), item("2", Some("2026-01-02T00:00:00+00:00"))],
            Some("c1".to_string()),
        );
        let (fresh, duplicates) = window.accept(&first);
        assert_eq!(fresh.len(), 2);
        assert_eq!(duplicates, 0);
        assert_eq!(window.advance(&first, &fresh).as_deref(), Some("c1"), "上游游标优先");

        // 第二轮：上游把上一条重复返回（分页边界常见）
        let second = PullPage::new(vec![
            item("2", Some("2026-01-02T00:00:00+00:00")),
            item("3", Some("2026-01-03T00:00:00+00:00")),
        ]);
        let (fresh, duplicates) = window.accept(&second);
        assert_eq!(fresh.len(), 1, "重复条目不得二次交付");
        assert_eq!(fresh[0]["agf_remote_id"], "3");
        assert_eq!(duplicates, 1);
        assert_eq!(window.seen_count(), 3);
        assert_eq!(window.delivered(), 3);
        assert_eq!(window.duplicates(), 1);

        // 上游不给游标 ⇒ 由最大更新时间派生（RFC3339 规范形态）
        assert_eq!(window.advance(&second, &fresh).as_deref(), Some("2026-01-03T00:00:00.000Z"));
        assert_eq!(window.cursor(), Some("2026-01-03T00:00:00.000Z"));
    }

    #[test]
    fn window_uses_content_hash_without_id() {
        let mut window = IncrementalWindow::new();
        let anonymous = PullPage::new(vec![json!({"summary": "same"}), json!({"summary": "same"})]);
        let (fresh, duplicates) = window.accept(&anonymous);
        assert_eq!(fresh.len(), 1, "无 id 时按内容哈希去重");
        assert_eq!(duplicates, 1);
        assert_eq!(window.seen_count(), 1);
    }

    #[test]
    fn window_restores_cursor_and_resets() {
        let mut window = IncrementalWindow::with_cursor(Some("2026-01-01T00:00:00+00:00".to_string()));
        assert_eq!(window.cursor(), Some("2026-01-01T00:00:00+00:00"));
        let empty = PullPage::empty();
        assert_eq!(window.advance(&empty, &[]), Some("2026-01-01T00:00:00+00:00".to_string()), "空页不得清空位点");
        window.set_cursor(None);
        assert!(window.cursor().is_none());
        window.reset();
        assert_eq!(window.seen_count(), 0);
        assert_eq!(window.delivered(), 0);
    }

    #[test]
    fn client_side_since_filter_keeps_unparseable_items() {
        let items = vec![
            item("1", Some("2026-01-01T00:00:00+00:00")),
            item("2", Some("2026-01-05T00:00:00+00:00")),
            json!({"id": "3"}),
        ];
        let kept = filter_since(&items, Some("2026-01-03T00:00:00+00:00"));
        let ids: Vec<String> = kept.iter().map(crate::contract::item_key).collect();
        assert_eq!(ids, vec!["2".to_string(), "3".to_string()], "无时间戳条目必须保留（不漏数据）");
        assert_eq!(filter_since(&items, None).len(), 3, "无 since 即全量");
        assert_eq!(filter_since(&items, Some("not-a-time")).len(), 3, "since 不可解析时不得静默丢数据");
        assert!(filter_since(&items, Some("2027-01-01T00:00:00+00:00")).len() == 1, "仅保留无时间戳条目");
    }

    #[test]
    fn max_updated_at_picks_latest_parseable() {
        let items = vec![item("1", Some("2026-01-01T00:00:00+00:00")), item("2", None), json!({"id": "3"})];
        assert_eq!(max_updated_at(&items).as_deref(), Some("2026-01-01T00:00:00.000Z"));
        assert!(max_updated_at(&[]).is_none());
        assert!(max_updated_at(&[json!({"id": "x", "agf_updated_at": "bad"})]).is_none());
    }
}
