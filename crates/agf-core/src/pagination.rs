//! 分页、过滤与排序通用类型（§8 API 约定）。

use serde::{Deserialize, Serialize};

/// 每页条数上限——防止一次性拉全表。
pub const MAX_PAGE_SIZE: u32 = 200;
/// 默认每页条数。
pub const DEFAULT_PAGE_SIZE: u32 = 20;

/// 排序方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    /// 升序。
    Asc,
    /// 降序（默认）。
    #[default]
    Desc,
}

impl SortDirection {
    /// 转 SQL 关键字。
    #[must_use]
    pub const fn as_sql(&self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

/// 分页 + 排序请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageRequest {
    /// 页码，从 1 开始。
    #[serde(default = "default_page")]
    pub page: u32,
    /// 每页条数，上限 [`MAX_PAGE_SIZE`]。
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// 排序字段（白名单由各仓储校验，避免 SQL 注入）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,
    /// 排序方向。
    #[serde(default)]
    pub sort_dir: SortDirection,
    /// 全文/模糊过滤关键字。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
}

const fn default_page() -> u32 {
    1
}

const fn default_page_size() -> u32 {
    DEFAULT_PAGE_SIZE
}

impl Default for PageRequest {
    fn default() -> Self {
        Self { page: 1, page_size: DEFAULT_PAGE_SIZE, sort_by: None, sort_dir: SortDirection::Desc, q: None }
    }
}

impl PageRequest {
    /// 构造第 1 页请求。
    #[must_use]
    pub fn first(page_size: u32) -> Self {
        Self { page_size, ..Self::default() }
    }

    /// 归一化：页码至少 1，页大小夹在 `1..=MAX_PAGE_SIZE`。
    #[must_use]
    pub fn normalized(&self) -> Self {
        Self {
            page: self.page.max(1),
            page_size: self.page_size.clamp(1, MAX_PAGE_SIZE),
            sort_by: self.sort_by.clone(),
            sort_dir: self.sort_dir,
            q: self.q.clone(),
        }
    }

    /// SQL `LIMIT`。
    #[must_use]
    pub fn limit(&self) -> i64 {
        i64::from(self.normalized().page_size)
    }

    /// SQL `OFFSET`。
    #[must_use]
    pub fn offset(&self) -> i64 {
        let n = self.normalized();
        i64::from(n.page.saturating_sub(1)) * i64::from(n.page_size)
    }
}

/// 分页结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    /// 当前页数据。
    pub items: Vec<T>,
    /// 总条数（未知时可为 `None`，如游标分页）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
    /// 当前页码。
    pub page: u32,
    /// 每页条数。
    pub page_size: u32,
    /// 下一页游标（游标分页使用）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// 由切片构造（`total` 已知）。
    #[must_use]
    pub fn new(items: Vec<T>, total: i64, req: &PageRequest) -> Self {
        let n = req.normalized();
        Self { items, total: Some(total), page: n.page, page_size: n.page_size, next_cursor: None }
    }

    /// 空页。
    #[must_use]
    pub fn empty(req: &PageRequest) -> Self {
        Self::new(Vec::new(), 0, req)
    }

    /// 映射元素类型。
    pub fn map<U, F: FnMut(T) -> U>(self, mut f: F) -> Page<U> {
        Page {
            items: self.items.into_iter().map(&mut f).collect(),
            total: self.total,
            page: self.page,
            page_size: self.page_size,
            next_cursor: self.next_cursor,
        }
    }

    /// 是否还有下一页（依据 total）。
    #[must_use]
    pub fn has_more(&self) -> bool {
        match self.total {
            Some(total) => i64::from(self.page) * i64::from(self.page_size) < total,
            None => self.next_cursor.is_some(),
        }
    }
}

/// 通用列表过滤条件（键值对，仓储层按白名单消费）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Filter {
    /// 过滤项。
    #[serde(default)]
    pub items: Vec<FilterItem>,
}

/// 单条过滤项。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterItem {
    /// 字段名。
    pub field: String,
    /// 操作符。
    pub op: FilterOp,
    /// 值（`In` 时为逗号分隔）。
    pub value: String,
}

/// 过滤操作符。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    /// 等于。
    Eq,
    /// 不等于。
    Ne,
    /// 模糊匹配。
    Like,
    /// 大于。
    Gt,
    /// 大于等于。
    Gte,
    /// 小于。
    Lt,
    /// 小于等于。
    Lte,
    /// 集合包含。
    In,
    /// 是否为空。
    IsNull,
}

impl Filter {
    /// 追加一条过滤项。
    pub fn push(&mut self, field: impl Into<String>, op: FilterOp, value: impl Into<String>) {
        self.items.push(FilterItem { field: field.into(), op, value: value.into() });
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_request_normalizes() {
        let req = PageRequest { page: 0, page_size: 10_000, ..PageRequest::default() };
        let n = req.normalized();
        assert_eq!(n.page, 1);
        assert_eq!(n.page_size, MAX_PAGE_SIZE);
        assert_eq!(n.limit(), i64::from(MAX_PAGE_SIZE));
        assert_eq!(n.offset(), 0);
    }

    #[test]
    fn offset_grows_with_page() {
        let req = PageRequest { page: 3, page_size: 20, ..PageRequest::default() };
        assert_eq!(req.offset(), 40);
    }

    #[test]
    fn page_map_and_has_more() {
        let req = PageRequest::first(2);
        let page = Page::new(vec![1_u32, 2], 5, &req);
        assert!(page.has_more());
        let mapped = page.map(|v| v * 2);
        assert_eq!(mapped.items, vec![2, 4]);
        assert_eq!(mapped.total, Some(5));
    }

    #[test]
    fn empty_page_reports_no_more() {
        let req = PageRequest::default();
        let page: Page<u8> = Page::empty(&req);
        assert!(!page.has_more());
        assert_eq!(page.total, Some(0));
    }

    #[test]
    fn filter_push() {
        let mut f = Filter::default();
        assert!(f.is_empty());
        f.push("severity", FilterOp::In, "high,critical");
        assert!(!f.is_empty());
        assert_eq!(f.items.len(), 1);
    }
}
