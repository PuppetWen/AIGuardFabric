//! 列表查询的统一解析：分页 / 排序 / 过滤 / 字段裁剪（§8 API 约定）。
//!
//! 为什么不用 `axum::extract::Query`：本项目需要"未声明的 query 参数一律当作过滤器"，
//! 而 `serde_urlencoded` 对 `#[serde(flatten)]` + `BTreeMap` 的支持不可靠。这里直接用
//! `url::form_urlencoded` 手工解析，行为完全确定，也便于对边界值做归一化。

use std::collections::BTreeMap;

use agf_core::error::{DomainError, DomainResult};
use agf_core::pagination::{MAX_PAGE_SIZE, Page, PageRequest, SortDirection};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::Serialize;
use serde_json::Value;

use crate::error::ApiError;

/// 保留参数（不作为过滤条件）。
const RESERVED: [&str; 5] = ["page", "page_size", "sort", "fields", "q"];

/// 归一化后的列表查询。
#[derive(Debug, Clone)]
pub struct ListQuery {
    /// 页码（≥1）。
    pub page: u32,
    /// 每页条数（1..=200）。
    pub page_size: u32,
    /// 排序字段（白名单由各路由自行判断，未识别则忽略）。
    pub sort_by: Option<String>,
    /// 排序方向。
    pub sort_dir: SortDirection,
    /// 字段裁剪白名单（空 = 全字段）。
    pub fields: Vec<String>,
    /// 模糊搜索关键字。
    pub q: Option<String>,
    /// 其余参数一律视为过滤条件（字段 → 值，多值用逗号分隔）。
    pub filters: BTreeMap<String, String>,
}

impl Default for ListQuery {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: agf_core::pagination::DEFAULT_PAGE_SIZE,
            sort_by: None,
            sort_dir: SortDirection::Desc,
            fields: Vec::new(),
            q: None,
            filters: BTreeMap::new(),
        }
    }
}

impl ListQuery {
    /// 由原始 query 串解析（非法数值回退默认值并归一化，不报错）。
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        let mut out = Self::default();
        let Some(raw) = raw else { return out };
        for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            let key = key.into_owned();
            let value = value.into_owned();
            match key.as_str() {
                "page" => out.page = value.parse().unwrap_or(1),
                "page_size" => out.page_size = value.parse().unwrap_or(agf_core::pagination::DEFAULT_PAGE_SIZE),
                "sort" => {
                    // 支持 `-created_at`（降序）与 `created_at`（升序）
                    if let Some(rest) = value.strip_prefix('-') {
                        out.sort_by = Some(rest.to_string());
                        out.sort_dir = SortDirection::Desc;
                    } else if let Some(rest) = value.strip_prefix('+') {
                        out.sort_by = Some(rest.to_string());
                        out.sort_dir = SortDirection::Asc;
                    } else {
                        out.sort_by = Some(value.clone());
                        out.sort_dir = SortDirection::Asc;
                    }
                }
                "fields" => {
                    out.fields =
                        value.split(',').map(str::trim).filter(|s| !s.is_empty()).map(ToString::to_string).collect();
                }
                "q" => {
                    if !value.is_empty() {
                        out.q = Some(value);
                    }
                }
                other => {
                    if !RESERVED.contains(&other) && !value.is_empty() {
                        out.filters.insert(other.to_string(), value);
                    }
                }
            }
        }
        out.page = out.page.max(1);
        out.page_size = out.page_size.clamp(1, MAX_PAGE_SIZE);
        out
    }

    /// 转 [`PageRequest`]。
    #[must_use]
    pub fn to_page_request(&self) -> PageRequest {
        PageRequest {
            page: self.page,
            page_size: self.page_size,
            sort_by: self.sort_by.clone(),
            sort_dir: self.sort_dir,
            q: self.q.clone(),
        }
    }

    /// 单值过滤条件。
    #[must_use]
    pub fn filter(&self, key: &str) -> Option<&str> {
        self.filters.get(key).map(String::as_str)
    }

    /// 逗号分隔的多值过滤条件。
    #[must_use]
    pub fn filter_many(&self, key: &str) -> Vec<String> {
        self.filter(key)
            .map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(ToString::to_string).collect())
            .unwrap_or_default()
    }

    /// 整数过滤条件（非法值返回校验错误，避免静默忽略用户的过滤意图）。
    ///
    /// # Errors
    /// 值不是整数。
    pub fn filter_i64(&self, key: &str) -> DomainResult<Option<i64>> {
        match self.filter(key) {
            None => Ok(None),
            Some(raw) => raw
                .parse::<i64>()
                .map(Some)
                .map_err(|_| DomainError::Validation(format!("查询参数 {key} 必须是整数，收到 {raw}"))),
        }
    }

    /// 布尔过滤条件。
    ///
    /// # Errors
    /// 值不是布尔字面量。
    pub fn filter_bool(&self, key: &str) -> DomainResult<Option<bool>> {
        match self.filter(key) {
            None => Ok(None),
            Some(raw) => match raw.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" => Ok(Some(true)),
                "0" | "false" | "no" => Ok(Some(false)),
                other => Err(DomainError::Validation(format!("查询参数 {key} 必须是布尔值，收到 {other}"))),
            },
        }
    }

    /// 排序方向是否降序。
    #[must_use]
    pub const fn descending(&self) -> bool {
        matches!(self.sort_dir, SortDirection::Desc)
    }

    /// 按 `fields` 裁剪 JSON 对象（未指定则原样返回）。
    #[must_use]
    pub fn project(&self, value: &Value) -> Value {
        if self.fields.is_empty() {
            return value.clone();
        }
        match value {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for key in &self.fields {
                    if let Some(v) = map.get(key) {
                        out.insert(key.clone(), v.clone());
                    }
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }

    /// 用 `fields` 裁剪任意可序列化值。
    ///
    /// # Errors
    /// 序列化失败（理论不会发生）。
    pub fn project_value<T: Serialize>(&self, value: &T) -> DomainResult<Value> {
        let json = serde_json::to_value(value)?;
        Ok(self.project(&json))
    }

    /// 构造标准列表响应体：`{ items, total, page, page_size, has_more }`。
    ///
    /// # Errors
    /// 序列化失败。
    pub fn render_page<T: Serialize>(&self, page: &Page<T>) -> DomainResult<Value> {
        let mut items = Vec::with_capacity(page.items.len());
        for item in &page.items {
            items.push(self.project_value(item)?);
        }
        Ok(serde_json::json!({
            "items": items,
            "total": page.total.unwrap_or(0),
            "page": page.page,
            "page_size": page.page_size,
            "has_more": page.has_more(),
            "next_cursor": page.next_cursor,
        }))
    }

    /// 在内存列表上执行过滤/排序/分页（离线后端统一走这里，保证与 SQL 语义一致）。
    ///
    /// `search` 返回该元素的全文检索文本；`sort_key` 返回排序键。
    pub fn paginate_vec<T: Clone, S, K>(&self, items: &[T], search: S, sort_key: K) -> Page<T>
    where
        S: Fn(&T) -> String,
        K: Fn(&T) -> String,
    {
        let mut filtered: Vec<T> = items
            .iter()
            .filter(|item| match &self.q {
                Some(needle) => search(item).to_lowercase().contains(&needle.to_lowercase()),
                None => true,
            })
            .cloned()
            .collect();
        if self.sort_by.is_some() {
            filtered.sort_by(|a, b| {
                let ka = sort_key(a);
                let kb = sort_key(b);
                if self.descending() { kb.cmp(&ka) } else { ka.cmp(&kb) }
            });
        }
        let total = i64::try_from(filtered.len()).unwrap_or(i64::MAX);
        let offset = usize::try_from(self.to_page_request().offset()).unwrap_or(0);
        let limit = usize::try_from(self.to_page_request().limit()).unwrap_or(usize::MAX);
        let items = filtered.into_iter().skip(offset).take(limit).collect();
        Page::new(items, total, &self.to_page_request())
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ListQuery {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::parse(parts.uri.query()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaults_and_normalization() {
        let q = ListQuery::parse(None);
        assert_eq!(q.page, 1);
        assert_eq!(q.page_size, agf_core::pagination::DEFAULT_PAGE_SIZE);
        assert!(q.filters.is_empty());

        let q2 = ListQuery::parse(Some("page=0&page_size=100000"));
        assert_eq!(q2.page, 1, "页码至少为 1");
        assert_eq!(q2.page_size, MAX_PAGE_SIZE, "页大小必须夹到上限");
        assert_eq!(q2.to_page_request().limit(), i64::from(MAX_PAGE_SIZE));

        let q3 = ListQuery::parse(Some("page_size=0"));
        assert_eq!(q3.page_size, 1, "页大小至少为 1");
    }

    #[test]
    fn parse_sort_and_filters_and_fields() {
        let q = ListQuery::parse(Some("sort=-created_at&severity=high,critical&fields=id,title&q=abc&page=2"));
        assert_eq!(q.sort_by.as_deref(), Some("created_at"));
        assert!(q.descending());
        assert_eq!(q.filter_many("severity"), vec!["high".to_string(), "critical".to_string()]);
        assert_eq!(q.fields, vec!["id".to_string(), "title".to_string()]);
        assert_eq!(q.q.as_deref(), Some("abc"));
        assert_eq!(q.page, 2);
        assert_eq!(q.to_page_request().offset(), 20);

        let asc = ListQuery::parse(Some("sort=name"));
        assert!(!asc.descending());
    }

    #[test]
    fn filter_typed_parsing_reports_errors() {
        let q = ListQuery::parse(Some("min_exposure=70&enabled=true"));
        assert_eq!(q.filter_i64("min_exposure").ok().flatten(), Some(70));
        assert_eq!(q.filter_bool("enabled").ok().flatten(), Some(true));
        let bad = ListQuery::parse(Some("min_exposure=lots"));
        assert!(bad.filter_i64("min_exposure").is_err());
    }

    #[test]
    fn projection_trims_fields() {
        let q = ListQuery::parse(Some("fields=id,name"));
        let value = serde_json::json!({"id": "1", "name": "n", "secret": "x"});
        let projected = q.project(&value);
        assert_eq!(projected.get("secret"), None);
        assert_eq!(projected.get("name"), Some(&serde_json::json!("n")));
        let all = ListQuery::parse(None).project(&value);
        assert!(all.get("secret").is_some());
    }

    #[test]
    fn paginate_vec_applies_search_and_window() {
        let q = ListQuery::parse(Some("page=2&page_size=2&q=rt"));
        let items = vec!["rt-1".to_string(), "rt-2".to_string(), "rt-3".to_string(), "other".to_string()];
        let page = q.paginate_vec(&items, Clone::clone, Clone::clone);
        assert_eq!(page.total, Some(3));
        assert_eq!(page.items, vec!["rt-3".to_string()]);
    }
}
