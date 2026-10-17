//! 内置厂商模板目录（§4.5 解析：内置 100+ 模板；本 crate 提供 19 个**带真实/合成样本**的开箱即用模板）。
//!
//! ## 样本与 `SOURCES.md`
//!
//! 每个模板的 `sample_fixture` 指向仓库 `tests/fixtures/logs/` 下的样本文件；
//! [`FIXTURE_DIR_REL`] 与 `SOURCES.md` 记录了每个样本的**来源 URL 与获取日期**，
//! 无法联网核实的一律标注 `synthetic=true`（合成样本，格式忠于厂商公开文档）。
//! `manifest.json` 是模板 key → 样本文件的机器可读映射，供测试自动遍历。
//!
//! ## 模板选取原则
//!
//! 1. **一类设备一个模板**，不追求数量堆砌；`vendor`/`product`/`protocols` 用于消歧；
//! 2. `mapping` 只做"原始字段 → ECS 路径"，不做业务判定（判定在规则引擎）；
//! 3. CEF/LEEF 的 `sev` 由引擎直接换算等级，模板只需补 `cat` → 类别的映射；
//! 4. 未映射字段不会被丢弃，会进入 `Event::extra`。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agf_core::enums::{IngestProtocol, Severity};
use agf_core::error::{DomainError, DomainResult};
use agf_core::parser::{FieldMapping, ParserDefinition, ParserEngine};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod builder;
mod builtin_a;
mod builtin_b;
mod builtin_c;
mod builtin_d;
mod fixtures;

#[cfg(test)]
mod tests;

pub use builder::*;
pub use fixtures::*;

/// 内置模板目录（19 个厂商/产品，覆盖 8 类解析引擎）。
///
/// 调用方通常不需要直接用本函数，走 [`crate::registry::ParserRegistry::with_builtins`] 即可。
///
/// 目录本体按段落拆在 `builtin_a`..`builtin_d` 四个子模块，这里只负责**依原顺序**拼接；
/// 返回值与拆分前的单一长函数逐字一致。
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn builtin_templates() -> Vec<ParserDefinition> {
    let mut out = Vec::new();
    builtin_a::push_builtin_a(&mut out);
    builtin_b::push_builtin_b(&mut out);
    builtin_c::push_builtin_c(&mut out);
    builtin_d::push_builtin_d(&mut out);
    out
}

/// 按 `(vendor, product, protocol)` 查找内置模板（空字符串表示"不限"）。
#[must_use]
pub fn lookup(vendor: &str, product: &str, protocol: Option<IngestProtocol>) -> Vec<ParserDefinition> {
    builtin_templates()
        .into_iter()
        .filter(|d| vendor.is_empty() || d.vendor.contains(vendor))
        .filter(|d| product.is_empty() || d.product.contains(product))
        .filter(|d| protocol.is_none_or(|p| d.protocols.contains(&p)))
        .collect()
}

/// 按 key 查找内置模板。
#[must_use]
pub fn find(key: &str) -> Option<ParserDefinition> {
    builtin_templates().into_iter().find(|d| d.key == key)
}

/// 内置模板数量（用于文档与看板展示）。
#[must_use]
pub fn builtin_count() -> usize {
    builtin_templates().len()
}
