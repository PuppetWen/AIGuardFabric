//! 解析引擎（§4.5 解析：内置模板 + Grok/JSONPath/JQ/自定义插件 + AI 推断）。
//!
//! 把 [`ParserDefinition`] 变成可执行的解析器，输出 [`ParseOutcome`]。
//!
//! ## 关键约定（模板作者必读）
//!
//! 1. **引擎负责把厂商标准键改写为 AGF-ECS 路径**。例如 CEF 的 `src` 直接产出
//!    `source.ip`、`cat` 产出 `event.category_raw`；这样 `required_fields`
//!    与 `mapping` 都按"引擎输出后的字段名"书写。
//! 2. `JsonPath` 引擎的 `pattern` 是**逐行 `字段名=$.路径`** 的规格表
//!    （也兼容单行裸路径，此时按路径末段命名并把对象扁平化）。
//! 3. 所有行式引擎在解析前先剥离**可选的 syslog 信封**
//!    （`<PRI>Mmm dd HH:MM:SS host app[pid]: `），信封字段并入结果
//!    （`host.name` / `process.name` / `process.pid` / `event.time`）。
//! 4. `FieldMapping` 里的 `severity_field` / `action_field` / `time_field` 写的是
//!    **源字段名**（如 `risk`、`act`、`eventtime`），与 `event.*` 无关；
//!    `category_map` 依次按 `event.category_raw` → `rule.id` → 动作原值 查找，
//!    但 `defaults` 中显式声明的 `event.category` 优先级更高（模板作者意图优先）。
//!
//! ## 支持的引擎与实现方式
//!
//! | 引擎 | 实现 | 离线可用 |
//! |---|---|---|
//! | `Grok` | `%{PATTERN:name}` 展开为命名捕获正则（内置常用 pattern 表） | ✅ |
//! | `Regex` | 直接编译正则 + 命名捕获组（无命名组时退化为 `g1..gn`） | ✅ |
//! | `JsonPath` | `jsonpath-rust` + `字段=$.路径` 规格表 | ✅ |
//! | `Jq` | `jaq-core` + `jaq-std`（纯 Rust JQ，不依赖外部 `jq`） | ✅ |
//! | `Syslog` | [`crate::syslog`] 的 RFC3164/5424 解析器 | ✅ |
//! | `Cef` / `Leef` / `Gelf` | 行内头解析 + 标准键改写（CEF 处理 `\|` 逃逸） | ✅ |
//! | `Csv` / `Kv` | 分隔符自动识别 + 表头映射 / 键值对 | ✅ |
//! | `Cel` | **已实现（派生字段）** → 模板 `derived` 段用 `cel-interpreter` 求值（见 [`crate::cel`]）；非独立抽取引擎 | ✅ |
//! | `Plugin` | **已实现** → 运行时加载 `.dll`/`.so`/`.dylib`（[`agf_plugin`] 的版本化 C ABI）+ 可配超时；见 [`plugin`] | ✅（需插件目录）
//! | `AiInferred` | 由 [`crate::ai_parser`] 生成定义后按载荷形态分派执行 | ✅（离线启发式） |
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | Grok 中出现未知 pattern | 退化为 `\S+` 并记 debug 日志（不让单个未知 pattern 废掉整条模板） |
//! | 主模式未匹配 | 依次尝试 `fallback_patterns`，全部失败返回 `ParseOutcome::miss` |
//! | `required_fields` 未满足 | 视为不匹配（用于多模板消歧）；判定与**样本打分**共用同一口径：**映射前**的扁平字段名（见 [`required_fields_satisfied`]） |
//! | Plugin 引擎规格非法 | `validate_pattern` 拒绝（坏模板不进入匹配集） |
//! | Plugin 运行时未装载 / 插件名不存在 / 调用失败 / 超时 / 返回非法 JSON | **不 panic、不静默丢弃**：该模板不命中（原始日志照常落库），失败按五类计数并落诊断（见 [`plugin`]） |
//! | CEL 派生表达式失败 | 不中断解析，记入 `derived_errors`，对应目标字段不写值 |
//! | JSONPath 路径不存在 | 该字段跳过（不报错）；全部路径都空才算不匹配 |
//! | 时间字段无法识别 | 不写 `event.time`（由上游补接收时间），不报错 |
//! | RFC3164 时间戳无年份 | 按接入年份补全（syslog 协议本身的限制） |

use std::collections::BTreeMap;
use std::sync::OnceLock;

use agf_core::enums::{IngestProtocol, Severity};
use agf_core::error::DomainError;
use agf_core::parser::{FieldMapping, ParseOutcome, ParserDefinition, ParserEngine};
use agf_core::time::Timestamp;
use regex::Regex;
use serde_json::Value;
use tracing::debug;

mod cef_leef;
mod gelf_kv;
mod jsonpath;
mod pattern;
pub mod plugin;
mod support;
mod syslog_envelope;
mod time_mapping;

#[cfg(test)]
mod tests;

pub use cef_leef::*;
pub use gelf_kv::*;
// `jsonpath` 子模块只有 crate 内部可见的项（无 `pub` 项）⇒ 私有 glob 引入即可，避免"重导出为空"告警
use jsonpath::*;
pub use pattern::*;
pub use support::*;
pub use syslog_envelope::*;
pub use time_mapping::*;
