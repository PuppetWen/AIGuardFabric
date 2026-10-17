//! 解析器注册表：内置模板 + YAML 目录加载 + 优先级匹配 + 统计（§4.5 解析）。
//!
//! ## 匹配顺序（`match_raw` / `match_raw_with_mode`）
//!
//! 1. **显式指定**：日志源配置的 `parser_id`（或 `parser_key`）优先，命中即用
//!    （不受协议白名单约束）→ [`MatchMode::Explicit`]；
//! 2. **严格趟**：按 `(priority 升序, 内置优先, key)` 排序逐个尝试，模板声明的
//!    `protocols` **必须**包含当前协议（`protocols` 为空的模板视为"不限协议"，与旧行为一致）
//!    → [`MatchMode::Protocol`]；
//! 3. **放宽趟**（**仅当严格趟零命中**）：**忽略协议白名单**，只补试"显式声明了协议但不含当前
//!    协议"的模板（`protocols` 为空者已在严格趟试过，不重复解析），顺序与严格趟完全一致，
//!    `required_fields` 校验**照常生效**（缺字段的载荷依旧不接受）→ [`MatchMode::ProtocolRelaxed`]。
//!    存在的理由：模板库对 `mqtt`/`otlp`/`jdbc`/`pulsar`/`snmp-trap` 等新接入协议**缺少声明**，
//!    载荷字段明明对得上却因白名单被跳过；放宽趟把这类载荷救回来，并**如实标注**趟次；
//! 4. **样本打分**：用 [`crate::engine::sample_match_score`] 对候选打分，取最高分且
//!    超过 [`crate::engine::MATCH_THRESHOLD`] 者（本就不做协议过滤与厂商过滤）
//!    → [`MatchMode::SampleScore`]；打分的**必需字段口径与 `parse_with` 完全一致**
//!    （映射前扁平字段名，见 `engine::required_fields_satisfied`）——修复前打分用映射后的
//!    字段名查 `required_fields`，带 `required_fields` 的模板被腰斩成 `base * 0.5`
//!    （上限 0.495 < 阈值）⇒ 本趟对它们**恒不命中**；
//!    本趟与放宽趟共用**格式自证**闸门（[`format_plausible`]），否则打分之下的
//!    `Csv` 模板会把 JSON 载荷按逗号切开凑出必需字段，造成高分假命中；
//! 5. **AI 推断兜底**（可选开启）→ [`MatchMode::AiInferred`]；
//! 6. 全部失败 → 返回 `matched=false` 的 [`ParseOutcome`]，由上层决定是否触发 AI 推断。
//!
//! 放宽趟的命中次数在 [`RegistryStats::matched_relaxed`] / [`RegistryStats::relaxed_hits`]
//! 与流水线统计里**分项暴露**，绝不与严格趟混在一起统计——"命中率变高"必须能解释成
//! "哪些模板、因为什么被放宽命中"。
//!
//! 模板加载期会依次执行 `ParserDefinition::validate()` 与
//! [`crate::engine::validate_pattern`]（Grok/正则真正编译一次），**加载失败的模板不进入
//! 匹配集**并计入 [`RegistryStats::invalid`] —— 坏模板绝不影响其他模板工作。

use std::collections::BTreeMap;
use std::path::Path;

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::Id;
use agf_core::parser::{AiParserSuggestion, ParseOutcome, Parser, ParserDefinition, ParserEngine};
use agf_core::secret::content_hash;
use agf_core::time::Timestamp;
use tracing::{debug, warn};

use crate::engine::{self, MATCH_THRESHOLD};
use crate::normalize::parser_id_for;
use crate::template;

mod catalog;
mod matcher;
mod template_file;
mod types;

#[cfg(test)]
mod tests;

// `matcher` 子模块只提供 `impl ParserRegistry` 块（无常量/类型可重导出）⇒ 无需 glob 重导出
pub use template_file::*;
pub use types::*;
