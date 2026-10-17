//! 原始日志回放：用**当前**解析器注册表重新解析历史原始日志，并与既有事件做差分（§4.5）。
//!
//! ## 为什么需要回放
//!
//! 1. **模板补录**：某厂商日志先到、模板后到（`parsed=false` 的原始日志留在保真层）；
//! 2. **规则/模板升级**：新模板上线后，历史数据的归一化视图可能变化，需要量化影响面；
//! 3. **取证复现**：脱敏后的事件副本不足以定案时，由具备权限的运维从 `raw_logs` 复现原文。
//!
//! ## 语义约定
//!
//! - 回放**不修改也不删除**既有事件（事件表按 `(tenant,time,id)` 追加）；新解析结果作为
//!   **新事件**写入，差分行记录在 [`ReplayReport::diffs`] 中供人工确认；
//! - `mark_parsed=true`（默认）时把原始日志标记为已解析，避免被反复回放；
//! - 仍无法解析的原始日志保持 `parsed=false`，并在 [`ReplayReport::failures`] 中给出原因。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::event::Event;
use agf_core::ids::{Id, TenantId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::bus::EventBus;
use crate::normalize::{self, SourceMeta};
use crate::pipeline::{Sink, decode_payload};
use crate::registry::ParserRegistry;

mod diff;
mod plan;

#[cfg(test)]
mod tests;

pub use diff::*;
pub use plan::*;
