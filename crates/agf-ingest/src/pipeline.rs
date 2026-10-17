//! 接入流水线：去重 → 解析 → 归一化 → 脱敏 → 持久化（原始 + 归一）→ 投递总线（§4.5）。
//!
//! ## 处理顺序与理由
//!
//! 1. **报文大小 / EPS 闸门**先于一切：平台自我保护优先，超限直接拒绝并计数；
//! 2. **原始日志先落库**（保真层）：即使后续解析、归一、脱敏全部失败，证据也不会丢；
//! 3. 解析 → 归一化 → **脱敏**：脱敏只作用于**归一化事件的 `message`/`raw` 副本**，
//!    `raw_logs.payload_b64` 始终保存**原始未脱敏**载荷，由具备权限的运维通过
//!    [`crate::replay`] 复现（这是"可回放"与"最小暴露"的折中）；
//! 4. 事件落库 → 原始日志标记解析状态 → 投递总线。总线失败**不回滚**（至少一次投递）。
//!
//! ## 去重与限流
//!
//! - 去重键 = `Event::dedup_key()`（`源 + 事件时间 + 原始载荷哈希`），窗口可配置；
//! - 限流 = 每日志源一个令牌桶（容量 = `LogSource::max_eps`，按同速率补充），
//!   `max_eps = 0` 表示不限速。
//!
//! ## 无 PostgreSQL 的测试路径
//!
//! 持久化通过 [`Sink`] 抽象：单元测试用 [`InMemorySink`]，生产用
//! [`SqlSink`]（`agf_storage::Store` + RLS 租户事务）。

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use agf_core::enums::IngestProtocol;
use agf_core::error::{DomainError, DomainResult};
use agf_core::event::{Event, RawLog};
use agf_core::ids::{Id, TenantId};
use agf_core::redact::{RedactionMap, RedactionMode, redact_json, redact_text};
use agf_core::secret::{content_hash, scan_credentials};
use agf_core::source::LogSource;
use agf_core::time::Timestamp;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, warn};

use crate::bus::{EventBus, NoopEventBus};
use crate::normalize::{self, SourceMeta};
use crate::registry::{MatchMode, ParserRegistry, RegistryStats};

mod agentteams_audit;
mod agentteams_failure;
mod agentteams_failure_memory;
mod agentteams_failure_sql;
pub use agentteams_failure::{
    AGENTTEAMS_FAILURE_LIMIT, AgentTeamsFailureQuery, AgentTeamsFailureSnapshot, agentteams_failure_from_envelope,
    validate_agentteams_failure_record,
};
mod agentteams_memory;
mod agentteams_queries;
mod agentteams_sql;
mod agentteams_trace;
mod agentteams_trace_memory;
mod agentteams_trace_sql;
mod config;
pub use agentteams_audit::*;
pub use agentteams_trace::*;
mod dedup;
mod ingest;
mod persistence;
pub use persistence::IngestWrite;
mod sink;
mod source_control;
mod sql_sink;
pub use source_control::NativeSourceControl;
mod transport;
pub use transport::{TransportPeer, source_transport_controls, validate_cidrs};

#[cfg(test)]
mod tests;

pub use config::*;
pub use ingest::*;
pub use sink::*;
