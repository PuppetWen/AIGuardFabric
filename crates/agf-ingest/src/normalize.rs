//! 归一化：解析结果 → AGF-ECS [`Event`]（§4.5 归一化，兼容 ECS/OCSF）。
//!
//! 输入是 [`ParseOutcome::fields`]（已映射的 ECS 路径）与 [`ParseOutcome::extra`]
//! （模板未映射的原始字段名），两者一并归一化；输出是可直接落库的
//! [`Event`]。**未知路径一律进 `Event::extra`**，绝不丢弃：字段字典可以随时扩充，
//! 但原始信息一旦丢失就无法补回。
//!
//! 映射规则摘要：
//!
//! | ECS 路径 | 目标 |
//! |---|---|
//! | `event.time` / `event.severity` / `event.category` / `event.action` | 事件主干 |
//! | `host.*` | [`HostInfo`] |
//! | `user.*` | [`UserInfo`] |
//! | `network.*` / `source.*` / `destination.*` / `url.domain` | [`NetworkInfo`] |
//! | `ai.*` | [`AiContext`] |
//! | `message` / `log.original` | `Event::message` |
//! | 其他 | `Event::extra` |

use std::collections::BTreeMap;

use agf_core::enums::{IngestProtocol, Severity};
use agf_core::event::{Event, EventAction, EventCategory, NetworkDirection};
use agf_core::ids::{Id, TenantId, deterministic_id};
use agf_core::parser::ParseOutcome;
use agf_core::secret::content_hash;
use agf_core::time::Timestamp;
use serde_json::Value;

mod event;
mod mapping;

#[cfg(test)]
mod tests;

pub use event::*;
pub use mapping::*;
