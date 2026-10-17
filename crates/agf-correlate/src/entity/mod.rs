//! 跨源实体对齐（§4.6「跨源实体对齐」）。
//!
//! 同一台主机在终端 Agent 上报里叫 `WORKSTATION-01`、在 syslog 里叫 `workstation-01.corp.local`、
//! 在云 API 里只有 `i-2ze0abcdefghijkl`，而它们其实是**同一个实体**。本模块把这些"同一实体
//! 的不同指称"归一为**稳定对齐键**，让关联规则、告警聚合与攻击链路图能跨日志源把证据串起来。
//!
//! ## 设计要点
//!
//! | 决策 | 理由 |
//! |---|---|
//! | 归一化不引入外部依赖（不用 `url`/`ipnet`），手写小解析器 | 依赖面越小，离线可测性越好；失败一律降级为"原样小写"，绝不 panic |
//! | 对齐键 = `租户 + 实体类型 + : + 归一化标识` | 与 [`agf_core::alert::Alert::compute_dedup_key`] 同风格，可读且可直接作为 Map key |
//! | IP/MAC 形式的标识自动升级为 [`EntityKind::Host`] | 避免"同一个 IP 既被当 IP 又被当主机"导致对齐键分裂 |
//! | IPv6 做完整展开归一 | `::1` 与 `0:0:0:0:0:0:0:1` 必须落到同一键 |
//!
//! ## 降级行为
//!
//! | 能力 | 未实现/不可用时 | 锚点 |
//! |---|---|---|
//! | DNS 反向解析补全主机别名 | **不做**（需要网络）：只接受上游已给的 `HostInfo.name`/`host.id`/`ips` | `TODO(correlate-entity-dns)` |
//! | 组织架构/CMDB 拉取（工号 → 部门） | 不做：`UserInfo` 里已有 `department` 则直接采用 | `TODO(correlate-entity-cmdb)` |
//! | 资产 id 反查 | 由调用方传入 `asset_id`；本模块不访问存储 | `TODO(correlate-entity-asset-lookup)` |

pub(crate) use std::collections::BTreeMap;
pub(crate) use std::collections::BTreeSet;

pub(crate) use agf_core::event::Event;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[cfg(test)]
pub(crate) use agf_core::enums::IngestProtocol;
#[cfg(test)]
pub(crate) use agf_core::enums::Severity;

#[allow(unused_imports)]
pub use impl_cross_source_alignment::*;
#[allow(unused_imports)]
pub use impl_entity_kind::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 实体类型（对齐攻击链路图节点语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntityKind {
    /// IP 地址（v4/v6）。
    Ip,
    /// 主机（主机名 / 主机 id / 云实例 id / MAC）。
    Host,
    /// 用户（用户名 / 邮箱 / 工号）。
    User,
    /// AI Agent 实例。
    Agent,
    /// MCP Server。
    McpServer,
    /// 域名。
    Domain,
    /// 云端身份（RAM 用户 / IAM Role / 服务账号）。
    CloudIdentity,
}

/// 证据强度：该指称本身有多可信（用于冲突时择强）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntityRefStrength {
    /// 弱：从消息正文里正则抠出来的。
    Weak,
    /// 中：结构字段（如 `host.name`）。
    Medium,
    /// 强：不可变的唯一标识（主机 id / 云实例 id / 资产 id / 工号）。
    Strong,
}

/// 归一化后的实体指称。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRef {
    /// 实体类型（`None` = 无法判定类型，退化为"通用标识"）。
    pub kind: Option<EntityKind>,
    /// 归一化后的标识（小写、去空白、IP 展开）。
    pub canonical: String,
    /// 证据强度。
    pub strength: EntityRefStrength,
    /// 证据来源（日志源名 / 字段名 / `message`）。
    pub source: String,
}

/// 实体对齐命名空间（确定性 id 用）。
pub const NS_ENTITY: &str = "aiguardfabric.correlate.entity";

/// 一个事件抽取出的全部指称，以及按类型归并后的对齐键集合。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventEntities {
    /// 全部指称（按 [`EntityRefStrength`] 降序排列，强的在前）。
    pub refs: Vec<EntityRef>,
    /// 类型 → 归一化标识集合。
    pub by_kind: BTreeMap<String, BTreeSet<String>>,
}

/// 实体对齐器（可配置"是否把 IP 视作主机标识"等策略）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityAligner {
    /// 抽取正文（`Event::message`）中的 IP / 域名 / 邮箱。
    pub scan_message: bool,
    /// 把 IP、MAC 形式的指称归入 [`EntityKind::Host`]（默认 true）。
    pub promote_ip_to_host: bool,
    /// 抽取正文中的实体上限（防御性：避免超长日志拖慢关联）。
    pub max_message_refs: usize,
}

/// 跨源对齐：把多个来源的 [`EventEntities`] 合并成"实体 → 证据来源"映射。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrossSourceAlignment {
    /// 对齐键 → 证据来源集合。
    pub keys: BTreeMap<String, BTreeSet<String>>,
    /// 对齐键 → 最强证据强度。
    pub strength: BTreeMap<String, EntityRefStrength>,
}

mod impl_cross_source_alignment;
mod impl_entity_kind;
#[cfg(test)]
mod tests;
