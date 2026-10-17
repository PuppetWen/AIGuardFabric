//! 三级配额强制（§4.3 对齐 ClawPro：租户 → Agent → 会话；维度 Token/次数/并发/金额）。
//!
//! # 职责边界
//!
//! - **纯判定**（哪些配额超限、动作是什么）由 `agf-core` 的
//!   [`agf_core::quota::check_quotas`] 负责，本模块**不重复实现**；
//! - **原子计数**由 [`agf_storage::QuotaCounter`]（Redis Lua 脚本）负责；
//! - 本模块负责把两者串起来，并给出**明确的降级语义**（[`FailMode`]）。
//!
//! # 三级作用域与计数键
//!
//! | 作用域 | 计数目标 | 说明 |
//! |---|---|---|
//! | [`QuotaScope::Tenant`] | 无 | 租户总量 |
//! | [`QuotaScope::Agent`] | Agent 资产 id | 单 Agent 总量（`agent=None` 时**跳过 Agent 级检查**） |
//! | [`QuotaScope::Session`] | 会话 id | 单会话总量 |
//!
//! 计数键由 [`QuotaKey`] 描述，并交给 [`agf_storage::RedisStore::quota`] 组装成
//! `{prefix}:quota:{tenant}:{scope}:{dimension}:{bucket}[:{target}]`——
//! 两边共用同一套键规则，避免"配额服务写一套键、Redis 层读另一套键"。
//! 窗口桶（`bucket`）由 [`agf_core::quota::QuotaWindow::bucket_key`] 生成。
//!
//! # 并发维度与会话生命周期
//!
//! `concurrency` 与其它维度**语义不同**：它是"在飞请求数"，必须在请求结束时归还。
//!
//! - 请求进入：[`QuotaService::check`] 消费 `concurrency = +1`；
//! - 请求结束：[`QuotaService::complete`] 释放 `concurrency = -1`，并把
//!   token/金额等**后置计量**累加进计数（[`QuotaService::record_usage`]）。
//!
//! 因此"并发上限"在 Redis 中的值 = 当前在飞请求数，而不是历史累计值——这也是
//! [`agf_storage::QuotaCounter::release`] 存在的原因。
//!
//! # 降级行为（[`FailMode`]）
//!
//! | 配额维度的 `on_exceed` | 默认失败模式 | 理由 |
//! |---|---|---|
//! | `deny` / `isolate` | [`FailMode::FailClosed`] | 安全控制，宁可少服务不可失控 |
//! | `audit` / `quota` / `throttle` / `degrade` / `allow` | [`FailMode::FailOpen`] | 计量类，不应因计数后端抖动阻断业务 |
//!
//! 失败模式只影响**存储不可达**这一种情况；正常超限判定永远按 `on_exceed` 执行。
//! 被降级放行的结论会把 `degraded = true` 与 `reason` 一起返回，控制台据此显示
//! "配额服务降级中"，避免"看起来一切正常"。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Mutex;

pub(crate) use agf_core::enums::PolicyAction;
pub(crate) use agf_core::enums::QuotaDimension;
pub(crate) use agf_core::enums::QuotaScope;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::quota::Quota;
pub(crate) use agf_core::quota::QuotaCheck;
pub(crate) use agf_core::quota::QuotaConsumption;
pub(crate) use agf_core::quota::QuotaWindow;
pub(crate) use agf_core::quota::check_quotas;

pub(crate) use agf_storage::RedisStore;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;
#[allow(unused_imports)]
pub(crate) use window_secs::*;

/// 配额存储不可达时的失败方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailMode {
    /// 失败即拒绝（保守）。
    FailClosed,
    /// 失败即放行（可用性优先），但结论标记 `degraded`。
    FailOpen,
}

/// 配额存储错误（**必须携带 `closed`**：由存储层区分"不可达"与"逻辑拒绝"）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaStoreError {
    /// 人类可读原因。
    pub reason: String,
    /// 是否应触发 fail-closed（存储不可达 ⇒ `true`；非法参数等 ⇒ 由实现决定）。
    pub closed: bool,
}

/// 计数器定位（与 [`agf_storage::RedisStore::quota`] 的键布局**单一来源**）。
///
/// 之所以传结构化字段而不是拼接好的字符串：`QuotaCounter` 只能由
/// `RedisStore::quota(tenant, scope, dimension, bucket, target)` 构造，
/// 传结构体可以让两边共用同一套键规则，避免"配额服务写一套键、Redis 层读另一套键"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaKey {
    /// 租户。
    pub tenant: TenantId,
    /// 作用域（`tenant` / `agent` / `session`）。
    pub scope: String,
    /// 维度（`tokens` / `requests` / `concurrency` / `cost`）。
    pub dimension: String,
    /// 窗口桶。
    pub bucket: String,
    /// 作用域对象（Agent id / 会话 id；租户级为 `None`）。
    pub target: Option<String>,
}

/// 单级单维度的消费结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumeOutcome {
    /// 是否放行。
    pub allowed: bool,
    /// 消费后的用量。
    pub used: i64,
}

/// 配额计数存储抽象。
///
/// 生产实现是 [`RedisQuotaStore`]（Lua 原子 check-and-consume）；
/// 测试与离线演示用 [`InMemoryQuotaStore`]。
///
/// **为什么不是直接依赖 `RedisStore`**：这样测试可以在不启动 Redis 的前提下
/// 覆盖 fail-open / fail-closed 两条路径（见 `FailingStore` 测试替身）。
#[async_trait]
pub trait QuotaStore: Send + Sync + std::fmt::Debug {
    /// 原子"检查 + 消费"。
    ///
    /// # Errors
    /// 存储不可达或参数非法，见 [`QuotaStoreError`]。
    async fn check_and_consume(
        &self,
        key: &QuotaKey,
        limit: i64,
        amount: i64,
        window_secs: i64,
    ) -> Result<ConsumeOutcome, QuotaStoreError>;

    /// 归还额度（并发维度在请求结束时调用）。
    ///
    /// # Errors
    /// 存储不可达。
    async fn release(&self, key: &QuotaKey, amount: i64) -> Result<i64, QuotaStoreError>;

    /// 只读查询当前用量（不消费）。
    ///
    /// # Errors
    /// 存储不可达。
    async fn peek(&self, key: &QuotaKey) -> Result<i64, QuotaStoreError>;

    /// 存储是否可用（快照与自检据此标注 `degraded`）。
    fn is_degraded(&self) -> bool {
        false
    }
}

/// Redis 实现（唯一的生产实现）。
///
/// 说明：`RedisStore` 本身是轻量句柄（内部为可克隆的连接管理器），
/// 这里持有 `Arc` 以便与其它服务共享同一实例。
#[derive(Debug, Clone)]
pub struct RedisQuotaStore {
    store: std::sync::Arc<RedisStore>,
}

/// 内存实现（单进程近似计数；用于测试、离线演示与 Redis 缺失时的回退）。
///
/// 语义与 Redis 版一致：`limit <= 0` 视为不限量；消费超过上限时不写入计数
/// （与 Lua 脚本"超限不消费"保持一致，避免计数被超限请求污染）。
#[derive(Debug, Default)]
pub struct InMemoryQuotaStore {
    counters: Mutex<BTreeMap<String, i64>>,
}

/// 配额检查结论（[`QuotaCheck`] 的运行时扩展）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaCheckOutcome {
    /// 底层检查结论（超限判定 / 软阈值 / 建议动作）。
    pub check: QuotaCheck,
    /// 是否因存储不可达而降级（`true` 时控制台应显示"配额降级中"）。
    pub degraded: bool,
    /// 降级 / 拒绝原因（人类可读）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// 快照条目（控制台「配额」面板的一行）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// 配额 id。
    pub quota_id: Id,
    /// 配额名。
    pub name: String,
    /// 作用域。
    pub scope: QuotaScope,
    /// 作用域对象（Agent id / 会话 id；租户级为空）。
    pub target: String,
    /// 维度。
    pub dimension: QuotaDimension,
    /// 窗口。
    pub window: QuotaWindow,
    /// 已用（`-1` 表示存储不可达、无法读取）。
    pub used: i64,
    /// 上限。
    pub limit: i64,
    /// 使用率（0.0-1.0+；`used < 0` 时为 `-1.0`）。
    pub ratio: f32,
    /// 超限动作。
    pub on_exceed: PolicyAction,
    /// 是否触发软阈值。
    pub soft_breached: bool,
    /// 是否读取失败（降级）。
    pub degraded: bool,
}

/// 三级配额快照。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuotaSnapshot {
    /// 条目列表。
    pub entries: Vec<SnapshotEntry>,
    /// 是否存在降级读数。
    pub degraded: bool,
    /// 快照时间。
    pub at: agf_core::time::Timestamp,
}

/// 三级配额服务。
///
/// 实现 `Clone`：内部计数存储是 `Arc<dyn QuotaStore>`，克隆后**共享同一份计数**
/// （句柄语义），可安全地同时交给 MCP 代理与会话结束钩子。
#[derive(Debug, Clone)]
pub struct QuotaService {
    /// 生效配额（已展开到具体作用域）。
    quotas: Vec<Quota>,
    /// 计数存储。
    store: std::sync::Arc<dyn QuotaStore>,
    /// 每维度的失败方向覆盖（未设置时按 `on_exceed` 推导）。
    fail_modes: BTreeMap<QuotaDimension, FailMode>,
}

mod impl_fail_mode;
mod impl_quota_service;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_2;
mod window_secs;
