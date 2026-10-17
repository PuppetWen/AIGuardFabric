//! 人工审批流程（§4.3 动作：人工审批）。
//!
//! # 语义（**绝不静默放行**）
//!
//! 1. 策略判定为 [`agf_core::enums::PolicyAction::Approval`] ⇒ 运行时**创建审批单并拒绝本次调用**，
//!    拒绝原因里带审批单 id（`approval/{id}`），调用方据此展示"请在控制台审批"。
//!    这是本模块的核心不变量：**待审批期间一律 DENY**（[`Decision::Pending`] 对应拒绝），
//!    不存在"先放行、审批结果稍后补"的实现。
//! 2. 审批通过后，该审批单**只能被消费一次**（[`ApprovalStore::consume`]）；重复使用返回
//!    [`ApprovalError::AlreadyUsed`]。这防止一个审批单被重放来放行多次危险调用。
//! 3. 审批单带 TTL：`created_at + ttl_secs` 之后状态自动转为
//!    [`ApprovalState::Expired`]（在每次读写时惰性判定，无需后台任务）。
//! 4. 被拒绝/过期/撤销的审批单不可消费，原因分别可辨。
//!
//! ## 状态机
//!
//! ```text
//! Pending ──approve──▶ Approved ──consume──▶ Used（终态）
//!    │                    │
//!    ├──reject──▶ Rejected└──expire(惰性)──▶ Expired（终态）
//!    ├──revoke──▶ Revoked
//!    └──expire(惰性)──▶ Expired
//! ```
//!
//! # 状态扩展
//!
//! `agf_core::auth::ApprovalState` 只有 `Pending/Approved/Rejected/Expired/Revoked`。
//! 本模块**不改动** `agf-core`（跨 crate 影响面大），而是在记录里增加
//! [`ApprovalRecord::used_at`] / [`ApprovalRecord::consumed_by`] 两个字段来表达"已消费"，
//! 并提供 [`ApprovalRecord::effective_state`] 把二者归一成
//! [`Decision`]（`Pending/Approved/Rejected/Expired/Revoked/Used`）供上层判定。
//!
//! # TODO(agf-runtime/approval-store-sql)
//!
//! **待办**：`agf-storage` 目前**没有** `approval_requests` 表（见
//! `agf-storage::REQUIRED_TABLES`），因此本模块只提供
//! [`InMemoryApprovalStore`]。要落库需要：
//!
//! 1. 新增迁移 `deploy/sql/migrations/XXXX_approval_requests.sql`，建表
//!    `approval_requests(id, tenant_id, session_id, agent_id, target, action, reason, ttl_secs,
//!    state, requester_id, approver_id, decision_note, used_at, consumed_by, created_at, decided_at)`，
//!    并加 `UNIQUE` 约束（`id`）与单次消费的原子更新
//!    （`UPDATE ... SET used_at = now() WHERE id = $1 AND state = 'approved' AND used_at IS NULL RETURNING *`
//!    ——用 `UPDATE ... RETURNING` 保证"检查 + 置位"原子）；
//! 2. 在本模块实现 `SqlApprovalStore`，签名与 [`ApprovalStore`] 一致；
//! 3. 在 `agf-storage::REQUIRED_TABLES` 登记新表（否则 `agfctl db check-schema` 会漏检）。
//!
//! **阻塞原因**：本 crate 的任务边界限定在 `crates/agf-runtime/`（不得改动
//! `agf-storage` 与迁移目录），且并发代理正在写 `agf-storage`，跨 crate 加表会引入冲突。
//! 影响范围：单实例部署无影响（内存实现语义完全一致）；多实例部署时审批单不共享，
//! 需在上表落地前避免多副本运行或把审批固定路由到同一实例。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Mutex;

pub(crate) use agf_core::auth::ApprovalRequest;
pub(crate) use agf_core::auth::ApprovalState;

pub(crate) use agf_core::enums::InterceptPoint;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[allow(unused_imports)]
pub use build_request::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 审批单默认有效期（秒，15 分钟）。
pub const DEFAULT_TTL_SECS: i64 = 900;

/// 审批流转的最终判定（把 `ApprovalState` + 消费记录归一）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// 待审批 ⇒ **拒绝本次调用**。
    Pending,
    /// 已批准且未被消费 ⇒ 可放行（消费后转为 `Used`）。
    Approved,
    /// 已拒绝。
    Rejected,
    /// 已过期。
    Expired,
    /// 已撤销。
    Revoked,
    /// 已消费（单次语义，重复使用会被拒）。
    Used,
}

/// 审批记录（在 [`ApprovalRequest`] 之上补充运行时上下文）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// 基础审批单。
    pub request: ApprovalRequest,
    /// 会话 id（审批与具体会话绑定，避免跨会话复用）。
    pub session_id: String,
    /// Agent 资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Id>,
    /// 命中该审批的策略 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Id>,
    /// 命中该审批的策略名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// 拦截点。
    pub intercept_point: InterceptPoint,
    /// 被拦截内容的摘要（**已脱敏**，仅用于人工判断）。
    pub excerpt: String,
    /// 过期时间（`created_at + ttl_secs`）。
    pub expires_at: Timestamp,
    /// 消费时间（`Some` ⇒ 已使用）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_at: Option<Timestamp>,
    /// 消费者标识（审批放行后的调用方，用于审计与责任追溯）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_by: Option<String>,
}

/// 审批存储错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    /// 审批单不存在。
    NotFound(Id),
    /// 审批单不可消费（状态不符）。
    NotConsumable {
        /// 审批单 id。
        id: Id,
        /// 当前判定。
        state: Decision,
    },
    /// 审批单已被消费过（单次语义）。
    AlreadyUsed(Id),
    /// 存储不可用（fail-closed：视为审批未通过）。
    StoreUnavailable(String),
    /// 参数非法。
    Invalid(String),
}

/// 审批存储抽象。
#[async_trait]
pub trait ApprovalStore: Send + Sync + std::fmt::Debug {
    /// 创建审批单。
    ///
    /// # Errors
    /// 存储不可用。
    async fn create(&self, record: ApprovalRecord) -> Result<ApprovalRecord, ApprovalError>;

    /// 读取（会做惰性过期判定，但**不改写**存储内容）。
    ///
    /// # Errors
    /// 不存在 / 存储不可用。
    async fn get(&self, tenant: TenantId, id: Id) -> Result<ApprovalRecord, ApprovalError>;

    /// 列出某租户的审批单（可按判定过滤）。
    ///
    /// # Errors
    /// 存储不可用。
    async fn list(&self, tenant: TenantId, filter: Option<Decision>) -> Result<Vec<ApprovalRecord>, ApprovalError>;

    /// 批准。
    ///
    /// # Errors
    /// 不存在 / 状态不是 `Pending` / 已过期 / 存储不可用。
    async fn approve(
        &self,
        tenant: TenantId,
        id: Id,
        approver: Id,
        note: &str,
    ) -> Result<ApprovalRecord, ApprovalError>;

    /// 拒绝。
    ///
    /// # Errors
    /// 不存在 / 状态不是 `Pending` / 存储不可用。
    async fn reject(&self, tenant: TenantId, id: Id, approver: Id, note: &str)
    -> Result<ApprovalRecord, ApprovalError>;

    /// 撤销（申请人撤回或管理员强制失效）。
    ///
    /// # Errors
    /// 不存在 / 已是终态 / 存储不可用。
    async fn revoke(&self, tenant: TenantId, id: Id, note: &str) -> Result<ApprovalRecord, ApprovalError>;

    /// **原子消费**：把 `Approved` 置为已使用并返回记录；重复消费返回
    /// [`ApprovalError::AlreadyUsed`]。
    ///
    /// # Errors
    /// 不存在 / 不可消费 / 存储不可用。
    async fn consume(&self, tenant: TenantId, id: Id, consumer: &str) -> Result<ApprovalRecord, ApprovalError>;

    /// 把已到期的审批单标记为 [`ApprovalState::Expired`]（返回被标记的数量）。
    ///
    /// # Errors
    /// 存储不可用。
    async fn expire_due(&self, tenant: TenantId, now: Timestamp) -> Result<usize, ApprovalError>;

    /// 存储是否可用（自检）。
    fn is_available(&self) -> bool {
        true
    }

    /// 审批单数量（控制台计数）。
    ///
    /// 默认实现返回 `None`（表示"该实现不支持计数"），
    /// [`InMemoryApprovalStore`] 覆盖为真实条数。
    ///
    /// # Errors
    /// 存储不可用。
    async fn count(&self) -> Result<Option<usize>, ApprovalError> {
        Ok(None)
    }
}

/// 内存实现（**默认实现**；见模块文档的 TODO 锚点）。
#[derive(Debug, Default)]
pub struct InMemoryApprovalStore {
    /// `(tenant, id) → 记录`。
    records: Mutex<BTreeMap<(TenantId, Id), ApprovalRecord>>,
    /// 便于 `list` 保持创建顺序的 id 序列。
    order: Mutex<Vec<(TenantId, Id)>>,
}

mod build_request;
mod impl_decision;
#[cfg(test)]
mod tests;
