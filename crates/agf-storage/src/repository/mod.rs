//! 仓储层：基于 SQLx 运行期查询的领域对象读写。
//!
//! ## 约定
//!
//! - 所有**租户级**读写都通过 [`Store::with_tenant`] 拿到 [`TenantTransaction`]，
//!   由数据库 RLS 兜底越权（应用层忘记加 `tenant_id` 条件也不会越权）；
//! - 复合字段（证据、AI 上下文、主机信息、能力声明…）统一以 `jsonb` 存储；
//! - 查询一律使用绑定参数，禁止把用户输入拼进 SQL；仅表名/列名动态拼接时用
//!   [`is_safe_identifier`] 校验；
//! - "upsert" 不使用 `ON CONFLICT`（目标是**部分唯一索引**，PostgreSQL 要求
//!   冲突推断与索引谓词完全匹配，容易写错），统一采用
//!   `UPDATE → 受影响 0 行 → INSERT` 的两步写法，语义清晰且与部分索引兼容。

use sqlx::Row;

use crate::db::Database;

use crate::objectstore::ObjectStore;

use crate::redis_store::RedisStore;

#[allow(unused_imports)]
pub(crate) use impl_api_key_repo::*;
#[allow(unused_imports)]
pub use impl_case_repo::*;
#[allow(unused_imports)]
pub(crate) use impl_store::*;
#[allow(unused_imports)]
pub(crate) use row_to_asset::*;
#[allow(unused_imports)]
pub(crate) use row_to_finding::*;
#[allow(unused_imports)]
pub(crate) use row_to_policy::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 闭包返回的异步结果类型别名（`with_tenant` 使用）。
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// 统一数据访问入口：数据库 + Redis + 对象存储。
#[derive(Debug, Clone)]
pub struct Store {
    db: Database,
    redis: Option<RedisStore>,
    objects: std::sync::Arc<dyn ObjectStore>,
}

/// 存储健康状态。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoreHealth {
    /// 数据库可用。
    pub database: bool,
    /// Redis 可用。
    pub redis: bool,
    /// 对象存储可用。
    pub objects: bool,
    /// 对象存储后端。
    pub object_backend: String,
}

/// 平台统计。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlatformStats {
    /// 资产总数。
    pub assets: i64,
    /// 生产环境资产数。
    pub assets_production: i64,
    /// 影子 MCP 数。
    pub shadow_mcps: i64,
    /// 活动告警数。
    pub alerts_active: i64,
    /// 待处置发现数。
    pub findings_open: i64,
    /// 严重发现数。
    pub findings_critical: i64,
    /// 未关闭案件数。
    pub cases_open: i64,
    /// 今日事件数。
    pub events_today: i64,
    /// 策略数。
    pub policies: i64,
    /// 启用规则数。
    pub rules_enabled: i64,
}

/// 读取列类型名（`sqlx::PgRow` 提供 `columns()` 与 `Column::type_info()`）。
trait ColumnTypeInfo {
    fn column_type_info_public(&self, idx: usize) -> String;
}

// ===========================================================================
// 资产
// ===========================================================================

/// 资产仓储。
#[derive(Debug)]
pub struct AssetRepo;

// ===========================================================================
// 风险发现
// ===========================================================================

/// 风险发现仓储。
#[derive(Debug)]
pub struct FindingRepo;

// ===========================================================================
// 审计（哈希链）
// ===========================================================================

/// 审计仓储：**追加-only**，维护哈希链。
#[derive(Debug)]
pub struct AuditRepo;

pub use audit_query::AuditSelection;

// ===========================================================================
// 策略
// ===========================================================================

/// 策略仓储。
#[derive(Debug)]
pub struct PolicyRepo;

// ===========================================================================
// 事件与原始日志
// ===========================================================================

/// 事件仓储。
#[derive(Debug)]
pub struct EventRepo;

// ===========================================================================
// 告警与案件
// ===========================================================================

/// 告警仓储。
#[derive(Debug)]
pub struct AlertRepo;

/// 案件仓储。
#[derive(Debug)]
pub struct CaseRepo;

// ===========================================================================
// 身份凭据
// ===========================================================================

/// API Key 仓储（`X-AGF-Key` 的落库与水合回读；明文永不落库）。
#[derive(Debug)]
pub struct ApiKeyRepo;

mod audit_query;
mod case_identity;
mod impl_api_key_repo;
mod impl_asset_repo;
mod impl_case_repo;
mod impl_store;
mod row_to_asset;
mod row_to_finding;
mod row_to_policy;
#[cfg(test)]
mod tests;

mod alert_query;
mod impl_alert_repo;

mod finding_query;

mod finding_filter;
pub use finding_filter::FindingFilter;

mod alert_filter;
pub use alert_filter::AlertFilter;
