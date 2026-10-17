//! # agf-storage — 存储层
//!
//! 职责（§7 数据库核心表、§9 部署）：
//! - [`db`]：PostgreSQL / TimescaleDB 连接池、迁移执行、**租户上下文事务**（RLS 兜底）；
//! - [`crypto`]：字段级 AES-256-GCM 加解密（凭据永不落明文）；
//! - [`redis_store`]：缓存、三级配额原子计数（Lua）、分布式锁、限流；
//! - [`objectstore`]：证据包/归档对象存储（S3 兼容 + 本地 + 内存三种实现，自动降级）；
//! - [`repository`]：各领域对象的读写（资产、发现、审计哈希链、策略、事件、告警、案件…）。
//!
//! ## 降级策略（§2.4 可降级）
//!
//! | 依赖 | 不可用时的行为 |
//! |---|---|
//! | PostgreSQL | **拒绝启动**（平台没有数据库无法工作），返回 `DependencyUnavailable` |
//! | Redis | 启动继续，缓存/配额走降级路径（配额检查 `fail_closed` 由调用方决定） |
//! | 对象存储 | 自动降级为本地文件系统 `<data_dir>/objects`，再失败则内存实现 |
//!
//! ## 为什么不用 `sqlx::query!` 宏
//!
//! 见 [`db`] 模块文档：编译期校验要求构建机持有数据库，与"离线可编译、单目录自包含"冲突。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod audit_anchor;
pub mod config;
pub mod configuration;
pub mod crypto;
pub mod db;
pub mod objectstore;
pub mod redis_store;
pub mod repository;
pub mod semantic_response_cache;

pub use config::StorageConfig;
pub use crypto::FieldCipher;
pub use db::{Database, TenantTransaction, is_safe_identifier, map_sqlx_err};
pub use objectstore::{ObjectStore, StoredObject, build_object_store, select_object_store};
pub use redis_store::{QuotaCounter, QuotaOutcome, RedisStore};
pub use repository::{
    AlertRepo, ApiKeyRepo, AssetRepo, AuditRepo, AuditSelection, CaseRepo, EventRepo, FindingRepo, PlatformStats,
    PolicyRepo, Store, StoreHealth,
};

/// 平台版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// §7 规定的核心表清单（`agfctl db check-schema` 校验用）。
pub const REQUIRED_TABLES: &[&str] = &[
    // 租户与身份
    "tenants",
    "users",
    "roles",
    "permissions",
    "role_bindings",
    "api_keys",
    // 资产
    "asset_types",
    "assets",
    "asset_relations",
    "asset_snapshots",
    "asset_changes",
    "asset_inventory_runs",
    "asset_inventory_snapshots",
    "asset_inventory_changes",
    "agents",
    "mcps",
    "skills",
    "prompt_templates",
    "models",
    "model_endpoints",
    "credentials",
    // 风险
    "findings",
    "alert_escalation_receipts",
    "finding_evidence",
    "risk_rules",
    "rule_versions",
    "scan_jobs",
    "redteam_campaigns",
    "redteam_cases",
    // 策略与配额
    "policies",
    "policy_versions",
    "policy_hits",
    "quotas",
    "semantic_response_cache_v2",
    "quota_usage",
    // 接入与事件
    "log_sources",
    "parsers",
    "events",
    "raw_logs",
    "event_delivery_outbox",
    "event_analysis_receipts",
    "agentteams_audit",
    "event_analysis_retries",
    "event_analysis_actions",
    "broker_quarantine",
    "broker_quarantine_actions",
    "alerts",
    "cases",
    "case_events",
    "timelines",
    "notifications",
    "notification_channels",
    // 平台能力
    "audit_logs",
    "audit_chain_anchors",
    "agent_runtime_audit_entries",
    "reports",
    "schedules",
    "cloud_integrations",
    "alicloud_bindings",
    "adapter_configs",
    "adapter_health",
];

/// 组装完整的存储层（数据库 + 可选 Redis + 对象存储）。
///
/// 返回 `(Store, 降级说明列表)`。降级说明会写入启动日志并在"系统自检"页展示。
///
/// # Errors
/// 数据库连接失败（唯一硬失败）。
pub async fn build_store(cfg: &StorageConfig) -> agf_core::error::DomainResult<(Store, Vec<String>)> {
    let mut notes = Vec::new();
    let db = Database::connect(cfg).await?;

    let redis = match RedisStore::connect(cfg).await {
        Ok(r) => Some(r),
        Err(e) => {
            notes.push(format!("Redis 不可用（{e}）；缓存与配额降级：配额检查的失败策略由调用方决定"));
            None
        }
    };

    let (objects, note) = build_object_store(cfg).await;
    if let Some(n) = note {
        notes.push(n);
    }

    Ok((Store::new(db, redis, objects), notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_tables_cover_all_spec_groups() {
        for needle in [
            "tenants",
            "users",
            "roles",
            "permissions",
            "role_bindings",
            "api_keys",
            "assets",
            "asset_types",
            "asset_relations",
            "asset_snapshots",
            "asset_changes",
            "agents",
            "mcps",
            "skills",
            "models",
            "model_endpoints",
            "credentials",
            "findings",
            "finding_evidence",
            "risk_rules",
            "rule_versions",
            "scan_jobs",
            "redteam_campaigns",
            "redteam_cases",
            "policies",
            "policy_versions",
            "policy_hits",
            "quotas",
            "quota_usage",
            "log_sources",
            "parsers",
            "events",
            "raw_logs",
            "agentteams_audit",
            "alerts",
            "cases",
            "case_events",
            "timelines",
            "notifications",
            "notification_channels",
            "audit_logs",
            "schedules",
            "cloud_integrations",
            "alicloud_bindings",
            "adapter_configs",
            "adapter_health",
        ] {
            assert!(REQUIRED_TABLES.contains(&needle), "§7 要求的表 {needle} 未纳入 REQUIRED_TABLES（自检会漏检）");
        }
    }

    #[test]
    fn required_tables_are_unique() {
        let mut sorted = REQUIRED_TABLES.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "REQUIRED_TABLES 存在重复项");
    }

    #[test]
    fn version_is_exposed() {
        assert!(!VERSION.is_empty());
    }
}
