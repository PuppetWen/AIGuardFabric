//! # agf-core — AIGuardFabric 领域内核
//!
//! 本 crate 提供全平台共享的领域模型、错误类型、通用类型与安全原语。
//! 它**不依赖任何 I/O 实现**（数据库、HTTP、消息队列），只依赖纯计算与序列化，
//! 因此可以被所有上层 crate 依赖，也能在离线环境下完整单元测试。
//!
//! ## 分层约定
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`error`] | 统一错误类型，向上层暴露 [`DomainError`]，由 `agf-api` 映射为 RFC 9457 |
//! | [`ids`] / [`time`] / [`pagination`] | 通用类型（UUID v7 / UTC 时间戳 / 分页） |
//! | [`enums`] | 跨域枚举（资产类型、严重等级、策略动作、协议…） |
//! | [`tenant`] / [`user`] / [`rbac`] / [`auth`] | 多租户与身份 |
//! | [`asset`] / [`agent`] / [`mcp`] / [`skill`] / [`model`] / [`credential`] / [`topology`] | 资产域 |
//! | [`risk`] / [`rule`] / [`redteam`] / [`policy`] / [`quota`] | 风险与治理域 |
//! | [`event`] / [`source`] / [`parser`] / [`alert`] / [`case`] / [`notify`] | 日志告警与案件域 |
//! | [`adapter`] / [`cloud`] / [`audit`] / [`report`] / [`config`] | 集成与平台能力域 |
//! | [`secret`] / [`redact`] | 安全原语（凭据识别、掩码、脱敏） |
//! | [`constants`] | 全局常量 |
//!
//! ## 设计原则
//!
//! 1. **纯函数优先**：评分、匹配、去重、差分等核心判定都写成可单测的纯函数
//!    （见 [`asset::score_exposure`]、[`quota::check_quotas`]、[`risk::fuse_confidence`]、
//!    [`audit::verify_chain`]、[`policy::domain_matches`]、[`topology::Topology::shortest_path`]）。
//! 2. **明文凭据绝不进入领域模型**：见 [`credential::SecretMaterial`] 与 [`redact`]。
//! 3. **枚举是共同语言**：API / 数据库文本列 / 前端 i18n key / 规则谓词共用一份定义。
//! 4. **无 `unwrap()`、无 `unsafe`**：crate 级 `forbid(unsafe_code)`，clippy 拒绝 `unwrap_used`。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod adapter;
pub mod agent;
pub mod alert;
pub mod asset;
pub mod audit;
pub mod auth;
pub mod case;
pub mod cloud;
pub mod config;
pub mod constants;
pub mod credential;
pub mod cron;
pub mod enums;
pub mod error;
pub mod event;
pub mod ids;
pub mod mcp;
pub mod mcp_config_safety;
pub mod model;
pub mod notify;
pub mod pagination;
pub mod parser;
pub mod policy;
pub mod process_hook;
pub mod quota;
pub mod rbac;
pub mod redact;
pub mod redteam;
pub mod report;
pub mod risk;
pub mod rule;
pub mod secret;
pub mod skill;
pub mod skill_package;
pub mod source;
pub mod tenant;
pub mod time;
pub mod topology;
pub mod user;

pub use error::{DomainError, DomainResult};
pub use ids::{Id, TenantScoped};

/// 平台版本（编译期取自 Cargo 包版本）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 便捷重导出：上层最常用的类型。
pub mod prelude {
    pub use crate::error::{DomainError, DomainResult};
    pub use crate::ids::{Id, TenantId, TenantScoped};
    pub use crate::pagination::{Page, PageRequest, SortDirection};
    pub use crate::time::Timestamp;
}
