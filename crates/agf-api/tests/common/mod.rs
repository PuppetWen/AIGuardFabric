//! agf-api 集成测试：全部通过 `tower::ServiceExt::oneshot` 直接驱动路由器。
//!
//! **不监听端口、不联网、不需要 PostgreSQL**：数据层是进程内存后端
//! （`AGF_MOCK_MODE=1` / 未配置数据库时的正式降级路径）。
//!
//! 覆盖：认证状态机（登录/锁定/首登改密/刷新/登出）、401/403/跨租户、problem+json、
//! 分页边界、幂等、限流、healthz/readyz/metrics、未实现端点 501（带 TODO 锚点）、
//! 能力矩阵、审计链校验、以及"资产发现 → 风险检出 → 告警 → 案件 → 策略下发 → 拦截生效"全链路。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    dead_code,
    unreachable_pub,
    unused_imports
)]

pub use std::collections::BTreeMap;
pub use std::sync::Arc;

pub use agf_api::middleware::{RateLimitTier, RateLimitTiers};
pub use agf_api::persistence::{DURABLE_RESOURCES, MEMORY_ONLY_RESOURCES, PersistenceReport, PgWrite, WriteQueue};
pub use agf_api::{AppState, BootstrapOutcome, build_router};
pub use agf_auth::api_key::ApiKeyIssueRequest;
pub use agf_auth::password::PasswordHasher;
pub use agf_core::config::AppConfig;
pub use agf_core::ids::TenantId;
pub use agf_core::rbac::Permission;
pub use agf_core::time::Timestamp;
pub use agf_core::user::User;
pub use axum::Router;
pub use axum::body::Body;
pub use axum::http::{HeaderMap, Request, StatusCode, header};
pub use serde_json::{Value, json};
pub use tokio::sync::mpsc::UnboundedReceiver;
pub use tower::ServiceExt;

mod fixtures;

mod harness;

mod replay;

pub use fixtures::*;
pub use harness::*;
pub use replay::*;

pub const ADMIN_PWD: &str = "Zt7#kLm9!Qw2$Xr5";
pub const VIEWER_PWD: &str = "Vb3@nH8%Tq6&Lz1";
pub const NEWBIE_PWD: &str = "Nx4^pK7*Wm2(Rs9";
