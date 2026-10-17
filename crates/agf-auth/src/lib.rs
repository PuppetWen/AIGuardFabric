//! # agf-auth — 认证与授权
//!
//! 覆盖 §4.7 平台能力：
//! - **认证**：本地口令（Argon2id）、JWT 访问/刷新令牌、API Key（`X-AGF-Key`）、MFA（TOTP）、
//!   OIDC 单点登录与 LDAP/AD 目录认证；SAML 与扫码登录尚待开发；
//! - **授权**：RBAC（角色 → 权限点）+ ABAC（部门/数据分级/来源网段）+ 租户隔离；
//! - **风控**：登录失败锁定、口令策略、刷新令牌吊销、首登强制改密。
//!
//! ## 降级行为（§2.4）
//!
//! | 依赖 | 未配置时 |
//! |---|---|
//! | OIDC | 未启用时仅本地账号可用，企业登录入口会提示管理员配置 |
//! | TOTP | 不强制 MFA，可由管理员按用户开启 |
//! | JWT 密钥 | **拒绝启动**（无签名密钥无法安全运行），由 `AppConfig::enforce_safety` 拦截 |
//!
//! 真实 IdP 联调需要外部凭据与服务；阶段一先完成本地 Mock 验证，
//! 阶段二的授权条件见 `docs/pending-verification.md`。

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
// 单元测试用 assert!/panic! 表达不变量；生产代码的 panic 仍在 workspace 层被 deny。
#![cfg_attr(test, allow(clippy::panic))]

pub mod api_key;
pub mod claims;
pub mod mfa;
pub mod password;
pub mod rbac;
pub mod service;

pub use api_key::ApiKeyService;
pub use claims::{AccessClaims, TokenIssuer};
pub use mfa::TotpService;
pub use password::{PasswordHasher, PasswordVerifier};
pub use rbac::Authorizer;
pub use service::{AuthError, AuthService, LoginOutcome};

pub mod ldap;
pub mod oidc;

/// 平台版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 认证子系统的默认参数（与 `.env.example` 保持一致，避免多处硬编码）。
pub mod defaults {
    /// 访问令牌有效期（秒）。
    pub const ACCESS_TTL_SECS: i64 = 3_600;
    /// 刷新令牌有效期（秒，7 天）。
    pub const REFRESH_TTL_SECS: i64 = 259_200;
    /// 登录失败锁定阈值。
    pub const MAX_FAILURES: u32 = 5;
    /// 锁定持续（秒）。
    pub const LOCKOUT_SECS: i64 = 900;
    /// 口令最小长度。
    pub const MIN_PASSWORD_LEN: usize = 12;
    /// TOTP 时间步长（秒）。
    pub const TOTP_STEP_SECS: u64 = 30;
    /// TOTP 允许的时钟偏移（步数）。
    pub const TOTP_SKEW: u8 = 1;
    /// API Key 生产前缀。
    pub const API_KEY_PREFIX: &str = "agf_live_";
    /// API Key 测试前缀。
    pub const API_KEY_PREFIX_TEST: &str = "agf_test_";
}
