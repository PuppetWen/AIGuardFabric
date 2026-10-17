//! 认证服务：登录、刷新、登出、改密、首登强制改密的完整状态机。
//!
//! ## 为什么用 trait 抽象后端
//!
//! [`AuthBackend`] 把"读/写用户与令牌"的能力从服务逻辑中剥离：
//! - 生产环境由 `agf-server` 用 `agf-storage` 实现（`SqlAuthBackend`）；
//! - 单元测试用 [`InMemoryAuthBackend`]（本模块自带）做全流程验证，无需数据库。
//!
//! 这样登录状态机（锁定、审计、首登改密、令牌轮换）可以在离线环境下被完整测试。

use std::collections::HashMap;

use std::sync::Mutex;

use agf_core::auth::{PasswordPolicy, TokenPair};

use agf_core::error::DomainResult;

use agf_core::ids::{Id, TenantId};

use agf_core::rbac::Permission;

use agf_core::user::{LoginAttempt, RefreshTokenRecord, User, UserWithSecret};

use async_trait::async_trait;

use crate::claims::TokenIssuer;

use crate::password::PasswordHasher;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 认证错误（比 [`DomainError`] 更贴近登录场景，便于前端区分提示）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// 用户名或口令错误（**不区分**，避免用户名枚举）。
    InvalidCredentials,
    /// 账号被锁定（含剩余秒数）。
    Locked {
        /// 剩余锁定秒数。
        remaining_secs: i64,
    },
    /// 账号状态不允许登录。
    Disabled(String),
    /// 需要 MFA 二次验证。
    MfaRequired,
    /// MFA 验证码错误。
    MfaInvalid,
    /// 必须先修改口令。
    PasswordChangeRequired,
    /// 新口令不符合策略。
    WeakPassword(String),
    /// 账号不存在（仅用于内部区分，`display` 与 [`Self::InvalidCredentials`] 一致）。
    NotFound,
}

/// 登录请求。
#[derive(Debug, Clone)]
pub struct LoginRequest {
    /// 登录名。
    pub username: String,
    /// 口令。
    pub password: String,
    /// MFA 验证码（若已开启 MFA）。
    pub mfa_code: Option<String>,
    /// 来源 IP。
    pub source_ip: Option<String>,
    /// User-Agent。
    pub user_agent: Option<String>,
    /// 设备标识。
    pub device: Option<String>,
}

/// 登录结果。
#[derive(Debug, Clone)]
pub enum LoginOutcome {
    /// 登录成功，返回令牌对。
    Success {
        /// 令牌对。
        tokens: TokenPair,
        /// 用户视图。
        user: User,
        /// 有效权限点（供前端裁剪 UI）。
        permissions: Vec<Permission>,
    },
    /// 需要先改密（不签发可用令牌，只返回一次性改密令牌）。
    MustChangePassword {
        /// 改密令牌（仅可用于 `change_password`）。
        change_token: String,
        /// 用户视图。
        user: User,
    },
}

/// 持有业务事务时可使用的账号权威来源；禁止猜测异步后端或静默切换来源。
#[derive(Debug)]
pub enum CurrentUserAuthority {
    /// 自定义后端未声明无需额外连接的读取能力，调用者必须拒绝。
    Unavailable,
    /// 账号与角色来自指定的同一个业务 SQL Store。
    Sql {
        /// 仅在进程内比对 Arc<Store> 身份，不写入日志或公开响应。
        store_identity: usize,
        /// ProtectedBackend 绑定的配置 Store；None 表示后端不执行配置 MFA 策略。
        mfa_configuration_identity: Option<usize>,
    },
    /// 内置内存后端在账号锁及角色锁共同持有时读取的同步快照。
    Synchronous {
        /// None 明确表示原账号缺失，不得回退到 SQL 或旧 Principal。
        user: Option<Box<User>>,
        /// 与该账号同一次锁定读取的当前角色。
        roles: Vec<String>,
        /// 配置 MFA 装饰器的 Store 身份；不能借用另一个配置来源。
        mfa_configuration_identity: Option<usize>,
    },
}

/// 认证后端抽象（生产由 `agf-storage` 实现）。
#[async_trait]
pub trait AuthBackend: Send + Sync + std::fmt::Debug {
    /// 仅声明可在已有业务事务内核实的权威来源；默认禁止，不能轮询异步方法试探。
    fn current_user_authority(&self, _tenant: TenantId, _user: Id) -> DomainResult<CurrentUserAuthority> {
        Ok(CurrentUserAuthority::Unavailable)
    }

    /// 列举当前租户的未删除用户。
    async fn list_users(&self, tenant: TenantId) -> DomainResult<Vec<User>>;

    /// 原子保存用户、口令和角色（管理操作）；`user.version` 必须等于持久化版本。
    async fn save_account(&self, user: &User, password_hash: Option<&str>, roles: &[String]) -> DomainResult<()>;
    /// Create an external account only if absent; never reset existing state or roles.
    async fn provision_federated(&self, user: &User, roles: &[String]) -> DomainResult<()>;
    /// 按登录名查找用户（含口令哈希）。
    ///
    /// # Errors
    /// 存储错误。
    async fn find_user_with_secret(&self, tenant: TenantId, username: &str) -> DomainResult<Option<UserWithSecret>>;

    /// 按 id 查找用户。
    ///
    /// # Errors
    /// 存储错误。
    async fn find_user(&self, tenant: TenantId, user_id: Id) -> DomainResult<Option<User>>;

    /// 条件保存用户（口令哈希变更、失败计数、状态等），旧版本返回冲突。
    ///
    /// # Errors
    /// 存储错误。
    async fn save_user(&self, user: &User, password_hash: Option<&str>) -> DomainResult<()>;

    /// 最近的历史口令哈希，按新到旧排列。
    async fn password_history(&self, tenant: TenantId, user_id: Id) -> DomainResult<Vec<String>>;

    /// 租户是否要求 MFA；受限登录只可完成绑定。
    async fn mfa_required(&self, _tenant: TenantId) -> DomainResult<bool> {
        Ok(false)
    }
    /// 安全设置变更后，使此前签发的访问会话失效。
    async fn session_valid(&self, _tenant: TenantId, _user: &User, _issued_at: i64) -> DomainResult<bool> {
        Ok(true)
    }

    /// 记录刷新令牌。
    ///
    /// # Errors
    /// 存储错误。
    async fn store_refresh(&self, record: &RefreshTokenRecord) -> DomainResult<()>;

    /// 依据指纹查找刷新令牌。
    ///
    /// # Errors
    /// 存储错误。
    async fn find_refresh(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<RefreshTokenRecord>>;

    /// 吊销刷新令牌。
    ///
    /// # Errors
    /// 存储错误。
    async fn revoke_refresh(&self, tenant: TenantId, id: Id, reason: &str) -> DomainResult<bool>;

    /// 写入登录尝试审计。
    ///
    /// # Errors
    /// 存储错误。
    async fn record_attempt(&self, attempt: &LoginAttempt) -> DomainResult<()>;

    /// 加载主体的角色名。
    ///
    /// # Errors
    /// 存储错误。
    async fn roles_of(&self, tenant: TenantId, user_id: Id) -> DomainResult<Vec<String>>;

    /// 校验 MFA；未装配验证器时拒绝已开启 MFA 的账号。
    ///
    /// # Errors
    /// 存储错误。
    async fn verify_mfa(&self, tenant: TenantId, user: &User, _code: Option<&str>) -> DomainResult<bool> {
        Ok(user.tenant_id == tenant && !user.mfa_enabled)
    }
}

/// 认证服务。
#[derive(Clone)]
pub struct AuthService {
    issuer: TokenIssuer,
    hasher: PasswordHasher,
    policy: PasswordPolicy,
    fingerprint_salt: String,
}

// ===========================================================================
// 内存后端（单元测试 / 离线演示）
// ===========================================================================

/// 内存认证后端：**仅用于测试与离线演示**，进程重启即丢失。
#[derive(Debug, Default)]
pub struct InMemoryAuthBackend {
    users: Mutex<HashMap<Id, (User, Option<String>)>>,
    refreshes: Mutex<Vec<RefreshTokenRecord>>,
    attempts: Mutex<Vec<LoginAttempt>>,
    role_assignments: Mutex<HashMap<Id, Vec<String>>>,
    mfa_codes: Mutex<HashMap<Id, String>>,
    password_histories: Mutex<HashMap<(TenantId, Id), Vec<String>>>,
}

mod federated;
mod impl_auth_error;
mod impl_in_memory_auth_backend;
#[cfg(test)]
mod tests;
