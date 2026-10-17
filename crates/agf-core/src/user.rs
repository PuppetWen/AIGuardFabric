//! 用户与身份模型（本地 Argon2id / OIDC / SAML / LDAP-AD / 扫码 / MFA，§4.7）。

use serde::{Deserialize, Serialize};

use crate::ids::{Id, TenantId, TenantScoped};
use crate::time::Timestamp;

/// 身份来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityProvider {
    /// 本地账号（Argon2id 口令）。
    Local,
    /// OIDC / OAuth2。
    Oidc,
    /// SAML 2.0。
    Saml,
    /// LDAP / Active Directory。
    Ldap,
    /// 扫码登录（企业微信/钉钉/飞书）。
    QrCode,
}

impl IdentityProvider {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Oidc => "oidc",
            Self::Saml => "saml",
            Self::Ldap => "ldap",
            Self::QrCode => "qr-code",
        }
    }
}

/// 账号状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserState {
    /// 待激活（邀请未接受）。
    Invited,
    /// 正常。
    Active,
    /// 锁定（连续登录失败或人工锁定）。
    Locked,
    /// 停用。
    Disabled,
}

impl UserState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Invited => "invited",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Disabled => "disabled",
        }
    }

    /// 是否允许登录。
    #[must_use]
    pub const fn can_login(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// 用户。
///
/// 注意：`password_hash` 使用 `serde(skip)`，**绝不**通过 API 序列化出去；
/// 需要传递口令哈希时使用 [`UserWithSecret`]。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 登录名（租户内唯一）。
    pub username: String,
    /// 邮箱。
    pub email: String,
    /// 显示名。
    pub display_name: String,
    /// 手机号（短信通知/扫码绑定）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// 所属部门。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// 身份来源。
    pub idp: IdentityProvider,
    /// 外部身份主体标识（OIDC sub / SAML NameID / LDAP DN）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_subject: Option<String>,
    /// 状态。
    pub state: UserState,
    /// 是否超级管理员（跨租户，仅平台运维）。
    pub is_superadmin: bool,
    /// 首登强制改密（安全基线 §2.6）。
    pub must_change_password: bool,
    /// MFA 是否已启用。
    pub mfa_enabled: bool,
    /// MFA TOTP 密钥引用（密文存 `credentials`，此处仅存引用 id）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_secret_ref: Option<Id>,
    /// 连续登录失败次数。
    pub failed_logins: u32,
    /// 锁定截止时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<Timestamp>,
    /// 上次登录时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<Timestamp>,
    /// 上次登录 IP。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_ip: Option<String>,
    /// 口令最后修改时间（用于过期策略）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_changed_at: Option<Timestamp>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
    /// 账号写入版本。每次持久化递增，旧快照不得覆盖新的安全状态。
    #[serde(default)]
    pub version: u64,
    /// 软删除。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<Timestamp>,
}

impl TenantScoped for User {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl User {
    /// 新建本地用户（不含口令哈希，由 `agf-auth` 设置）。
    #[must_use]
    pub fn new_local(tenant_id: TenantId, username: impl Into<String>, email: impl Into<String>) -> Self {
        let now = Timestamp::now();
        let username = username.into();
        Self {
            id: Id::new(),
            tenant_id,
            display_name: username.clone(),
            username,
            email: email.into(),
            phone: None,
            department: None,
            idp: IdentityProvider::Local,
            external_subject: None,
            state: UserState::Active,
            is_superadmin: false,
            must_change_password: true,
            mfa_enabled: false,
            mfa_secret_ref: None,
            failed_logins: 0,
            locked_until: None,
            last_login_at: None,
            last_login_ip: None,
            password_changed_at: None,
            created_at: now,
            updated_at: now,
            version: 0,
            deleted_at: None,
        }
    }

    /// 账号当前是否被锁定。
    #[must_use]
    pub fn is_locked_now(&self) -> bool {
        self.state == UserState::Locked
            || self.locked_until.is_some_and(|until| until.as_datetime() > chrono::Utc::now())
    }

    /// 是否可登录（状态 + 未锁定）。
    #[must_use]
    pub fn can_authenticate(&self) -> bool {
        self.state.can_login() && !self.is_locked_now() && self.deleted_at.is_none()
    }
}

/// 携带口令哈希的用户记录（仅 `agf-auth` / `agf-storage` 内部使用）。
#[derive(Debug, Clone)]
pub struct UserWithSecret {
    /// 用户主体。
    pub user: User,
    /// Argon2id PHC 字符串。
    pub password_hash: Option<String>,
}

/// 登录尝试记录（用于风控与审计）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    /// 主键。
    pub id: Id,
    /// 租户（未知租户时为 `None`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<TenantId>,
    /// 尝试的用户名。
    pub username: String,
    /// 来源 IP。
    pub source_ip: String,
    /// User-Agent。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// 是否成功。
    pub success: bool,
    /// 失败原因码。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    /// 发生时间。
    pub at: Timestamp,
}

/// 刷新令牌记录（支持吊销与设备管理）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 用户。
    pub user_id: Id,
    /// 令牌指纹（SHA-256 前 16 字节 hex，不存明文）。
    pub token_fingerprint: String,
    /// 过期时间。
    pub expires_at: Timestamp,
    /// 是否已吊销。
    pub revoked: bool,
    /// 吊销原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
    /// 设备/客户端标识。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// 创建时间。
    pub created_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_local_user_requires_password_change() {
        let u = User::new_local(TenantId::default_tenant(), "alice", "alice@example.com");
        assert!(u.must_change_password);
        assert_eq!(u.state, UserState::Active);
        assert!(u.can_authenticate());
        assert_eq!(u.idp.as_str(), "local");
    }

    #[test]
    fn locked_user_cannot_authenticate() {
        let mut u = User::new_local(TenantId::default_tenant(), "bob", "bob@example.com");
        u.locked_until = Some(Timestamp::now().offset_secs(600));
        assert!(u.is_locked_now());
        assert!(!u.can_authenticate());
        u.locked_until = Some(Timestamp::now().offset_secs(-1));
        assert!(!u.is_locked_now());
    }

    #[test]
    fn disabled_user_cannot_authenticate() {
        let mut u = User::new_local(TenantId::default_tenant(), "carol", "c@example.com");
        u.state = UserState::Disabled;
        assert!(!u.can_authenticate());
        assert!(!UserState::Invited.can_login());
    }

    #[test]
    fn idp_str() {
        assert_eq!(IdentityProvider::Ldap.as_str(), "ldap");
        assert_eq!(IdentityProvider::QrCode.as_str(), "qr-code");
    }
}
