//! 认证域类型：JWT 声明、令牌对、会话、口令策略、MFA。

use serde::{Deserialize, Serialize};

use crate::ids::{Id, TenantId};
use crate::rbac::SubjectKind;
use crate::time::Timestamp;

/// JWT 访问令牌声明。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    /// 签发者（`AGF_JWT_ISSUER`）。
    pub iss: String,
    /// 主体（用户 id / API Key id / Agent id）。
    pub sub: String,
    /// 受众（固定 `agf-api`）。
    pub aud: String,
    /// 过期时间（Unix 秒）。
    pub exp: i64,
    /// 签发时间（Unix 秒）。
    pub iat: i64,
    /// 高精度签发时间，用于安全设置变更后吊销同一秒内的旧会话。
    #[serde(default)]
    pub issued_at_ms: i64,
    /// 生效时间（Unix 秒）。
    pub nbf: i64,
    /// JWT ID（用于吊销黑名单）。
    pub jti: String,
    /// 租户。
    pub tenant_id: String,
    /// 主体类型。
    pub subject_kind: SubjectKind,
    /// 角色标识列表（仅放名字，权限点在服务端展开，避免令牌膨胀）。
    #[serde(default)]
    pub roles: Vec<String>,
    /// 是否超级管理员。
    #[serde(default)]
    pub superadmin: bool,
    /// 是否处于"必须改密"状态（此状态下仅放行改密/登出接口）。
    #[serde(default)]
    pub must_change_password: bool,
    /// 会话 id（用于三级配额的会话级统计与强制下线）。
    pub session_id: String,
}

impl AccessClaims {
    /// 是否已过期。
    #[must_use]
    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.exp
    }
}

/// 令牌对。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// 访问令牌（JWT）。
    pub access_token: String,
    /// 刷新令牌（不透明随机串，服务端存指纹）。
    pub refresh_token: String,
    /// 令牌类型（固定 `Bearer`）。
    pub token_type: String,
    /// 访问令牌有效期（秒）。
    pub expires_in: i64,
    /// 会话 id。
    pub session_id: String,
}

impl TokenPair {
    /// 构造标准 Bearer 令牌对。
    #[must_use]
    pub fn bearer(access_token: String, refresh_token: String, expires_in: i64, session_id: String) -> Self {
        Self { access_token, refresh_token, token_type: "Bearer".to_string(), expires_in, session_id }
    }
}

/// 会话视图（强制下线 / 设备管理页使用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    /// 会话 id。
    pub id: String,
    /// 用户。
    pub user_id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 客户端标识。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// 来源 IP。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 最近活跃。
    pub last_seen_at: Timestamp,
    /// 是否当前会话。
    pub current: bool,
}

/// 口令策略（安全基线 §2.6）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// 最小长度。
    pub min_length: usize,
    /// 是否要求大小写/数字/符号四类中的至少三类。
    pub require_classes: bool,
    /// 口令有效期（天，0 = 不过期）。
    pub max_age_days: u32,
    /// 禁止复用最近 N 次口令（0 = 不限制）。
    pub history_size: u32,
    /// 连续失败锁定阈值。
    pub max_failures: u32,
    /// 锁定持续（秒）。
    pub lockout_secs: i64,
    /// 弱口令黑名单（内置常见弱口令 + 平台专有名词）。
    pub deny_list: Vec<String>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_classes: true,
            max_age_days: 90,
            history_size: 5,
            max_failures: 5,
            lockout_secs: 900,
            deny_list: default_weak_passwords(),
        }
    }
}

impl PasswordPolicy {
    /// 校验口令强度。
    ///
    /// # Errors
    /// 返回人类可读的失败原因（会直接回显给用户，注意不要泄露策略细节以外信息）。
    pub fn validate(&self, password: &str, username: &str) -> Result<(), String> {
        if password.chars().count() < self.min_length {
            return Err(format!("口令长度至少 {} 位", self.min_length));
        }
        if self.require_classes {
            let has_lower = password.chars().any(char::is_lowercase);
            let has_upper = password.chars().any(char::is_uppercase);
            let has_digit = password.chars().any(|c| c.is_ascii_digit());
            let has_symbol = password.chars().any(|c| !c.is_alphanumeric());
            let classes = [has_lower, has_upper, has_digit, has_symbol].iter().filter(|v| **v).count();
            if classes < 3 {
                return Err("口令需包含大写字母、小写字母、数字、符号中的至少三类".to_string());
            }
        }
        let lower = password.to_lowercase();
        if self.deny_list.iter().any(|w| lower.contains(&w.to_lowercase())) {
            return Err("口令包含常见弱口令片段，请更换".to_string());
        }
        if !username.is_empty() && lower.contains(&username.to_lowercase()) {
            return Err("口令不得包含用户名".to_string());
        }
        Ok(())
    }
}

/// 内置弱口令黑名单（用于拒绝；生产环境可替换为完整字典）。
#[must_use]
pub fn default_weak_passwords() -> Vec<String> {
    [
        "password",
        "passw0rd",
        "123456",
        "12345678",
        "qwerty",
        "admin",
        "administrator",
        "root",
        "letmein",
        "welcome",
        "changeme",
        "aiguardfabric",
        "agf123",
        "iloveyou",
        "monkey",
        "dragon",
        "abc123",
        "111111",
        "000000",
        "admin123",
        "p@ssw0rd",
        "test123",
        "secret",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// MFA 方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MfaMethod {
    /// TOTP（推荐）。
    Totp,
    /// WebAuthn / 安全密钥。
    WebAuthn,
    /// 短信验证码。
    Sms,
    /// 邮件验证码。
    Email,
    /// 恢复码。
    RecoveryCode,
}

impl MfaMethod {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::WebAuthn => "webauthn",
            Self::Sms => "sms",
            Self::Email => "email",
            Self::RecoveryCode => "recovery-code",
        }
    }
}

/// MFA 注册记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaEnrollment {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 用户。
    pub user_id: Id,
    /// 方式。
    pub method: MfaMethod,
    /// 是否已确认（注册完成需一次验证）。
    pub confirmed: bool,
    /// 机密引用（TOTP seed 密文存 `credentials`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<Id>,
    /// 恢复码哈希（每个一次）。
    #[serde(default)]
    pub recovery_hashes: Vec<String>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 最后使用。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<Timestamp>,
}

/// 单点登录提供方配置（OIDC / SAML / LDAP）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpConfig {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 类型。
    pub provider: crate::user::IdentityProvider,
    /// 显示名（登录页按钮文案）。
    pub display_name: String,
    /// 是否启用。
    pub enabled: bool,
    /// OIDC issuer。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// OIDC client id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// client secret 引用（密文存 `credentials`，此处只存引用 id）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_ref: Option<Id>,
    /// 需要的 scope。
    #[serde(default)]
    pub scopes: Vec<String>,
    /// 用户名映射的 claim（如 `preferred_username`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_claim: Option<String>,
    /// 部门映射的 claim（用于 ABAC）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department_claim: Option<String>,
    /// 自动开通用户。
    pub auto_provision: bool,
    /// 默认授予角色名。
    #[serde(default)]
    pub default_roles: Vec<String>,
    /// 创建时间。
    pub created_at: Timestamp,
}

/// 权限提升审批（`PolicyAction::Approval` 落地）。
///
/// 派生 `PartialEq`/`Eq`：审批单的字段全为值语义，便于测试与"审批单是否被改写"的断言。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 申请人。
    pub requester_id: Id,
    /// 目标资源描述（Agent / 工具 / 域名）。
    pub target: String,
    /// 申请动作。
    pub action: String,
    /// 申请理由。
    pub reason: String,
    /// 有效时长（秒）。
    pub ttl_secs: i64,
    /// 状态。
    pub state: ApprovalState,
    /// 审批人。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_id: Option<Id>,
    /// 审批意见。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_note: Option<String>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 决策时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<Timestamp>,
}

/// 审批状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalState {
    /// 待审批。
    Pending,
    /// 已批准。
    Approved,
    /// 已拒绝。
    Rejected,
    /// 已过期。
    Expired,
    /// 已撤销。
    Revoked,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> AccessClaims {
        AccessClaims {
            iss: "aiguardfabric".into(),
            sub: "u1".into(),
            aud: "agf-api".into(),
            exp: 1_000,
            iat: 0,
            issued_at_ms: 0,
            nbf: 0,
            jti: "j1".into(),
            tenant_id: TenantId::default_tenant().to_string(),
            subject_kind: SubjectKind::User,
            roles: vec!["soc-analyst".into()],
            superadmin: false,
            must_change_password: false,
            session_id: "s1".into(),
        }
    }

    #[test]
    fn claims_expiry() {
        let c = sample_claims();
        assert!(!c.is_expired(999));
        assert!(c.is_expired(1_000));
        assert!(c.is_expired(1_001));
    }

    #[test]
    fn password_policy_rejects_short_and_weak() {
        let p = PasswordPolicy::default();
        assert!(p.validate("short", "alice").is_err());
        assert!(p.validate("Password123!@#", "alice").is_err(), "包含弱口令片段 password");
        assert!(p.validate("Alice!23456789", "alice").is_err(), "包含用户名");
        assert!(p.validate("Str0ng&Passw0rd123", "alice").is_err(), "含 passw0rd 片段");
        assert!(p.validate("Xk9#mQ2$vL7@wZ1", "alice").is_ok());
    }

    #[test]
    fn password_policy_requires_three_classes() {
        let p = PasswordPolicy { deny_list: vec![], ..PasswordPolicy::default() };
        assert!(p.validate("abcdefghijklmn", "bob").is_err());
        assert!(p.validate("abcdefghijklm1", "bob").is_err());
        assert!(p.validate("Abcdefghijklm1", "bob").is_ok());
    }

    #[test]
    fn weak_password_list_is_populated() {
        let list = default_weak_passwords();
        assert!(list.len() >= 20);
        assert!(list.iter().any(|v| v == "password"));
    }

    #[test]
    fn token_pair_is_bearer() {
        let tp = TokenPair::bearer("a".into(), "r".into(), 3600, "s".into());
        assert_eq!(tp.token_type, "Bearer");
        assert_eq!(tp.expires_in, 3600);
    }

    #[test]
    fn mfa_method_str() {
        assert_eq!(MfaMethod::Totp.as_str(), "totp");
        assert_eq!(MfaMethod::RecoveryCode.as_str(), "recovery-code");
    }
}
