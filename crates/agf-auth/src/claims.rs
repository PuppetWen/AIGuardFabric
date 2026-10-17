//! JWT 令牌签发与校验（§8 API 约定：JWT / `X-AGF-Key`）。
//!
//! - 算法固定 **HS256**（对称密钥，便于单机与容器化部署；如需非对称可扩展 `kid` 轮换）；
//! - 令牌内只放**角色名**，权限点在服务端展开，避免令牌膨胀与权限滞后；
//! - `jti` 支持吊销黑名单（Redis），`session_id` 用于三级配额的会话级统计；
//! - `must_change_password=true` 时，中间件只放行改密/登出接口。

use agf_core::auth::TokenPair;
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::rbac::SubjectKind;
use agf_core::time::Timestamp;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

/// JWT 访问令牌声明（对外契约，字段名与 `agf-core::auth::AccessClaims` 一致）。
pub type AccessClaims = agf_core::auth::AccessClaims;

/// 令牌签发者。
#[derive(Clone)]
pub struct TokenIssuer {
    encoding: EncodingKey,
    decoding: DecodingKey,
    issuer: String,
    audience: String,
    access_ttl_secs: i64,
    refresh_ttl_secs: i64,
}

impl std::fmt::Debug for TokenIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenIssuer")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("access_ttl_secs", &self.access_ttl_secs)
            .field("refresh_ttl_secs", &self.refresh_ttl_secs)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// 签发上下文（一次登录/刷新所绑定的身份信息）。
#[derive(Debug, Clone)]
pub struct IssueContext {
    /// 主体 id。
    pub subject: Id,
    /// 租户。
    pub tenant: TenantId,
    /// 主体类型。
    pub kind: SubjectKind,
    /// 角色名列表。
    pub roles: Vec<String>,
    /// 是否超级管理员。
    pub superadmin: bool,
    /// 是否必须修改口令。
    pub must_change_password: bool,
    /// 会话 id（客户端不提供时由服务端生成）。
    pub session_id: String,
}

impl TokenIssuer {
    /// 构造签发者。
    ///
    /// # Errors
    /// 密钥长度不足 32 字节时返回 [`DomainError::Config`]（HS256 最短安全长度）。
    pub fn new(
        secret: &str,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        access_ttl_secs: i64,
        refresh_ttl_secs: i64,
    ) -> DomainResult<Self> {
        if secret.len() < 32 {
            return Err(DomainError::Config(format!(
                "JWT 密钥长度不足（{} < 32 字节），拒绝以弱密钥签发令牌",
                secret.len()
            )));
        }
        Ok(Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
            issuer: issuer.into(),
            audience: audience.into(),
            access_ttl_secs,
            refresh_ttl_secs,
        })
    }

    /// 访问令牌有效期。
    #[must_use]
    pub const fn access_ttl_secs(&self) -> i64 {
        self.access_ttl_secs
    }

    /// 刷新令牌有效期。
    #[must_use]
    pub const fn refresh_ttl_secs(&self) -> i64 {
        self.refresh_ttl_secs
    }

    /// 签发访问令牌。
    ///
    /// # Errors
    /// 编码失败。
    pub fn issue_access(&self, ctx: &IssueContext, now: Timestamp) -> DomainResult<String> {
        let claims = AccessClaims {
            iss: self.issuer.clone(),
            sub: ctx.subject.to_string(),
            aud: self.audience.clone(),
            exp: now.unix_secs() + self.access_ttl_secs,
            iat: now.unix_secs(),
            issued_at_ms: now.unix_millis(),
            nbf: now.unix_secs(),
            jti: Id::new().to_string(),
            tenant_id: ctx.tenant.to_string(),
            subject_kind: ctx.kind,
            roles: ctx.roles.clone(),
            superadmin: ctx.superadmin,
            must_change_password: ctx.must_change_password,
            session_id: ctx.session_id.clone(),
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(|e| DomainError::Crypto(format!("签发访问令牌失败: {e}")))
    }

    /// 签发令牌对（访问 + 刷新）。
    ///
    /// # Errors
    /// 编码失败。
    pub fn issue_pair(&self, ctx: &IssueContext, now: Timestamp) -> DomainResult<(TokenPair, String)> {
        let access = self.issue_access(ctx, now)?;
        let refresh = agf_core::secret::generate_token();
        let pair = TokenPair::bearer(access, refresh.clone(), self.access_ttl_secs, ctx.session_id.clone());
        Ok((pair, refresh))
    }

    /// 校验访问令牌并返回声明。
    ///
    /// # Errors
    /// - 签名/过期/受众校验失败 → [`DomainError::Unauthenticated`]；
    /// - 声明内容非法（如 tenant_id 不是 UUID）→ [`DomainError::Parse`]。
    pub fn verify(&self, token: &str) -> DomainResult<AccessClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.leeway = 5;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        let data = decode::<AccessClaims>(token, &self.decoding, &validation).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                DomainError::Unauthenticated("令牌已过期，请刷新或重新登录".to_string())
            }
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                DomainError::Unauthenticated("令牌签名无效".to_string())
            }
            jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                DomainError::Unauthenticated("令牌受众不匹配".to_string())
            }
            _ => DomainError::Unauthenticated(format!("令牌校验失败: {e}")),
        })?;
        // 额外一致性校验：租户必须是合法 UUID
        TenantId::parse(&data.claims.tenant_id)
            .map_err(|e| DomainError::Parse(format!("令牌中的 tenant_id 非法: {e}")))?;
        Ok(data.claims)
    }

    /// 从 `Authorization: Bearer <token>` 中提取令牌。
    ///
    /// # Errors
    /// 头部缺失或格式错误。
    pub fn extract_bearer(header_value: &str) -> DomainResult<&str> {
        let trimmed = header_value.trim();
        let (scheme, token) = trimmed
            .split_once(' ')
            .ok_or_else(|| DomainError::Unauthenticated("Authorization 头格式应为 `Bearer <token>`".to_string()))?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(DomainError::Unauthenticated(format!("不支持的认证方案: {scheme}")));
        }
        let token = token.trim();
        if token.is_empty() {
            return Err(DomainError::Unauthenticated("令牌为空".to_string()));
        }
        Ok(token)
    }

    /// 刷新令牌指纹（落库只存指纹，不存明文）。
    #[must_use]
    pub fn refresh_fingerprint(&self, refresh_token: &str, salt: &str) -> String {
        agf_core::secret::fingerprint(refresh_token, salt)
    }

    /// 刷新令牌过期时间。
    #[must_use]
    pub fn refresh_expiry(&self, now: Timestamp) -> Timestamp {
        now.offset_secs(self.refresh_ttl_secs)
    }
}

/// 令牌黑名单条目（Redis 存储，键 `agf:jwt:revoked:<jti>`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedToken {
    /// JWT ID。
    pub jti: String,
    /// 吊销时间。
    pub revoked_at: Timestamp,
    /// 原因。
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "unit-test-secret-key-at-least-32-bytes-long";

    fn issuer() -> TokenIssuer {
        let r = TokenIssuer::new(SECRET, "aiguardfabric", "agf-api", 3600, 259_200);
        assert!(r.is_ok());
        r.unwrap_or_else(|_| unreachable!())
    }

    fn ctx() -> IssueContext {
        IssueContext {
            subject: Id::new(),
            tenant: TenantId::default_tenant(),
            kind: SubjectKind::User,
            roles: vec!["soc-analyst".to_string()],
            superadmin: false,
            must_change_password: false,
            session_id: "sess-1".to_string(),
        }
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let iss = issuer();
        let token = iss.issue_access(&ctx(), Timestamp::now());
        assert!(token.is_ok());
        let Ok(token) = token else { return };
        let claims = iss.verify(&token);
        assert!(claims.is_ok());
        let Ok(claims) = claims else { return };
        assert_eq!(claims.iss, "aiguardfabric");
        assert_eq!(claims.aud, "agf-api");
        assert_eq!(claims.roles, vec!["soc-analyst".to_string()]);
        assert_eq!(claims.session_id, "sess-1");
        assert_eq!(claims.subject_kind, SubjectKind::User);
        assert!(!claims.superadmin);
    }

    #[test]
    fn weak_secret_rejected() {
        let r = TokenIssuer::new("short", "iss", "aud", 60, 60);
        assert!(r.is_err());
        let msg = r.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(msg.contains("32"), "错误信息应说明长度要求: {msg}");
    }

    #[test]
    fn wrong_secret_fails_verification() {
        let a = TokenIssuer::new(SECRET, "iss", "aud", 60, 60);
        let b = TokenIssuer::new("another-secret-key-at-least-32-bytes-x", "iss", "aud", 60, 60);
        let (Ok(a), Ok(b)) = (a, b) else { return };
        let Ok(token) = a.issue_access(&ctx(), Timestamp::now()) else { return };
        let res = b.verify(&token);
        assert!(res.is_err());
        assert!(matches!(res.err(), Some(DomainError::Unauthenticated(_))));
    }

    #[test]
    fn expired_token_rejected() {
        let iss = issuer();
        // 构造一个已经过期的令牌：签发时间在 2 小时前
        let past = Timestamp::now().offset_secs(-7_200);
        let Ok(token) = iss.issue_access(&ctx(), past) else { return };
        let res = iss.verify(&token);
        assert!(res.is_err(), "过期令牌必须被拒绝");
        let msg = res.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(msg.contains("过期"), "错误信息应提示过期: {msg}");
    }

    #[test]
    fn audience_mismatch_rejected() {
        let a = TokenIssuer::new(SECRET, "iss", "aud-a", 3600, 3600);
        let b = TokenIssuer::new(SECRET, "iss", "aud-b", 3600, 3600);
        let (Ok(a), Ok(b)) = (a, b) else { return };
        let Ok(token) = a.issue_access(&ctx(), Timestamp::now()) else { return };
        assert!(b.verify(&token).is_err(), "受众不匹配必须拒绝");
    }

    #[test]
    fn issuer_mismatch_rejected() {
        let a = TokenIssuer::new(SECRET, "iss-a", "aud", 3600, 3600);
        let b = TokenIssuer::new(SECRET, "iss-b", "aud", 3600, 3600);
        let (Ok(a), Ok(b)) = (a, b) else { return };
        let Ok(token) = a.issue_access(&ctx(), Timestamp::now()) else { return };
        assert!(b.verify(&token).is_err(), "签发者不匹配必须拒绝");
    }

    #[test]
    fn pair_contains_bearer_and_session() {
        let iss = issuer();
        let (pair, refresh_plain) = iss.issue_pair(&ctx(), Timestamp::now()).unwrap_or_else(|_| unreachable!());
        assert_eq!(pair.token_type, "Bearer");
        assert_eq!(pair.session_id, "sess-1");
        assert_eq!(pair.expires_in, 3600);
        assert_eq!(pair.refresh_token, refresh_plain);
        assert!(iss.verify(&pair.access_token).is_ok());
    }

    #[test]
    fn bearer_extraction() {
        assert_eq!(TokenIssuer::extract_bearer("Bearer abc.def.ghi").ok(), Some("abc.def.ghi"));
        assert_eq!(TokenIssuer::extract_bearer("bearer abc").ok(), Some("abc"));
        assert!(TokenIssuer::extract_bearer("Basic abc").is_err());
        assert!(TokenIssuer::extract_bearer("abc").is_err());
        assert!(TokenIssuer::extract_bearer("Bearer ").is_err());
    }

    #[test]
    fn refresh_fingerprint_is_stable_and_salted() {
        let iss = issuer();
        let f1 = iss.refresh_fingerprint("refresh-token-value", "salt1");
        let f2 = iss.refresh_fingerprint("refresh-token-value", "salt1");
        let f3 = iss.refresh_fingerprint("refresh-token-value", "salt2");
        assert_eq!(f1, f2);
        assert_ne!(f1, f3);
        assert_eq!(f1.len(), 32);
    }

    #[test]
    fn tokens_are_unique_per_issue() {
        let iss = issuer();
        let ctx = ctx();
        let now = Timestamp::now();
        let Ok(t1) = iss.issue_access(&ctx, now) else { return };
        let Ok(t2) = iss.issue_access(&ctx, now) else { return };
        assert_ne!(t1, t2, "jti 不同应导致令牌不同");
    }

    #[test]
    fn debug_hides_secret() {
        let iss = issuer();
        let dbg = format!("{iss:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(SECRET));
    }

    #[test]
    fn refresh_expiry_uses_ttl() {
        let iss = issuer();
        let now = Timestamp::now();
        assert_eq!(iss.refresh_expiry(now).unix_secs() - now.unix_secs(), 259_200);
        assert_eq!(iss.access_ttl_secs(), 3600);
        assert_eq!(iss.refresh_ttl_secs(), 259_200);
    }
}
