//! API Key 服务（`X-AGF-Key`，§8 API 约定、§4.1 资产上报鉴权）。
//!
//! ## 安全设计
//!
//! - 明文只在**创建时返回一次**，落库仅存 `prefix`（定位用）与 `key_fingerprint`
//!   （`SHA-256(盐 ‖ 明文)` 前 16 字节），因此库被拖走也无法反推密钥；
//! - 支持 `expires_at`（临时 Key）、`allowed_cidrs`（来源限制）、`revoked`（吊销）；
//! - 支持绑定到具体 Agent（`bound_agent_id`），用于终端上报的最小权限隔离；
//! - `scopes` 是**直接授予**的权限点，与角色绑定叠加。

use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::rbac::{ApiKey, Permission};
use agf_core::time::Timestamp;

/// API Key 签发请求。
#[derive(Debug, Clone)]
pub struct ApiKeyIssueRequest {
    /// 租户。
    pub tenant: TenantId,
    /// 名称。
    pub name: String,
    /// 直接授予的权限点。
    pub scopes: Vec<Permission>,
    /// 绑定 Agent（终端上报专用）。
    pub bound_agent_id: Option<Id>,
    /// 过期时间。
    pub expires_at: Option<Timestamp>,
    /// 来源 CIDR 白名单。
    pub allowed_cidrs: Vec<String>,
    /// 当前时间。
    pub now: Timestamp,
}

impl ApiKeyIssueRequest {
    /// 最小构造：仅名称，无过期与来源限制。
    #[must_use]
    pub fn named(tenant: TenantId, name: impl Into<String>, now: Timestamp) -> Self {
        Self {
            tenant,
            name: name.into(),
            scopes: Vec::new(),
            bound_agent_id: None,
            expires_at: None,
            allowed_cidrs: Vec::new(),
            now,
        }
    }
}

/// API Key 服务。
#[derive(Debug, Clone)]
pub struct ApiKeyService {
    salt: String,
    default_prefix: String,
}

/// 新建 API Key 的结果（明文只在此处出现）。
#[derive(Debug, Clone)]
pub struct IssuedApiKey {
    /// 落库实体。
    pub record: ApiKey,
    /// **明文密钥**（仅本次返回，之后不可再获取）。
    pub plaintext: String,
}

impl ApiKeyService {
    /// 构造。
    #[must_use]
    pub fn new(salt: impl Into<String>, default_prefix: impl Into<String>) -> Self {
        Self { salt: salt.into(), default_prefix: default_prefix.into() }
    }

    /// 生成并返回新 API Key。
    #[must_use]
    pub fn issue(&self, req: ApiKeyIssueRequest) -> IssuedApiKey {
        let plaintext = agf_core::secret::generate_api_key(&self.default_prefix);
        let prefix = plaintext.chars().take(self.default_prefix.len() + 8).collect::<String>();
        let fingerprint = agf_core::secret::fingerprint(&plaintext, &self.salt);
        let record = ApiKey {
            id: Id::new(),
            tenant_id: req.tenant,
            name: req.name,
            prefix,
            key_fingerprint: fingerprint,
            scopes: req.scopes,
            bound_agent_id: req.bound_agent_id,
            expires_at: req.expires_at,
            last_used_at: None,
            allowed_cidrs: req.allowed_cidrs,
            revoked: false,
            created_at: req.now,
        };
        IssuedApiKey { record, plaintext }
    }

    /// 计算明文对应的指纹（校验时使用）。
    #[must_use]
    pub fn fingerprint_of(&self, plaintext: &str) -> String {
        agf_core::secret::fingerprint(plaintext, &self.salt)
    }

    /// 从明文解析前缀（用于快速定位候选记录，避免全表扫描）。
    ///
    /// # Errors
    /// 密钥格式非法（长度不足或前缀不匹配）。
    pub fn extract_prefix(&self, plaintext: &str) -> DomainResult<String> {
        let trimmed = plaintext.trim();
        if !trimmed.starts_with(&self.default_prefix) {
            return Err(DomainError::Unauthenticated(format!("API Key 前缀非法（应为 {} 开头）", self.default_prefix)));
        }
        if trimmed.len() < self.default_prefix.len() + 16 {
            return Err(DomainError::Unauthenticated("API Key 长度不足".to_string()));
        }
        Ok(trimmed.chars().take(self.default_prefix.len() + 8).collect())
    }

    /// 校验候选记录是否匹配明文，并检查有效期/吊销/来源/绑定身份。
    ///
    /// # Errors
    /// 未匹配 → `Unauthenticated`；已吊销/过期/来源不允许/身份不匹配 → `Forbidden`。
    pub fn validate(
        &self,
        candidate: &ApiKey,
        plaintext: &str,
        source_ip: Option<&str>,
        agent_id: Option<&Id>,
        now: Timestamp,
    ) -> DomainResult<()> {
        if candidate.revoked {
            return Err(DomainError::Forbidden("API Key 已被吊销".to_string()));
        }
        if candidate.expires_at.is_some_and(|e| e.as_datetime() <= now.as_datetime()) {
            return Err(DomainError::Forbidden("API Key 已过期".to_string()));
        }
        let expected = self.fingerprint_of(plaintext);
        if !constant_time_eq(expected.as_bytes(), candidate.key_fingerprint.as_bytes()) {
            return Err(DomainError::Unauthenticated("API Key 校验失败".to_string()));
        }
        if !candidate.allowed_cidrs.is_empty() {
            let allowed = source_ip.is_some_and(|ip| crate::rbac::cidr_matches_any(&candidate.allowed_cidrs, ip));
            if !allowed {
                return Err(DomainError::Forbidden(format!(
                    "API Key 不允许来自该来源地址（{}）",
                    source_ip.unwrap_or("<未知>")
                )));
            }
        }
        if let Some(bound) = candidate.bound_agent_id {
            if agent_id != Some(&bound) {
                return Err(DomainError::Forbidden("API Key 与上报的 Agent 身份不匹配".to_string()));
            }
        }
        Ok(())
    }

    /// 判断 Key 是否具备某权限（`scopes` 支持通配）。
    #[must_use]
    pub fn allows(candidate: &ApiKey, required: &Permission) -> bool {
        candidate.scopes.iter().any(|p| p.matches(required))
    }

    /// 是否需要轮换（临近过期，默认 7 天窗口）。
    #[must_use]
    pub fn needs_rotation(candidate: &ApiKey, now: Timestamp, window_secs: i64) -> bool {
        candidate.expires_at.is_some_and(|e| e.unix_secs() - now.unix_secs() <= window_secs) && !candidate.revoked
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> ApiKeyService {
        ApiKeyService::new("test-salt", crate::defaults::API_KEY_PREFIX)
    }

    fn issued() -> IssuedApiKey {
        svc().issue(ApiKeyIssueRequest {
            scopes: vec![Permission::from_raw("agents:write")],
            ..ApiKeyIssueRequest::named(TenantId::default_tenant(), "agent-report", Timestamp::now())
        })
    }

    #[test]
    fn issue_produces_prefix_and_fingerprint_without_plaintext() {
        let k = issued();
        assert!(k.plaintext.starts_with(crate::defaults::API_KEY_PREFIX));
        assert!(k.record.prefix.starts_with(crate::defaults::API_KEY_PREFIX));
        assert!(!k.record.key_fingerprint.contains(&k.plaintext), "指纹不得包含明文");
        assert_eq!(k.record.key_fingerprint.len(), 32);
        assert!(!k.record.revoked);
        assert!(k.record.last_used_at.is_none());
    }

    #[test]
    fn validate_accepts_correct_key() {
        let s = svc();
        let k = issued();
        assert!(s.validate(&k.record, &k.plaintext, None, None, Timestamp::now()).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_key() {
        let s = svc();
        let k = issued();
        let res = s.validate(&k.record, "agf_live_wrongwrongwrongwrong", None, None, Timestamp::now());
        assert!(matches!(res.err(), Some(DomainError::Unauthenticated(_))));
    }

    #[test]
    fn revoked_and_expired_keys_rejected() {
        let s = svc();
        let now = Timestamp::now();
        let mut k = issued();
        k.record.revoked = true;
        assert!(s.validate(&k.record, &k.plaintext, None, None, now).is_err());

        let mut k2 = issued();
        k2.record.expires_at = Some(now.offset_secs(-1));
        assert!(s.validate(&k2.record, &k2.plaintext, None, None, now).is_err());
    }

    #[test]
    fn cidr_restriction_enforced() {
        let s = svc();
        let now = Timestamp::now();
        let mut k = s.issue(ApiKeyIssueRequest {
            allowed_cidrs: vec!["10.0.0.0/8".to_string()],
            ..ApiKeyIssueRequest::named(TenantId::default_tenant(), "restricted", now)
        });
        assert!(s.validate(&k.record, &k.plaintext, Some("10.1.1.1"), None, now).is_ok());
        assert!(s.validate(&k.record, &k.plaintext, Some("8.8.8.8"), None, now).is_err());
        assert!(s.validate(&k.record, &k.plaintext, None, None, now).is_err(), "无来源地址应拒绝");
        k.record.allowed_cidrs.clear();
        assert!(s.validate(&k.record, &k.plaintext, None, None, now).is_ok());
    }

    #[test]
    fn bound_agent_identity_enforced() {
        let s = svc();
        let agent = Id::new();
        let now = Timestamp::now();
        let k = s.issue(ApiKeyIssueRequest {
            bound_agent_id: Some(agent),
            ..ApiKeyIssueRequest::named(TenantId::default_tenant(), "bound", now)
        });
        assert!(s.validate(&k.record, &k.plaintext, None, Some(&agent), now).is_ok());
        assert!(s.validate(&k.record, &k.plaintext, None, Some(&Id::new()), now).is_err());
        assert!(s.validate(&k.record, &k.plaintext, None, None, now).is_err());
    }

    #[test]
    fn prefix_extraction_and_validation() {
        let s = svc();
        let k = issued();
        let prefix = s.extract_prefix(&k.plaintext);
        assert_eq!(prefix.ok().as_deref(), Some(k.record.prefix.as_str()));
        let wrong_prefix = format!("agf_test_{}", "a".repeat(40));
        assert!(s.extract_prefix(&wrong_prefix).is_err(), "前缀类型不匹配应拒绝");
        assert!(s.extract_prefix("short").is_err());
        let too_short = format!("{}abc", crate::defaults::API_KEY_PREFIX);
        assert!(s.extract_prefix(&too_short).is_err(), "过短应拒绝");
    }

    #[test]
    fn scope_matching() {
        let mut k = issued();
        assert!(ApiKeyService::allows(&k.record, &Permission::from_raw("agents:write")));
        assert!(!ApiKeyService::allows(&k.record, &Permission::from_raw("agents:delete")));
        k.record.scopes = vec![Permission::from_raw("agents:*")];
        assert!(ApiKeyService::allows(&k.record, &Permission::from_raw("agents:delete")));
    }

    #[test]
    fn rotation_window_detection() {
        let now = Timestamp::now();
        let mut k = issued();
        assert!(!ApiKeyService::needs_rotation(&k.record, now, 604_800), "无过期时间不需要轮换");
        k.record.expires_at = Some(now.offset_secs(3 * 86_400));
        assert!(ApiKeyService::needs_rotation(&k.record, now, 7 * 86_400));
        k.record.expires_at = Some(now.offset_secs(30 * 86_400));
        assert!(!ApiKeyService::needs_rotation(&k.record, now, 7 * 86_400));
        k.record.revoked = true;
        k.record.expires_at = Some(now.offset_secs(60));
        assert!(!ApiKeyService::needs_rotation(&k.record, now, 7 * 86_400), "已吊销无需轮换");
    }

    #[test]
    fn keys_are_unique() {
        let a = issued();
        let b = issued();
        assert_ne!(a.plaintext, b.plaintext);
        assert_ne!(a.record.key_fingerprint, b.record.key_fingerprint);
    }
}
