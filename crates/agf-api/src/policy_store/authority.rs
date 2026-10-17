//! Original token expiry and current actor authority are rechecked after every transaction wait.
use super::*;
use agf_core::rbac::SubjectKind;
use axum::http::{HeaderMap, header};

#[derive(Debug, Clone)]
pub(crate) struct AccessLease {
    pub(super) expires_at: i64,
    pub(super) issued_at_ms: i64,
    session_id: String,
}
impl AccessLease {
    pub(crate) fn capture(state: &AppState, principal: &Principal, headers: &HeaderMap) -> DomainResult<Option<Self>> {
        if principal.subject_kind == SubjectKind::ApiKey {
            return Ok(None);
        }
        if principal.subject_kind != SubjectKind::User {
            return Err(DomainError::Forbidden("策略管理只接受用户或平台API Key身份".into()));
        }
        let header = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| DomainError::Unauthenticated("策略提交缺少原访问令牌".into()))?;
        let token = agf_auth::claims::TokenIssuer::extract_bearer(header)?;
        let claims = state.auth.issuer().verify(token)?;
        if claims.subject_kind != SubjectKind::User
            || Some(Id::parse(&claims.sub).map_err(|_| DomainError::Unauthenticated("策略访问令牌主体无效".into()))?)
                != principal.subject_id
            || TenantId::parse(&claims.tenant_id)
                .map_err(|_| DomainError::Unauthenticated("策略访问令牌租户无效".into()))?
                != principal.identity_tenant
            || principal.session_id.as_deref() != Some(claims.session_id.as_str())
        {
            return Err(DomainError::Unauthenticated("策略令牌与当前身份或会话不一致".into()));
        }
        let lease = Self {
            expires_at: claims.exp,
            issued_at_ms: if claims.issued_at_ms > 0 { claims.issued_at_ms } else { claims.iat.saturating_mul(1000) },
            session_id: claims.session_id,
        };
        lease.check()?;
        Ok(Some(lease))
    }
    pub(super) fn check(&self) -> DomainResult<()> {
        if Timestamp::now().unix_secs() >= self.expires_at {
            return Err(DomainError::Unauthenticated("策略提交访问令牌已过期；请重新登录并确认".into()));
        }
        Ok(())
    }
    pub(crate) fn check_subject(&self, principal: &Principal) -> DomainResult<()> {
        self.check()?;
        if principal.session_id.as_deref() != Some(self.session_id.as_str()) {
            return Err(DomainError::Unauthenticated("策略提交原会话不一致".into()));
        }
        Ok(())
    }
}

pub(super) async fn authorize(
    state: &AppState,
    principal: &Principal,
    action: &str,
    submitted_at: Timestamp,
    lease: Option<&AccessLease>,
) -> DomainResult<Principal> {
    authorize_for(state, principal, "policies", action, submitted_at, lease).await
}

pub(super) async fn authorize_for(
    state: &AppState,
    principal: &Principal,
    resource: &str,
    action: &str,
    submitted_at: Timestamp,
    lease: Option<&AccessLease>,
) -> DomainResult<Principal> {
    if let Some(lease) = lease {
        lease.check_subject(principal)?;
    }
    let current = crate::soar_workflow::Actor::from_principal(principal)?
        .resolve_for(state, principal.tenant, resource, action)
        .await?;
    if current.subject_kind == SubjectKind::User {
        let user = state
            .auth_backend
            .find_user(
                current.identity_tenant,
                current.subject_id.ok_or_else(|| DomainError::Forbidden("策略提交账号缺少身份".into()))?,
            )
            .await?
            .ok_or_else(|| DomainError::Forbidden("策略提交账号已不存在".into()))?;
        let issued_at = lease.map_or(submitted_at.unix_millis(), |lease| lease.issued_at_ms);
        if !state.auth_backend.session_valid(current.identity_tenant, &user, issued_at).await? {
            return Err(DomainError::Forbidden("策略提交期间账号安全设置已改变；请重新登录".into()));
        }
    }
    if let Some(lease) = lease {
        lease.check_subject(principal)?;
    }
    Ok(current)
}
