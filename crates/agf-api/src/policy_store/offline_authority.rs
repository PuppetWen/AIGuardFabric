//! Offline evidence brackets the existing authorizer, then is compared under the configuration mutex.
//! ProtectedBackend.find_user/roles_of only delegate to the built-in user/role stores. They never
//! read ConfigStore; mfa_required/session_valid do read it and must NEVER be polled in this callback.
use super::*;
use agf_core::rbac::SubjectKind;
use agf_storage::configuration::{OfflineGuardedSnapshot, OfflineSecurityRecords};
use futures::FutureExt;
use serde_json::Value;

#[derive(PartialEq)]
struct Evidence {
    subject: Value,
    roles: Vec<String>,
    directory: Option<Value>,
    password_policy: Option<Value>,
    mfa_enrollment: Option<Value>,
}

pub(super) struct Proof {
    evidence: Evidence,
    current: Principal,
}
impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof").field("subject_kind", &self.current.subject_kind).finish_non_exhaustive()
    }
}

pub(super) fn security(principal: &Principal) -> DomainResult<OfflineSecurityRecords> {
    Ok(OfflineSecurityRecords {
        identity_tenant: principal.identity_tenant,
        subject_id: principal.subject_id.ok_or_else(|| DomainError::Forbidden("策略提交缺少认证身份".into()))?,
    })
}

pub(super) async fn prepare(
    state: &AppState,
    submission: &mutation::Submission<'_>,
    action: &str,
) -> DomainResult<Option<Proof>> {
    prepare_for(state, submission, "policies", action, &[]).await
}

pub(super) async fn prepare_for(
    state: &AppState,
    submission: &mutation::Submission<'_>,
    resource: &str,
    action: &str,
    additional: &[publication_authority::Grant],
) -> DomainResult<Option<Proof>> {
    let Some(principal) = submission.principal else {
        return Ok(None);
    };
    let before = evidence(state, principal).await?;
    let current = authority::authorize_for(
        state,
        principal,
        resource,
        action,
        submission.submitted_at,
        submission.lease.as_ref(),
    )
    .await?;
    for grant in additional {
        current.require(state, grant.resource, grant.action).map_err(|error| error.error)?;
    }
    let after = evidence(state, principal).await?;
    if before != after {
        return Err(changed());
    }
    Ok(Some(Proof { evidence: after, current }))
}

impl Proof {
    /// No await, ConfigStore access, MFA rule evaluation or session_valid call is permitted here.
    pub(super) fn check(
        &self,
        state: &AppState,
        submission: &mutation::Submission<'_>,
        action: &str,
        snapshot: &OfflineGuardedSnapshot,
    ) -> DomainResult<()> {
        self.check_for(state, submission, "policies", action, &[], snapshot)
    }

    pub(super) fn check_for(
        &self,
        state: &AppState,
        submission: &mutation::Submission<'_>,
        resource: &str,
        action: &str,
        additional: &[publication_authority::Grant],
        snapshot: &OfflineGuardedSnapshot,
    ) -> DomainResult<()> {
        let principal = submission.principal.ok_or_else(changed)?;
        if (self.current.tenant, self.current.identity_tenant, self.current.subject_id, self.current.subject_kind)
            != (principal.tenant, principal.identity_tenant, principal.subject_id, principal.subject_kind)
        {
            return Err(changed());
        }
        if let Some(lease) = submission.lease.as_ref() {
            lease.check_subject(principal)?;
        }
        if (&self.evidence.directory, &self.evidence.password_policy, &self.evidence.mfa_enrollment)
            != (&snapshot.tenant_directory, &snapshot.password_policy, &snapshot.mfa_enrollment)
        {
            return Err(changed());
        }
        let (subject, roles) = current_subject(state, principal)?;
        if subject != self.evidence.subject || roles != self.evidence.roles {
            return Err(changed());
        }
        if let Some(id) = self.current.agent_id {
            validation::agent(submission.tenant, id, state.store.asset_get(submission.tenant, id)?.as_ref())?;
        }
        // Re-evaluate current grants, including ABAC, even when the role names did not change.
        self.current.require(state, resource, action).map_err(|error| error.error)?;
        for grant in additional {
            self.current.require(state, grant.resource, grant.action).map_err(|error| error.error)?;
        }
        // Synchronous store locks can also wait. Check expiry again immediately before the audit sink.
        if let Some(lease) = submission.lease.as_ref() {
            lease.check_subject(principal)?;
        }
        Ok(())
    }
}

pub(super) fn tenant_enabled(tenant: TenantId, directory: Option<&Value>) -> DomainResult<()> {
    if let Some(directory) = directory {
        let entries: Vec<crate::tenant_directory::Entry> =
            serde_json::from_value(directory.get("entries").cloned().ok_or_else(changed)?)?;
        if entries.iter().filter(|row| row.id == tenant).count() != 1
            || !entries.iter().any(|row| row.id == tenant && row.enabled)
        {
            return Err(DomainError::Forbidden("策略所属租户不存在或已停用".into()));
        }
    } else if tenant != TenantId::default_tenant() {
        return Err(DomainError::Forbidden("策略所属租户不存在".into()));
    }
    Ok(())
}

async fn evidence(state: &AppState, principal: &Principal) -> DomainResult<Evidence> {
    let keys = security(principal)?;
    let (subject, roles) = current_subject(state, principal)?;
    Ok(Evidence {
        subject,
        roles,
        directory: state
            .configurations
            .get(TenantId::default_tenant(), "tenant-directory", tenant_record_id(TenantId::default_tenant()))
            .await?,
        password_policy: state
            .configurations
            .get(keys.identity_tenant, crate::auth_policy::KIND, tenant_record_id(keys.identity_tenant))
            .await?,
        mfa_enrollment: state.configurations.get(keys.identity_tenant, crate::mfa_store::KIND, keys.subject_id).await?,
    })
}

fn current_subject(state: &AppState, principal: &Principal) -> DomainResult<(Value, Vec<String>)> {
    let id = principal.subject_id.ok_or_else(changed)?;
    match principal.subject_kind {
        SubjectKind::User => {
            let user = ready(state.auth_backend.find_user(principal.identity_tenant, id))?
                .filter(agf_core::user::User::can_authenticate)
                .ok_or_else(changed)?;
            let mut roles = ready(state.auth_backend.roles_of(principal.identity_tenant, id))?;
            roles.sort();
            roles.dedup();
            Ok((serde_json::to_value(user)?, roles))
        }
        SubjectKind::ApiKey => {
            let key = state
                .store
                .api_key_list(principal.identity_tenant)?
                .into_iter()
                .find(|key| key.id == id && !key.revoked && key.expires_at.is_none_or(|at| at > Timestamp::now()))
                .ok_or_else(changed)?;
            Ok((serde_json::to_value(key)?, Vec::new()))
        }
        _ => Err(changed()),
    }
}
fn ready<T>(future: impl std::future::Future<Output = DomainResult<T>>) -> DomainResult<T> {
    future.now_or_never().ok_or_else(unavailable)?
}
fn changed() -> DomainError {
    DomainError::Forbidden("策略提交期间身份、角色、会话安全设置或租户已变化；请重新读取并确认".into())
}
fn unavailable() -> DomainError {
    DomainError::PreconditionFailed("离线策略事务要求内置同步身份后端；异步后端请配置数据库".into())
}

#[cfg(test)]
mod tests;
