use crate::{
    Principal,
    policy_store::{AccessLease, AuthorizedSubmission, Grant, PublicationAuthorization},
    state::AppState,
};
use agf_core::rbac::SubjectKind;
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use axum::http::HeaderMap;

static READ: PublicationAuthorization =
    PublicationAuthorization { resource: "alicloud", action: "read", additional: &[] };
static WRITE: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "write",
    additional: &[Grant { resource: "alicloud", action: "read" }],
};
static MANAGE: PublicationAuthorization = PublicationAuthorization {
    resource: "platform",
    action: "admin",
    additional: &[Grant { resource: "alicloud", action: "read" }, Grant { resource: "alicloud", action: "write" }],
};
static INVENTORY: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "read",
    additional: &[Grant { resource: "assets", action: "read" }],
};
static LOG_PULL: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "read",
    additional: &[Grant { resource: "sources", action: "read" }, Grant { resource: "sources", action: "write" }],
};
static REDTEAM: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "read",
    additional: &[Grant { resource: "redteam", action: "read" }, Grant { resource: "redteam", action: "execute" }],
};
static RULE_RELOAD: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "read",
    additional: &[Grant { resource: "policies", action: "write" }],
};
static REPORT: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "read",
    additional: &[Grant { resource: "reports", action: "write" }],
};
pub(super) struct Submission {
    pub principal: Principal,
    pub submitted_at: Timestamp,
    pub lease: Option<AccessLease>,
    pub write: bool,
    pub deadline: tokio::time::Instant,
    execution_authorization: Option<&'static PublicationAuthorization>,
}
impl Submission {
    pub(super) fn capture(
        state: &AppState,
        principal: Principal,
        headers: &HeaderMap,
        write: bool,
    ) -> DomainResult<Self> {
        let submitted_at = Timestamp::now();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(110);
        let lease = AccessLease::capture(state, &principal, headers)?;
        Ok(Self { principal, submitted_at, lease, write, deadline, execution_authorization: None })
    }
    pub(super) fn capture_management(
        state: &AppState,
        principal: Principal,
        headers: &HeaderMap,
    ) -> DomainResult<Self> {
        let mut submission = Self::capture(state, principal, headers, true)?;
        if submission.principal.subject_kind != SubjectKind::User {
            return Err(DomainError::Forbidden("受管任务写入要求管理员 User；API Key 不可配置任务".into()));
        }
        for (resource, action) in [("platform", "admin"), ("alicloud", "read"), ("alicloud", "write")] {
            submission.principal.require(state, resource, action).map_err(|error| error.error)?;
        }
        submission.execution_authorization = Some(&MANAGE);
        Ok(submission)
    }
    pub(super) fn capture_execution(
        state: &AppState,
        principal: Principal,
        headers: &HeaderMap,
        kind: &str,
    ) -> DomainResult<Self> {
        let mut submission = Self::capture(state, principal, headers, false)?;
        if submission.principal.subject_kind != SubjectKind::ApiKey
            || submission.principal.tenant.as_uuid().is_nil()
            || submission.principal.identity_tenant != submission.principal.tenant
        {
            return Err(DomainError::Forbidden("Callback 执行要求所选非空租户的独立平台 API Key".into()));
        }
        let authorization = match kind {
            "asset-inventory" => &INVENTORY,
            "log-pull" => &LOG_PULL,
            "redteam-cruise" => &REDTEAM,
            "rule-hot-reload" => &RULE_RELOAD,
            "report" | "archive" => &REPORT,
            _ => return Err(DomainError::Validation("Callback 执行器类型无效".into())),
        };
        submission
            .principal
            .require(state, authorization.resource, authorization.action)
            .map_err(|error| error.error)?;
        for grant in authorization.additional {
            submission.principal.require(state, grant.resource, grant.action).map_err(|error| error.error)?;
        }
        submission.execution_authorization = Some(authorization);
        Ok(submission)
    }
    pub(super) fn borrowed(&self) -> AuthorizedSubmission<'_> {
        AuthorizedSubmission {
            principal: &self.principal,
            submitted_at: self.submitted_at,
            lease: self.lease.as_ref(),
            authorization: self.execution_authorization.unwrap_or(if self.write { &WRITE } else { &READ }),
        }
    }
    pub(super) async fn authorize(&self, state: &AppState) -> DomainResult<Principal> {
        self.budget()?;
        let principal =
            bounded(self.deadline, crate::policy_store::authorize_publication(state, &self.borrowed())).await?;
        self.budget()?;
        Ok(principal)
    }
    pub(super) fn budget(&self) -> DomainResult<()> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(expired());
        }
        Ok(())
    }
}
pub(super) async fn bounded<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = DomainResult<T>>,
) -> DomainResult<T> {
    if tokio::time::Instant::now() >= deadline {
        return Err(expired());
    }
    let result = tokio::time::timeout_at(deadline, future).await.map_err(|_| expired())?;
    if tokio::time::Instant::now() >= deadline {
        return Err(expired());
    }
    result
}
fn expired() -> DomainError {
    DomainError::Timeout("原 Scheduler 操作总预算已过期；原编号不会重派".into())
}
