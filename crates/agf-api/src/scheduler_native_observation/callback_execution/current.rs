use super::super::{
    authority::Submission, binding, eligibility, proof, records::BindingRecord, scope::SourceTarget, util,
};
use super::{
    input,
    model::{Context, Fact, Owner},
};
use crate::{Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
    rbac::SubjectKind,
};

pub(super) fn service(state: &AppState, principal: &Principal) -> DomainResult<Owner> {
    if principal.subject_kind != SubjectKind::ApiKey
        || principal.tenant.as_uuid().is_nil()
        || principal.identity_tenant != principal.tenant
        || state.store.database().is_none()
    {
        return Err(DomainError::PreconditionFailed("Callback 执行需要本租户平台 API Key 和持久数据库".into()));
    }
    Ok(Owner { key_id: principal.subject_id.filter(|id| !id.is_nil()).ok_or_else(input::invalid)? })
}
pub(super) async fn owner(state: &AppState, submission: &Submission, expected: &Owner) -> DomainResult<()> {
    let current = submission.authorize(state).await?;
    if service(state, &current)? != *expected {
        return Err(DomainError::Forbidden("原 Callback 执行仅允许相同有效服务密钥完成".into()));
    }
    Ok(())
}
pub(super) fn owner_locked(state: &AppState, submission: &Submission, expected: &Owner) -> DomainResult<()> {
    if service(state, &submission.principal)? != *expected {
        return Err(DomainError::Forbidden("Callback 原服务身份不匹配".into()));
    }
    Ok(())
}
pub(super) fn mapping(
    state: &AppState,
    row: &BindingRecord,
    tenant: TenantId,
    target: &SourceTarget,
    kind: &str,
    app: &str,
    job: &str,
) -> DomainResult<u64> {
    binding::validate(row, tenant)?;
    let proofs = proof::restore(state, row, tenant)?;
    if target.mocked
        || !matches!(target.transport_mode.as_str(), "live" | "loopback_test")
        || !row.enabled
        || row.target.as_ref() != Some(target)
        || row.app_id.as_deref() != Some(app)
        || !eligibility::qualified(row, kind, job)
        || !proofs.iter().any(|proof| {
            proof.source == *target
                && proof.app_id == app
                && proof.assignment.kind == kind
                && proof.assignment.job_id == job
                && proof.http_job
                && proof.enabled
        })
    {
        return Err(unqualified());
    }
    Ok(row.adoption_version)
}
pub(super) fn fence(state: &AppState, row: &BindingRecord, context: &Context) -> DomainResult<()> {
    let adopted =
        mapping(state, row, context.tenant, &context.target, &context.kind, &context.app_id, &context.job_id)?;
    if (row.version, adopted) != (context.binding_version, context.adoption_version) {
        return Err(util::stale());
    }
    Ok(())
}
pub(super) fn replay(row: &Fact, hash: &str) -> DomainResult<()> {
    if row.input_hash != hash {
        return Err(conflict());
    }
    Ok(())
}
pub(super) fn conflict() -> DomainError {
    DomainError::Conflict("原 Callback 全局执行事实或请求编号已用于其它参数；不得重派".into())
}
pub(super) fn unqualified() -> DomainError {
    DomainError::PreconditionFailed("Callback 缺少当前可信、启用的原生 HTTP Job 采用资格".into())
}
