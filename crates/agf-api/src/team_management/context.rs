use super::contract::Scope;
use crate::{
    Principal, agentteams_audit::binding, cloud_inventory, cloud_store, integration_store::decrypt, state::AppState,
};
use agf_alicloud::agentteams::relations;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub(super) struct Context {
    pub scope: Scope,
    pub inventory: cloud_inventory::Snapshot,
}

pub(super) async fn load(state: &AppState, tenant: TenantId) -> DomainResult<Context> {
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Err(DomainError::Forbidden("租户已停用".into()));
    }
    let ctx = binding::context(state, tenant)
        .await?
        .ok_or_else(|| DomainError::PreconditionFailed("请启用 AgentTeams 连接并完成可信完整盘点".into()))?;
    let relations = relations::parse_inventory(&ctx.snapshot.instance_id, &ctx.snapshot.teams, &ctx.snapshot.workers)?;
    relations.require_complete()?;
    if !relations.workers.iter().eq(ctx.snapshot.assets.keys()) {
        return Err(DomainError::PreconditionFailed("Worker 资产映射不完整，请重新盘点".into()));
    }
    let private = decrypt(state, tenant, &ctx.cloud)?;
    let identity = serde_json::to_vec(&(
        cloud_store::setting(&private, "account_id", ""),
        cloud_store::setting(&private, "endpoint", ""),
        cloud_store::setting(&private, "role_arn", ""),
        private.secrets.get("access_key_id").map(String::as_str).unwrap_or(""),
    ))?;
    let scope = Scope {
        id: ctx.scope_id,
        cloud_id: ctx.cloud.id,
        configuration_version: ctx.cloud.version,
        mocked: ctx.snapshot.mocked,
        region: ctx.snapshot.region.clone(),
        instance_id: ctx.snapshot.instance_id.clone(),
        account_fingerprint: format!("{:x}", Sha256::digest(identity)),
        inventory_at: ctx.snapshot.checked_at,
    };
    Ok(Context { scope, inventory: ctx.snapshot })
}

pub(super) fn record_id(tenant: TenantId, scope: &Scope, team: &str) -> DomainResult<Id> {
    // A configuration revision never clears a pending deletion of the same target.
    let key = serde_json::to_string(&(tenant, scope.cloud_id, &scope.region, &scope.instance_id, scope.mocked, team))?;
    Ok(deterministic_id("agf.team-management.resource", &key))
}

pub(super) fn same_scope(a: &Scope, b: &Scope) -> bool {
    a.id == b.id
        && a.cloud_id == b.cloud_id
        && a.configuration_version == b.configuration_version
        && a.mocked == b.mocked
        && a.region == b.region
        && a.instance_id == b.instance_id
        && a.account_fingerprint == b.account_fingerprint
}

pub(super) fn same_target(a: &Scope, b: &Scope) -> bool {
    a.cloud_id == b.cloud_id
        && a.mocked == b.mocked
        && a.region == b.region
        && a.instance_id == b.instance_id
        && a.account_fingerprint == b.account_fingerprint
}

pub(super) async fn available(state: &AppState, tenant: TenantId) -> DomainResult<Option<Context>> {
    match load(state, tenant).await {
        Ok(ctx) => Ok(Some(ctx)),
        Err(DomainError::Conflict(_) | DomainError::PreconditionFailed(_) | DomainError::Forbidden(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) async fn checked(
    state: &AppState,
    principal: &Principal,
    scope: &Scope,
    live: bool,
) -> DomainResult<Context> {
    principal.require(state, "alicloud", "read").map_err(|error| error.error)?;
    principal.require(state, "alicloud", "write").map_err(|error| error.error)?;
    let ctx = load(state, principal.tenant).await?;
    if !same_scope(scope, &ctx.scope) {
        return Err(super::stale());
    }
    confirm(&ctx.scope, live)?;
    Ok(ctx)
}

pub(super) fn confirm(scope: &Scope, live: bool) -> DomainResult<()> {
    if !scope.mocked && !live {
        return Err(DomainError::PreconditionFailed("请显式确认真实云调用".into()));
    }
    Ok(())
}

pub(super) async fn authority(
    state: &AppState,
    principal: &Principal,
    assets: bool,
    issued_at: Timestamp,
) -> DomainResult<Principal> {
    let current = crate::soar_workflow::Actor::from_principal(principal)?
        .resolve_for(state, principal.tenant, "alicloud", "write")
        .await?;
    current.require(state, "alicloud", "read").map_err(|error| error.error)?;
    if assets {
        current.require(state, "assets", "write").map_err(|error| error.error)?;
    }
    if current.subject_kind == agf_core::rbac::SubjectKind::User {
        let user = state
            .auth_backend
            .find_user(current.identity_tenant, current.subject_id.ok_or_else(super::stale)?)
            .await?
            .ok_or_else(super::stale)?;
        if !state.auth_backend.session_valid(current.identity_tenant, &user, issued_at.unix_millis()).await? {
            return Err(agf_core::error::DomainError::Forbidden("确认后账号安全设置已改变，请重新认证".into()));
        }
    }
    Ok(current)
}
