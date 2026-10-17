//! MCP 事实与 Agent 锚点提交前的当前身份核验；所有 SQL 读取复用原事务。
use super::AssetTransaction;
use crate::{AppState, Principal};
use agf_auth::service::CurrentUserAuthority;
use agf_core::{
    enums::AssetKind,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    rbac::SubjectKind,
    user::User,
};
use agf_storage::{TenantTransaction, repository::ApiKeyRepo};
use serde_json::Value;
use std::sync::Arc;

#[derive(serde::Deserialize)]
struct CurrentRole {
    name: String,
    expires_at: Option<agf_core::time::Timestamp>,
}

impl AssetTransaction<'_> {
    pub(crate) async fn runtime_authorize(&self, state: &AppState, original: &Principal) -> DomainResult<()> {
        if original.tenant != self.tenant {
            return Err(denied());
        }
        let mut tx = self.transaction(self.tenant).await?;
        authorize_transaction(state, &mut tx, original).await
    }
}

/// 已持有治理围栏的调用方复用原事务；不得为当前身份复核再次申请池连接。
pub(crate) async fn authorize_transaction(
    state: &AppState,
    tx: &mut TenantTransaction<'_>,
    original: &Principal,
) -> DomainResult<()> {
    if original.tenant != tx.tenant() {
        return Err(denied());
    }
    let id = original.subject_id.ok_or_else(denied)?;
    let mut current = original.clone();
    current.roles.clear();
    current.scopes.clear();
    current.superadmin = false;
    current.agent_id = None;
    current.must_change_password = false;
    current.must_setup_mfa = false;
    match original.subject_kind {
        SubjectKind::User => user(state, tx, original, &mut current, id).await?,
        SubjectKind::ApiKey => key(state, tx, original, &mut current, id).await?,
        _ => return Err(denied()),
    }
    if current.agent_id != original.agent_id || (current.tenant != current.identity_tenant && !current.superadmin) {
        return Err(denied());
    }
    current.require(state, "policies", "read").map_err(|error| error.error)
}
async fn user(
    state: &AppState,
    tx: &mut TenantTransaction<'_>,
    original: &Principal,
    current: &mut Principal,
    id: Id,
) -> DomainResult<()> {
    let mut source = state.auth_backend.current_user_authority(original.identity_tenant, id)?;
    let policy_store = match &source {
        CurrentUserAuthority::Unavailable => None,
        CurrentUserAuthority::Sql { mfa_configuration_identity, .. }
        | CurrentUserAuthority::Synchronous { mfa_configuration_identity, .. } => *mfa_configuration_identity,
    };
    let required = if let Some(store) = policy_store {
        if store != Arc::as_ptr(&state.configurations).addr()
            || !state.store.database().is_some_and(|database| state.configurations.uses_database(database))
        {
            return Err(denied());
        }
        set_tenant(tx, original.identity_tenant).await?;
        let result = mfa_required(tx, original.identity_tenant).await;
        let restored = set_tenant(tx, original.tenant).await;
        let required = result?;
        restored?;
        required
    } else {
        false
    };
    if matches!(source, CurrentUserAuthority::Synchronous { .. }) {
        // SQL 策略等待之后重新读取同步快照；之后没有 await，不沿用等待前的内存角色。
        source = state.auth_backend.current_user_authority(original.identity_tenant, id)?;
        if !matches!(&source, CurrentUserAuthority::Synchronous { mfa_configuration_identity, .. }
            if *mfa_configuration_identity == policy_store)
        {
            return Err(denied());
        }
    }
    let (user, roles) = match source {
        CurrentUserAuthority::Unavailable => {
            return Err(DomainError::PreconditionFailed(
                "MCP SQL 事实提交要求明确的同库 SQL 身份或内置同步身份读取能力".into(),
            ));
        }
        CurrentUserAuthority::Synchronous { user, roles, .. } => {
            (user.ok_or_else(denied)?, roles.into_iter().map(|name| CurrentRole { name, expires_at: None }).collect())
        }
        CurrentUserAuthority::Sql { store_identity, .. } => {
            let store = state.store.database().ok_or_else(denied)?;
            if store_identity != Arc::as_ptr(store).addr() {
                return Err(denied());
            }
            let identity = original.identity_tenant;
            set_tenant(tx, identity).await?;
            let result = sql_user(tx, identity, id).await;
            // 仅使用认证得到的 identity_tenant；无论读取是否通过，提交前恢复业务租户上下文。
            let restored = set_tenant(tx, original.tenant).await;
            let result = result?;
            restored?;
            (Box::new(result.0), result.1)
        }
    };
    if user.id != id || user.tenant_id != original.identity_tenant || !user.can_authenticate() {
        return Err(denied());
    }
    // FOR SHARE 的等待可能跨过绑定的 expires_at；在所有等待之后再筛一次自然过期。
    let now = agf_core::time::Timestamp::now();
    current.roles =
        roles.into_iter().filter(|role| role.expires_at.is_none_or(|at| at > now)).map(|role| role.name).collect();
    current.superadmin = user.is_superadmin;
    current.must_change_password = user.must_change_password;
    current.department = user.department;
    current.must_setup_mfa = required && !user.mfa_enabled;
    Ok(())
}

async fn sql_user(tx: &mut TenantTransaction<'_>, tenant: TenantId, id: Id) -> DomainResult<(User, Vec<CurrentRole>)> {
    let value: Option<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(u) - 'password_hash' - 'password_history'
        || jsonb_build_object('last_login_ip',host(last_login_ip)) FROM users u
        WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE",
    )
    .bind(tenant.as_uuid())
    .bind(id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(sql)?;
    let user: User = serde_json::from_value(value.ok_or_else(denied)?)?;
    let roles: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('name',r.name,'expires_at',b.expires_at)
        FROM role_bindings b JOIN roles r
        ON r.id=b.role_id AND r.tenant_id=b.tenant_id JOIN users u
        ON u.id=b.subject_id AND u.tenant_id=b.tenant_id WHERE b.tenant_id=$1 AND b.subject_id=$2
        AND b.subject_kind='user' AND b.deleted_at IS NULL AND r.deleted_at IS NULL AND u.deleted_at IS NULL
        AND (b.expires_at IS NULL OR b.expires_at>clock_timestamp()) ORDER BY r.name FOR SHARE OF b,r",
    )
    .bind(tenant.as_uuid())
    .bind(id.as_uuid())
    .fetch_all(&mut **tx)
    .await
    .map_err(sql)?;
    Ok((user, roles.into_iter().map(serde_json::from_value).collect::<Result<_, _>>()?))
}

async fn key(
    state: &AppState,
    tx: &mut TenantTransaction<'_>,
    original: &Principal,
    current: &mut Principal,
    id: Id,
) -> DomainResult<()> {
    if original.identity_tenant != original.tenant {
        return Err(denied());
    }
    let exists: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT id FROM api_keys WHERE tenant_id=$1
        AND id=$2 AND NOT revoked AND deleted_at IS NULL
        AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE",
    )
    .bind(original.tenant.as_uuid())
    .bind(id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(sql)?;
    if exists.is_none() {
        return Err(denied());
    }
    let key = ApiKeyRepo::by_id(tx, id).await?.ok_or_else(denied)?;
    if !key.allowed_cidrs.is_empty()
        && !original.source_ip.as_deref().is_some_and(|ip| agf_auth::rbac::cidr_matches_any(&key.allowed_cidrs, ip))
    {
        return Err(denied());
    }
    current.agent_id = key.bound_agent_id;
    current.scopes = key.scopes.clone();
    if let Some(agent) = key.bound_agent_id {
        let locked: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM assets WHERE tenant_id=$1
            AND id=$2 AND kind::text='agent' AND deleted_at IS NULL FOR SHARE",
        )
        .bind(original.tenant.as_uuid())
        .bind(agent.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map_err(sql)?;
        if locked.is_none() {
            return Err(denied());
        }
        let asset = agf_storage::AssetRepo::get(tx, agent).await?.ok_or_else(denied)?;
        if asset.kind != AssetKind::Agent {
            return Err(denied());
        }
        current.scopes = crate::agentteams_role_mapping::constrain_key_transaction(state, tx, &key, &asset).await?;
        current.department = asset.department;
    }
    // 绑定或角色行锁可能等待；提交前仍须拒绝等待期间自然过期的 Key。
    if key.expires_at.is_some_and(|at| at <= agf_core::time::Timestamp::now()) {
        return Err(denied());
    }
    Ok(())
}

async fn mfa_required(tx: &mut TenantTransaction<'_>, tenant: TenantId) -> DomainResult<bool> {
    let policy: Option<Value> = sqlx::query_scalar(
        "SELECT payload FROM console_configurations WHERE tenant_id=$1
        AND kind=$2 AND id=$3 AND deleted_at IS NULL FOR SHARE",
    )
    .bind(tenant.as_uuid())
    .bind(crate::auth_policy::KIND)
    .bind(crate::model_routes::tenant_record_id(tenant).as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(sql)?;
    Ok(policy
        .map(serde_json::from_value::<crate::auth_policy::TenantPolicy>)
        .transpose()?
        .is_some_and(|policy| policy.view.mfa_enforced))
}

async fn set_tenant(tx: &mut TenantTransaction<'_>, tenant: TenantId) -> DomainResult<()> {
    sqlx::query("SELECT set_config('agf.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut **tx)
        .await
        .map_err(sql)?;
    Ok(())
}
fn denied() -> DomainError {
    DomainError::Forbidden("MCP 事实提交的原账号、密钥、租户、Agent 或当前权限已失效".into())
}
fn sql(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("runtime_current_authority", &error)
}
