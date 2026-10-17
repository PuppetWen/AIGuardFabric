//! 链锁等待结束后重新核实原已认证 Key；所有身份围栏持续到事务提交。
use crate::{AppState, Principal};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    rbac::SubjectKind,
};
use agf_storage::TenantTransaction;

fn denied() -> DomainError {
    DomainError::Forbidden("审计追加的原密钥、租户、Agent 或当前权限已失效".into())
}

pub(super) async fn lock(tx: &mut TenantTransaction<'_>, principal: &Principal, agent: Id) -> DomainResult<()> {
    let key = principal.subject_id.ok_or_else(denied)?;
    if principal.subject_kind != SubjectKind::ApiKey
        || principal.identity_tenant != tx.tenant()
        || principal.tenant != tx.tenant()
        || principal.agent_id != Some(agent)
    {
        return Err(denied());
    }
    // 与资产/AgentTeams 治理采用相同的租户锁，禁止并发新增映射恢复宽权限。
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("agf.asset-governance:{}", tx.tenant()))
        .execute(&mut **tx)
        .await
        .map_err(|error| agf_storage::map_sqlx_err("audit_anchor_governance_fence", &error))?;
    let active: bool = sqlx::query_scalar("SELECT agf_agentteams_lock_tenant()")
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| agf_storage::map_sqlx_err("audit_anchor_tenant_fence", &error))?;
    if !active {
        return Err(denied());
    }
    let bound: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM api_keys WHERE tenant_id=$1 AND id=$2 AND bound_agent_id=$3 AND NOT revoked AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE")
        .bind(tx.tenant().as_uuid()).bind(key.as_uuid()).bind(agent.as_uuid()).fetch_optional(&mut **tx).await
        .map_err(|error|agf_storage::map_sqlx_err("audit_anchor_key_fence",&error))?;
    if bound.is_none() {
        return Err(denied());
    }
    let asset: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT id FROM assets WHERE tenant_id=$1 AND id=$2 AND kind::text='agent' AND deleted_at IS NULL FOR SHARE",
    )
    .bind(tx.tenant().as_uuid())
    .bind(agent.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| agf_storage::map_sqlx_err("audit_anchor_agent_fence", &error))?;
    if asset.is_none() {
        return Err(denied());
    }
    let cloud = crate::integration_store::id(tx.tenant(), crate::cloud_inventory::NAME);
    // 当前权限约束引用的连接、盘点、映射与角色都必须保持到提交；读取包括墓碑。
    let dependencies: Vec<(uuid::Uuid,String)> = sqlx::query_as("SELECT id,kind FROM console_configurations WHERE tenant_id=$1 AND ((kind=$2 AND id=$3) OR (kind='cloud-inventory' AND id=$3) OR (kind='agentteams-role-governance' AND id=$4)) ORDER BY kind,id FOR SHARE")
        .bind(tx.tenant().as_uuid()).bind(crate::cloud_store::KIND).bind(cloud.as_uuid()).bind(agent.as_uuid())
        .fetch_all(&mut **tx).await.map_err(|error|agf_storage::map_sqlx_err("audit_anchor_mapping_fence",&error))?;
    if dependencies.iter().any(|(_, kind)| kind == "agentteams-role-governance") {
        let roles: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM roles WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY id LIMIT 513 FOR SHARE",
        )
        .bind(tx.tenant().as_uuid())
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| agf_storage::map_sqlx_err("audit_anchor_role_fence", &error))?;
        if roles.len() > 512 {
            return Err(denied());
        }
    }
    Ok(())
}

pub(super) async fn authorize(state: &AppState, original: &Principal, agent: Id) -> DomainResult<()> {
    if original.subject_kind != SubjectKind::ApiKey
        || original.agent_id != Some(agent)
        || original.identity_tenant != original.tenant
    {
        return Err(denied());
    }
    // 重新使用既有 CIDR、当前 scopes 与治理交集校验；不得回用入口 Principal 的旧 scopes。
    let current = crate::soar_workflow::Actor::from_principal(original)?
        .resolve_for(state, original.tenant, "policies", "read")
        .await?;
    if current.subject_id != original.subject_id
        || current.agent_id != Some(agent)
        || current.identity_tenant != original.identity_tenant
    {
        return Err(denied());
    }
    Ok(())
}

/// 原事务已取得租户治理、租户状态及绑定资产围栏；当前权限也必须通过同一连接重核。
pub(super) async fn authorize_transaction(
    state: &AppState,
    tx: &mut TenantTransaction<'_>,
    original: &Principal,
    agent: Id,
) -> DomainResult<()> {
    if original.subject_kind != SubjectKind::ApiKey
        || original.agent_id != Some(agent)
        || original.identity_tenant != original.tenant
        || original.tenant != tx.tenant()
    {
        return Err(denied());
    }
    crate::store::asset_transaction::authorize_transaction(state, tx, original).await
}
