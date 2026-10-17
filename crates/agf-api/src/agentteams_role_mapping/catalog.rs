use super::*;

pub(super) fn supported(role: &RoleEntry, tenant: TenantId) -> DomainResult<()> {
    if role.id.is_nil() || role.tenant_id != tenant || !role.builtin {
        return Err(DomainError::Forbidden("仅可选择本租户实际已保存的受支持平台角色".into()));
    }
    // These roles have user/cross-tenant or per-resource ABAC semantics which a flat Key scope cannot express.
    if matches!(role.name.as_str(), "superadmin" | "asset-owner") {
        return Err(DomainError::PreconditionFailed("该角色需要用户/部门资源判定，本期不支持绑定到 Worker Key".into()));
    }
    let definitions = agf_core::rbac::Role::builtin_definitions();
    let Some((_, _, _, permissions)) = definitions.iter().find(|(name, _, _, _)| *name == role.name) else {
        return Err(DomainError::PreconditionFailed("平台角色语义未验证，不能采用".into()));
    };
    let expected: BTreeSet<&str> = permissions.iter().copied().collect();
    let actual: BTreeSet<&str> = role.permissions.iter().map(Permission::as_str).collect();
    if expected != actual {
        return Err(DomainError::Forbidden("平台角色权限已改变，请重新审查角色定义".into()));
    }
    Ok(())
}
pub(super) fn digest(role: &RoleEntry) -> DomainResult<String> {
    let permissions: BTreeSet<&str> = role.permissions.iter().map(Permission::as_str).collect();
    hash(&(role.id, role.tenant_id, &role.name, role.builtin, permissions))
}
pub(super) async fn list(state: &AppState, tenant: TenantId) -> DomainResult<Vec<RoleEntry>> {
    let db = state
        .store
        .database()
        .ok_or_else(|| DomainError::PreconditionFailed("离线认证无真实角色 UUID 目录；新增映射需要数据库".into()))?;
    let mut tx = db.db().begin_tenant(tenant).await?;
    let values: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'tenant_id',tenant_id,'name',name,
        'display_name',display_name,'permissions',permissions,'builtin',builtin) FROM roles
        WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY name,id LIMIT 513",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| agf_storage::map_sqlx_err("agentteams_role_catalog", &error))?;
    if values.len() > 512 {
        return Err(DomainError::PreconditionFailed("角色目录超过 512 项，请缩小管理范围".into()));
    }
    values.into_iter().map(|value| serde_json::from_value(value).map_err(Into::into)).collect()
}
pub(super) async fn mappings(state: &AppState, tenant: TenantId) -> DomainResult<Vec<model::Record>> {
    let db = state.store.database().ok_or_else(denied)?;
    let mut tx = db.db().begin_tenant(tenant).await?;
    let rows: Vec<(uuid::Uuid, Value)> = sqlx::query_as(
        "SELECT id,payload FROM console_configurations
        WHERE tenant_id=$1 AND kind=$2 AND deleted_at IS NULL ORDER BY id LIMIT 513",
    )
    .bind(tenant.as_uuid())
    .bind(KIND)
    .fetch_all(&mut *tx)
    .await
    .map_err(|error| agf_storage::map_sqlx_err("agentteams_role_mappings", &error))?;
    if rows.len() > MAX_WORKERS {
        return Err(DomainError::Crypto("角色治理台账超过上限".into()));
    }
    rows.into_iter()
        .map(|(id, value)| {
            let sealed: model::Sealed = serde_json::from_value(value)?;
            codec::record(state, tenant, Id::from_uuid(id), &sealed)
        })
        .collect()
}
