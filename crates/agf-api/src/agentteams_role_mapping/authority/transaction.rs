//! 复用已认证绑定 Key 的既有治理证明，在调用者原事务内求当前权限交集。
use super::*;
use agf_storage::TenantTransaction;

pub(crate) async fn constrain_key_transaction(
    state: &AppState,
    tx: &mut TenantTransaction<'_>,
    key: &ApiKey,
    asset: &Asset,
) -> DomainResult<Vec<Permission>> {
    let tenant = tx.tenant();
    let agent = asset.id;
    let cloud = id(tenant, crate::cloud_inventory::NAME);
    // 调用者持租户治理锁和 Agent 行锁；配置墓碑也必须参与证明，禁止恢复宽权限。
    sqlx::query(
        "SELECT id FROM console_configurations WHERE tenant_id=$1 AND
        ((kind=$2 AND id=$3) OR (kind='cloud-inventory' AND id=$3) OR (kind=$4 AND id=$5))
        ORDER BY kind,id FOR SHARE",
    )
    .bind(tenant.as_uuid())
    .bind(crate::cloud_store::KIND)
    .bind(cloud.as_uuid())
    .bind(KIND)
    .bind(agent.as_uuid())
    .fetch_all(&mut **tx)
    .await
    .map_err(sql)?;
    let data: Value = sqlx::query_scalar("SELECT jsonb_build_object(
        'mapping',(SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3),
        'mapping_deleted',(SELECT deleted_at IS NOT NULL FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3),
        'cloud',(SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$4 AND id=$5 AND deleted_at IS NULL),
        'inventory',(SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind='cloud-inventory' AND id=$5 AND deleted_at IS NULL))")
        .bind(tenant.as_uuid()).bind(KIND).bind(agent.as_uuid()).bind(crate::cloud_store::KIND)
        .bind(cloud.as_uuid()).fetch_one(&mut **tx).await.map_err(sql)?;
    if data["mapping"].is_null() {
        return constrain(tenant, key, asset, None, None, None, None, false);
    }
    if data["mapping_deleted"] != false {
        return Err(denied());
    }
    let sealed: model::Sealed = serde_json::from_value(data["mapping"].clone())?;
    let record = codec::record(state, tenant, agent, &sealed)?;
    let cfg: Stored = serde_json::from_value(data["cloud"].clone()).map_err(|_| denied())?;
    let saved: Stored = serde_json::from_value(data["inventory"].clone()).map_err(|_| denied())?;
    let snapshot: Snapshot =
        serde_json::from_value(decrypt(state, tenant, &saved)?.settings.get("snapshot").cloned().ok_or_else(denied)?)
            .map_err(|_| denied())?;
    if saved.id != cloud || saved.version != cfg.version {
        return Err(denied());
    }
    let roles: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'tenant_id',tenant_id,
        'name',name,'display_name',display_name,'permissions',permissions,'builtin',builtin)
        FROM roles WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY id LIMIT 513 FOR SHARE",
    )
    .bind(tenant.as_uuid())
    .fetch_all(&mut **tx)
    .await
    .map_err(sql)?;
    if roles.len() > 512 {
        return Err(denied());
    }
    let roles: Vec<RoleEntry> = roles.into_iter().map(serde_json::from_value).collect::<Result<_, _>>()?;
    let role = roles.iter().find(|role| role.id == record.proof.role_id);
    constrain(tenant, key, asset, Some(&record), Some(&cfg), Some(&snapshot), role, state.config.mock_mode || cfg.mock)
}

fn sql(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("runtime_agentteams_authority", &error)
}
