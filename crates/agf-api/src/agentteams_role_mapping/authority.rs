use super::*;
use crate::{
    cloud_inventory::Snapshot,
    integration_store::{Stored, decrypt, id},
};
mod transaction;
pub(crate) use transaction::constrain_key_transaction;

pub(super) fn intersection(key: &[Permission], role: &[Permission]) -> Vec<Permission> {
    let mut scopes = BTreeSet::new();
    for own in key {
        for governed in role {
            if own.matches(governed) {
                scopes.insert(governed.clone());
            } else if governed.matches(own) {
                scopes.insert(own.clone());
            }
        }
    }
    scopes.into_iter().collect()
}
pub(super) fn constrain(
    tenant: TenantId,
    key: &ApiKey,
    asset: &Asset,
    record: Option<&model::Record>,
    cfg: Option<&Stored>,
    snapshot: Option<&Snapshot>,
    role: Option<&RoleEntry>,
    mocked: bool,
) -> DomainResult<Vec<Permission>> {
    if key.tenant_id != tenant || key.bound_agent_id != Some(asset.id) {
        return Err(denied());
    }
    let marker = asset.attributes.get(MARKER);
    if record.is_none() && marker.is_none() {
        return Ok(key.scopes.clone());
    }
    // Either durable marker is sufficient to prohibit falling back to original broad scopes.
    let row = record.ok_or_else(denied)?;
    if marker != Some(&Value::Bool(true))
        || !row.governed
        || row.tenant != tenant
        || row.asset_id != asset.id
        || row.eligibility != model::Eligibility::Eligible
    {
        return Err(denied());
    }
    let (cfg, snapshot, role) = (cfg.ok_or_else(denied)?, snapshot.ok_or_else(denied)?, role.ok_or_else(denied)?);
    proof::current(&row.proof, tenant, cfg, snapshot, asset, role, mocked)?;
    Ok(intersection(&key.scopes, &role.permissions))
}

/// No caller Agent hint participates here. Unbound or unmanaged Keys retain their existing grants.
///
/// This is a current-read authority snapshot, not a substitute for a handler's final transaction fence.
pub(crate) async fn constrain_key(state: &AppState, tenant: TenantId, key: &ApiKey) -> DomainResult<Vec<Permission>> {
    if key.tenant_id != tenant {
        return Err(denied());
    }
    let Some(agent_id) = key.bound_agent_id else {
        return Ok(key.scopes.clone());
    };
    let asset = state.store.asset_get_durable(tenant, agent_id).await?.ok_or_else(denied)?;
    let Some(db) = state.store.database() else {
        if asset.attributes.contains_key(MARKER) {
            return Err(denied());
        }
        return Ok(key.scopes.clone());
    };
    let cloud_id = id(tenant, crate::cloud_inventory::NAME);
    let mut tx = db.db().begin_tenant(tenant).await?;
    // One statement sees the mapping, connection, inventory and role catalog at one SQL snapshot.
    // Read the row even when soft-deleted: deletion is not permission restoration.
    let data: Value = sqlx::query_scalar("SELECT jsonb_build_object(
        'mapping',(SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3),
        'mapping_deleted',(SELECT deleted_at IS NOT NULL FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3),
        'cloud',(SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$4 AND id=$5 AND deleted_at IS NULL),
        'inventory',(SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind='cloud-inventory' AND id=$5 AND deleted_at IS NULL),
        'roles',COALESCE((SELECT jsonb_agg(r) FROM (SELECT id,tenant_id,name,display_name,permissions,builtin FROM roles
        WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY id LIMIT 513) r),'[]'::jsonb))")
        .bind(tenant.as_uuid()).bind(KIND).bind(agent_id.as_uuid()).bind(crate::cloud_store::KIND)
        .bind(cloud_id.as_uuid()).fetch_one(&mut *tx).await
        .map_err(|error| agf_storage::map_sqlx_err("agentteams_role_authority", &error))?;
    if data["mapping"].is_null() {
        return constrain(tenant, key, &asset, None, None, None, None, false);
    }
    if data["mapping_deleted"] != false {
        return Err(denied());
    }
    let sealed: model::Sealed = serde_json::from_value(data["mapping"].clone())?;
    let record = codec::record(state, tenant, agent_id, &sealed)?;
    let cfg: Stored = serde_json::from_value(data["cloud"].clone()).map_err(|_| denied())?;
    let saved: Stored = serde_json::from_value(data["inventory"].clone()).map_err(|_| denied())?;
    let snapshot: Snapshot =
        serde_json::from_value(decrypt(state, tenant, &saved)?.settings.get("snapshot").cloned().ok_or_else(denied)?)
            .map_err(|_| denied())?;
    let roles: Vec<RoleEntry> = serde_json::from_value(data["roles"].clone())?;
    if roles.len() > 512 || saved.id != cloud_id || saved.version != cfg.version {
        return Err(denied());
    }
    let role = roles.iter().find(|role| role.id == record.proof.role_id);
    // A concurrent identity/classification change cannot be hidden by the earlier SQL statement.
    let latest_asset = state.store.asset_get_durable(tenant, agent_id).await?.ok_or_else(denied)?;
    if model::AgentIdentity::capture(tenant, &latest_asset)? != model::AgentIdentity::capture(tenant, &asset)?
        || latest_asset.attributes.get(MARKER) != asset.attributes.get(MARKER)
    {
        return Err(denied());
    }
    constrain(
        tenant,
        key,
        &latest_asset,
        Some(&record),
        Some(&cfg),
        Some(&snapshot),
        role,
        state.config.mock_mode || cfg.mock,
    )
}
