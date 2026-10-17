//! Persist complete discovery snapshots and hydrate MCP asset projections across API instances.
use super::{
    config::{self, Endpoint},
    invalid,
};
use crate::state::AppState;
use crate::store::asset_transaction::AssetTransaction;
use agf_asset::service::AssetBackend;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, Protocol},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) const KIND: &str = "mcp-http-discovery";

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Snapshot {
    id: Id,
    version: u64,
    observed_at: Timestamp,
    tools: Value,
    server: Value,
}

pub(super) fn project(
    existing: Option<Asset>,
    tenant: TenantId,
    row: &Endpoint,
    snapshot: Option<&Snapshot>,
) -> DomainResult<Asset> {
    if existing.as_ref().is_some_and(|a| a.kind != AssetKind::McpServer) {
        return Err(DomainError::Conflict("MCP ID belongs to another asset type".into()));
    }
    let mut asset =
        existing.unwrap_or_else(|| Asset::new(tenant, AssetKind::McpServer, &row.name, format!("mcp-http:{}", row.id)));
    asset.id = row.id;
    asset.name = row.name.clone();
    asset.endpoint = Some(row.url.clone());
    asset.protocol = Some(match row.transport {
        super::config::Transport::StreamableHttp => Protocol::McpHttp,
        super::config::Transport::LegacySse => Protocol::McpSse,
    });
    asset.attributes.insert("http_gateway".into(), json!(true));
    asset.attributes.insert("transport".into(), json!(row.transport.as_str()));
    asset.attributes.insert("enabled".into(), json!(row.enabled));
    asset.attributes.insert("has_plaintext_secret".into(), json!(false));
    let snapshot = snapshot.filter(|snapshot| snapshot.version == row.version);
    let tools = snapshot.map_or_else(|| json!([]), |row| row.tools.clone());
    asset.attributes.insert("tool_count".into(), json!(snapshot.and_then(|s| s.tools.as_array().map(Vec::len))));
    asset.attributes.insert("tools".into(), tools);
    asset.last_seen_at = if row.enabled { snapshot.map(|row| row.observed_at) } else { None };
    if let Some(snapshot) = snapshot {
        asset.version = snapshot.server.pointer("/serverInfo/version").and_then(Value::as_str).map(str::to_string);
        asset.attributes.insert("mcp_discovered_at".into(), json!(snapshot.observed_at));
    } else {
        asset.version = None;
        asset.attributes.remove("mcp_discovered_at");
    }
    Ok(asset)
}

pub(crate) async fn register(state: &AppState, tenant: TenantId, row: &Endpoint) -> DomainResult<()> {
    let snapshot: Option<Snapshot> = state.configurations.get(tenant, KIND, row.id).await?;
    persist(state, tenant, row, snapshot.as_ref()).await
}

async fn persist(state: &AppState, tenant: TenantId, row: &Endpoint, snapshot: Option<&Snapshot>) -> DomainResult<()> {
    state
        .store
        .asset_mutate_durable(tenant, row.id, |current| Ok((project(current, tenant, row, snapshot)?, None)))
        .await?;
    Ok(())
}

pub(crate) async fn save(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    version: u64,
    server: &Value,
    tools: &Value,
) -> DomainResult<()> {
    let row = config::get(state, tenant, id).await?;
    if row.version != version {
        return Err(DomainError::Conflict("MCP endpoint changed during discovery; run the probe again".into()));
    }
    let tools = tools
        .get("tools")
        .filter(|tools| tools.is_array())
        .ok_or_else(|| invalid("MCP tools/list omitted its tools array"))?;
    let snapshot =
        Snapshot { id, version, observed_at: Timestamp::now(), tools: tools.clone(), server: server.clone() };
    if let Some(db) = state.store.database() {
        let backend = AssetTransaction::begin(db, tenant).await?;
        let registry: config::Registry = backend
            .configuration(config::KIND, crate::model_routes::tenant_record_id(tenant))
            .await?
            .unwrap_or_default();
        let current = registry.entries.get(&id).filter(|current| current.version == version).ok_or_else(|| {
            DomainError::Conflict("MCP endpoint changed during discovery; run the probe again".into())
        })?;
        let asset = project(backend.find(tenant, id).await?, tenant, current, Some(&snapshot))?;
        backend.upsert(tenant, &asset).await?;
        backend.configure(KIND, id, Some(serde_json::to_value(&snapshot)?)).await?;
        return backend.commit(&state.store).await;
    }
    state.configurations.put(tenant, KIND, id, &snapshot).await?;
    persist(state, tenant, &row, Some(&snapshot)).await
}

pub(crate) async fn refresh(state: &AppState, tenant: TenantId) -> DomainResult<()> {
    // SQL projections commit with their configuration; reads must not overwrite them with an older snapshot.
    if state.store.database().is_some() {
        return Ok(());
    }
    let snapshots: Vec<Snapshot> = state.configurations.list(tenant, KIND).await?;
    let snapshots: BTreeMap<_, _> = snapshots.into_iter().map(|snapshot| (snapshot.id, snapshot)).collect();
    for row in config::list(state, tenant).await? {
        let existing = state.store.asset_get_durable(tenant, row.id).await?;
        state.store.remember_asset(&project(existing, tenant, &row, snapshots.get(&row.id))?)?;
    }
    Ok(())
}
