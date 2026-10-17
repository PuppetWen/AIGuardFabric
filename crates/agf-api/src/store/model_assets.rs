//! Model endpoint configuration and its inventory projection commit together.
use super::asset_transaction::AssetTransaction;
use super::*;
use crate::{
    model_gateway::{ENDPOINT_KIND, StoredEndpoint},
    state::AppState,
};
use agf_core::enums::{AssetKind, LlmProvider};
use serde_json::json;

fn project(existing: Option<Asset>, tenant: TenantId, record: &StoredEndpoint, mocked: bool) -> DomainResult<Asset> {
    let endpoint = &record.endpoint;
    let id = endpoint.id;
    if existing.as_ref().is_some_and(|a| a.kind != AssetKind::ModelEndpoint) {
        return Err(DomainError::Conflict("Model ID belongs to a different asset type".into()));
    }
    let mut asset = existing
        .unwrap_or_else(|| Asset::new(tenant, AssetKind::ModelEndpoint, &endpoint.name, format!("gateway:{id}")));
    asset.id = id;
    asset.name = endpoint.name.clone();
    asset.vendor = Some(endpoint.provider.as_str().into());
    asset.endpoint = Some(endpoint.base_url.clone());
    asset.attributes.insert("model".into(), json!(endpoint.model));
    asset.attributes.insert("local_deployment".into(), json!(endpoint.local_deployment));
    asset.attributes.insert("mock_mode".into(), json!(mocked || endpoint.provider == LlmProvider::Mock));
    asset.attributes.insert("enabled".into(), json!(endpoint.enabled));
    asset.updated_at = Timestamp::now();
    Ok(asset)
}

fn check_version(current: Option<&StoredEndpoint>, expected: u64) -> DomainResult<()> {
    if current.map_or(0, |record| record.version) != expected {
        return Err(DomainError::Conflict("模型端点已被其他人修改，请重新加载后合并变更".into()));
    }
    Ok(())
}

pub(crate) async fn save(
    state: &AppState,
    tenant: TenantId,
    record: &StoredEndpoint,
    expected: u64,
    audit: AuditLog,
) -> DomainResult<()> {
    let id = record.endpoint.id;
    if record.endpoint.tenant_id != tenant || audit.tenant_id != tenant {
        return Err(DomainError::TenantViolation { tenant: tenant.to_string(), resource: id.to_string() });
    }
    if expected.checked_add(1) != Some(record.version) {
        return Err(DomainError::Conflict("模型端点版本无效，请重新加载".into()));
    }
    if let Some(db) = state.store.database() {
        let backend = AssetTransaction::begin(db, tenant).await?;
        let current: Option<StoredEndpoint> = backend.configuration(ENDPOINT_KIND, id).await?;
        check_version(current.as_ref(), expected)?;
        let asset = project(backend.find(tenant, id).await?, tenant, record, state.config.mock_mode)?;
        backend.upsert(tenant, &asset).await?;
        backend.configure(ENDPOINT_KIND, id, Some(serde_json::to_value(record)?)).await?;
        backend.audit(audit).await?;
        backend.commit(&state.store).await?;
    } else {
        let _guard = state.model_asset_lock.lock().await;
        let current: Option<StoredEndpoint> = state.configurations.get(tenant, ENDPOINT_KIND, id).await?;
        check_version(current.as_ref(), expected)?;
        project(state.store.asset_get(tenant, id)?, tenant, record, state.config.mock_mode)?;
        state.configurations.put(tenant, ENDPOINT_KIND, id, record).await?;
        state
            .store
            .asset_mutate_durable(tenant, id, |current| {
                Ok((project(current, tenant, record, state.config.mock_mode)?, None))
            })
            .await?;
        state.store.audit_append_durable(audit).await?;
    }
    Ok(())
}

pub(crate) async fn remove(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    expected: u64,
    audit: AuditLog,
) -> DomainResult<()> {
    if audit.tenant_id != tenant {
        return Err(DomainError::TenantViolation { tenant: tenant.to_string(), resource: id.to_string() });
    }
    if let Some(db) = state.store.database() {
        let backend = AssetTransaction::begin(db, tenant).await?;
        let current: Option<StoredEndpoint> = backend.configuration(ENDPOINT_KIND, id).await?;
        let current = current.ok_or_else(|| DomainError::NotFound { entity: "model-endpoint", id: id.to_string() })?;
        check_version(Some(&current), expected)?;
        if let Some(mut asset) = backend.find(tenant, id).await? {
            if asset.kind != AssetKind::ModelEndpoint {
                return Err(DomainError::Conflict("Model ID belongs to a different asset type".into()));
            }
            asset.attributes.insert("enabled".into(), json!(false));
            asset.updated_at = Timestamp::now();
            backend.upsert(tenant, &asset).await?;
        }
        backend.configure(ENDPOINT_KIND, id, None).await?;
        backend.audit(audit).await?;
        backend.commit(&state.store).await?;
    } else {
        let _guard = state.model_asset_lock.lock().await;
        let current: Option<StoredEndpoint> = state.configurations.get(tenant, ENDPOINT_KIND, id).await?;
        let current = current.ok_or_else(|| DomainError::NotFound { entity: "model-endpoint", id: id.to_string() })?;
        check_version(Some(&current), expected)?;
        if state.store.asset_get(tenant, id)?.is_some_and(|asset| asset.kind != AssetKind::ModelEndpoint) {
            return Err(DomainError::Conflict("Model ID belongs to a different asset type".into()));
        }
        state.configurations.delete(tenant, ENDPOINT_KIND, id).await?;
        if state.store.asset_get(tenant, id)?.is_some() {
            state
                .store
                .asset_mutate_durable(tenant, id, |current| {
                    let mut asset =
                        current.ok_or_else(|| DomainError::NotFound { entity: "model-asset", id: id.to_string() })?;
                    asset.attributes.insert("enabled".into(), json!(false));
                    asset.updated_at = Timestamp::now();
                    Ok((asset, None))
                })
                .await?;
        }
        state.store.audit_append_durable(audit).await?;
    }
    Ok(())
}
