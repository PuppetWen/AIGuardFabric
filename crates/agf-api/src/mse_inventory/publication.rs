//! Asset observations, encrypted snapshot, final run and success audit publish atomically.
use super::{
    KIND,
    contract::{Record, Run, Scope, Snapshot},
    guard, scope, store, store_sql,
};
use crate::{
    Principal, cloud_store,
    integration_store::Stored,
    model_gateway,
    state::AppState,
    store::{asset_transaction::AssetTransaction, mse_discovery::merge_observation},
};
use agf_asset::service::AssetBackend;
use agf_core::{
    asset::Asset,
    audit::{AuditAction, AuditLog, AuditOutcome},
    enums::{AssetKind, DiscoverySource},
    error::{DomainError, DomainResult},
    ids::{TenantId, deterministic_id},
};
use agf_storage::{
    configuration::{ConditionalMutation, ConfigurationGuard, MutationDecision},
    crypto::FieldCipher,
};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::OnceLock};

pub(super) fn snapshot(state: &AppState, tenant: TenantId, row: &Record) -> DomainResult<Option<Snapshot>> {
    row.snapshot
        .as_ref()
        .map(|encrypted| {
            let id = crate::integration_store::id(tenant, super::NAME);
            if encrypted.aad.as_deref() != Some(FieldCipher::make_aad(&tenant, &id).as_str()) {
                return Err(DomainError::Crypto("MSE 快照的租户绑定不匹配".into()));
            }
            let plaintext = model_gateway::cipher(state)?.decrypt(encrypted)?;
            Ok(serde_json::from_str(plaintext.expose_secret())?)
        })
        .transpose()
}

pub(super) async fn publish(
    state: &AppState,
    principal: &Principal,
    run: &Run,
    mut candidate: Snapshot,
) -> DomainResult<()> {
    guard::authorize(state, principal, run.submitted_at.unwrap_or(run.started_at)).await?;
    assign_asset_ids(principal.tenant, &mut candidate)?;
    if state.store.database().is_some() {
        return sql(state, principal, run, candidate).await;
    }
    offline(state, principal, run, candidate).await
}

fn assign_asset_ids(tenant: TenantId, snapshot: &mut Snapshot) -> DomainResult<()> {
    for service in &mut snapshot.services {
        let fingerprint = fingerprint(tenant, &snapshot.scope, &service.key)?;
        service.asset_id = Some(deterministic_id("agf.mse.service.asset", &fingerprint));
    }
    Ok(())
}

fn fingerprint(tenant: TenantId, scope: &Scope, key: &str) -> DomainResult<String> {
    let identity = scope::hash(&json!([
        tenant,
        scope.source_identity,
        scope.region,
        scope.instance_id,
        scope.namespace_id,
        scope.mocked,
        key
    ]))?;
    Ok(format!("mse-service:{identity}"))
}

fn same_source(left: &Scope, right: &Scope) -> bool {
    left.cloud_id == right.cloud_id
        && left.source_identity == right.source_identity
        && left.region == right.region
        && left.instance_id == right.instance_id
        && left.namespace_id == right.namespace_id
        && left.mocked == right.mocked
}

fn observations(tenant: TenantId, current: &Snapshot, previous: Option<&Snapshot>) -> DomainResult<Vec<Asset>> {
    let mut assets = Vec::new();
    let mut keys = BTreeSet::new();
    for service in &current.services {
        if !keys.insert(service.key.clone()) {
            return Err(scope::stale());
        }
        let mut asset = base_asset(tenant, current, service)?;
        asset.attributes.extend([
            ("mse_name".into(), json!(service.name)),
            ("mse_group".into(), json!(service.group)),
            ("mse_instance_count".into(), json!(service.instance_count)),
            ("mse_healthy_count".into(), json!(service.healthy_count)),
            ("mse_cluster_count".into(), json!(service.cluster_count)),
            ("mse_source".into(), json!(service.source)),
            ("mse_observed".into(), json!(true)),
        ]);
        assets.push(asset);
    }
    if let Some(previous) = previous.filter(|previous| same_source(&previous.scope, &current.scope)) {
        for service in &previous.services {
            if !keys.contains(&service.key) {
                let mut asset = base_asset(tenant, current, service)?;
                asset.attributes.insert("mse_observed".into(), json!(false));
                for field in ["mse_instance_count", "mse_healthy_count", "mse_cluster_count", "mse_source"] {
                    asset.attributes.insert(field.into(), Value::Null);
                }
                assets.push(asset);
            }
        }
    }
    assets.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    Ok(assets)
}

fn base_asset(tenant: TenantId, snapshot: &Snapshot, service: &super::contract::Service) -> DomainResult<Asset> {
    let fingerprint = fingerprint(tenant, &snapshot.scope, &service.key)?;
    let mut asset = Asset::new(tenant, AssetKind::Other, format!("{} / {}", service.group, service.name), fingerprint);
    asset.id = service.asset_id.ok_or_else(scope::stale)?;
    asset.discovery_source = DiscoverySource::CloudApi;
    asset.vendor = Some("alicloud-mse".into());
    asset.cloud_resource_id = Some(scope::hash(&json!([
        snapshot.scope.instance_id,
        snapshot.scope.namespace_id,
        service.group,
        service.name
    ]))?);
    asset.last_seen_at = Some(snapshot.checked_at);
    asset.updated_at = snapshot.checked_at;
    asset.attributes.extend([
        ("mse_scope_id".into(), json!(snapshot.scope.id)),
        ("mse_source_identity".into(), json!(snapshot.scope.source_identity)),
        ("mse_configuration_version".into(), json!(snapshot.scope.configuration_version)),
        ("mse_region".into(), json!(snapshot.scope.region)),
        ("mse_instance_id".into(), json!(snapshot.scope.instance_id)),
        ("mse_namespace_id".into(), json!(snapshot.scope.namespace_id)),
        ("mse_mocked".into(), json!(snapshot.scope.mocked)),
        ("mse_checked_at".into(), json!(snapshot.checked_at)),
        ("mse_evidence".into(), json!("ListAnsServices")),
    ]);
    Ok(asset)
}

fn complete(state: &AppState, tenant: TenantId, row: &mut Record, run: &Run, candidate: &Snapshot) -> DomainResult<()> {
    store::owns(row, run)?;
    row.snapshot = Some(model_gateway::encrypt(state, tenant, run.scope.cloud_id, serde_json::to_string(candidate)?)?);
    let stored = row.runs.get_mut(&run.request_id).ok_or_else(scope::stale)?;
    stored.status = "succeeded".into();
    stored.finished_at = Some(candidate.checked_at);
    stored.published = true;
    stored.pages_read = candidate.pages_read;
    stored.services_observed = candidate.services.len() as u64;
    stored.note = "已按公开接口完成分页并原子发布本地观察；不代表云端强一致快照".into();
    row.active = None;
    store::bounded(row)?;
    Ok(())
}

fn audit(principal: &Principal, run: &Run, candidate: &Snapshot) -> AuditLog {
    let mut audit = store::audit(
        principal,
        run.request_id,
        AuditAction::Execute,
        AuditOutcome::Success,
        "完整MSE分页观察、资产和快照已原子发布",
    );
    audit.after = Some(json!({"configuration_version":candidate.scope.configuration_version,
        "mocked":candidate.scope.mocked,"services":candidate.services.len(),"pages":candidate.pages_read,
        "coverage":"observed_pages","consistency":"not_strong_snapshot"}));
    audit
}

async fn sql(state: &AppState, principal: &Principal, run: &Run, candidate: Snapshot) -> DomainResult<()> {
    let tenant = principal.tenant;
    let db = state.store.database().ok_or_else(scope::stale)?;
    let tx = AssetTransaction::begin(db, tenant).await?;
    store_sql::guarded(&tx, state, tenant, &run.scope).await?;
    tx.configuration_lock(KIND, run.scope.cloud_id).await?;
    let mut row = tx.configuration::<Record>(KIND, run.scope.cloud_id).await?.unwrap_or_default();
    store::owns(&row, run)?;
    let previous = snapshot(state, tenant, &row)?;
    let observations = observations(tenant, &candidate, previous.as_ref())?;
    let deadline = row.active.as_ref().ok_or_else(scope::stale)?.expires_at;
    let current_fingerprints = observations
        .iter()
        .filter(|asset| asset.attributes["mse_observed"] == true)
        .map(|asset| asset.fingerprint.clone())
        .collect::<Vec<_>>();
    if !tx.retired_fingerprints(&current_fingerprints).await?.is_empty() {
        return Err(DomainError::Conflict(
            "MSE 清单包含已由用户删除的资产；请先显式恢复或核对资产，整批原台账保持不变".into(),
        ));
    }
    complete(state, tenant, &mut row, run, &candidate)?;
    let payload = serde_json::to_value(&row)?;
    for observation in observations {
        let existing = tx.find_by_fingerprint(tenant, &observation.fingerprint).await?;
        if observation.attributes["mse_observed"] == false && existing.is_none() {
            continue;
        }
        let merged = merge_observation(existing, &observation)?;
        tx.upsert(tenant, &merged).await?;
    }
    guard::authorize(state, principal, run.submitted_at.unwrap_or(run.started_at)).await?;
    deadline_current(deadline)?;
    tx.configure(KIND, run.scope.cloud_id, Some(payload)).await?;
    tx.audit(audit(principal, run, &candidate)).await?;
    // Appending the audit can wait on another transaction; authority must still be current afterwards.
    guard::authorize(state, principal, run.submitted_at.unwrap_or(run.started_at)).await?;
    deadline_current(deadline)?;
    tx.commit(&state.store).await
}

async fn offline(state: &AppState, principal: &Principal, run: &Run, candidate: Snapshot) -> DomainResult<()> {
    if !crate::tenant_directory::get(state, principal.tenant).await?.enabled {
        return Err(DomainError::Forbidden("盘点租户已停用".into()));
    }
    // The callback borrows only the prepared observations. It cannot await or re-enter ConfigStore.
    let prepared = OnceLock::new();
    state
        .configurations
        .mutate_conditional_audited(
            principal.tenant,
            ConditionalMutation {
                kind: KIND,
                id: run.scope.cloud_id,
                guard: Some(ConfigurationGuard { kind: cloud_store::KIND, id: run.scope.cloud_id }),
            },
            |guard, row: &mut Record| {
                let cloud: Stored = guard
                    .map(serde_json::from_value)
                    .transpose()?
                    .filter(|cloud: &Stored| cloud.enabled)
                    .ok_or_else(scope::stale)?;
                if scope::from_row(state, principal.tenant, &cloud)? != run.scope {
                    return Err(scope::stale());
                }
                store::owns(row, run)?;
                let previous = snapshot(state, principal.tenant, row)?;
                let observations = observations(principal.tenant, &candidate, previous.as_ref())?;
                let deadline = row.active.as_ref().ok_or_else(scope::stale)?.expires_at;
                prepared
                    .set((observations, deadline))
                    .map_err(|_| DomainError::Internal("MSE 离线发布候选已准备".into()))?;
                complete(state, principal.tenant, row, run, &candidate)?;
                Ok(MutationDecision::Write(Some(Box::new(audit(principal, run, &candidate)))))
            },
            |entry| {
                let (observations, deadline) =
                    prepared.get().ok_or_else(|| DomainError::Internal("MSE 离线发布缺少候选".into()))?;
                deadline_current(*deadline)?;
                state.store.publish_mse_discovery_offline(observations, entry).map(Some)
            },
        )
        .await?;
    Ok(())
}

fn deadline_current(deadline: agf_core::time::Timestamp) -> DomainResult<()> {
    if deadline <= agf_core::time::Timestamp::now() {
        return Err(scope::stale());
    }
    Ok(())
}
