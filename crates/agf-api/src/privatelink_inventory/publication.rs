//! Endpoint observation, encrypted topology, terminal receipt and audit commit together.
use super::{
    KIND, assets,
    contract::{Record, Run, Snapshot},
    guard, scope, store, store_sql,
};
use crate::{
    Principal, cloud_store,
    integration_store::Stored,
    model_gateway,
    state::AppState,
    store::{asset_transaction::AssetTransaction, privatelink_discovery::merge_observation},
};
use agf_asset::service::AssetBackend;
use agf_core::{
    asset::Asset,
    audit::{AuditAction, AuditLog, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};
use agf_storage::{
    configuration::{ConditionalMutation, ConfigurationGuard, MutationDecision},
    crypto::FieldCipher,
};
use secrecy::ExposeSecret;
use serde_json::json;
use std::sync::OnceLock;

pub(super) fn snapshot(state: &AppState, tenant: TenantId, row: &Record) -> DomainResult<Option<Snapshot>> {
    row.snapshot
        .as_ref()
        .map(|encrypted| {
            let id = crate::integration_store::id(tenant, super::NAME);
            if encrypted.aad.as_deref() != Some(FieldCipher::make_aad(&tenant, &id).as_str()) {
                return Err(DomainError::Crypto("PrivateLink快照的租户绑定不匹配".into()));
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
    let observation = assets::observation(principal.tenant, &mut candidate)?;
    if state.store.database().is_some() {
        return sql(state, principal, run, candidate, observation).await;
    }
    offline(state, principal, run, candidate, observation).await
}

fn complete(state: &AppState, tenant: TenantId, row: &mut Record, run: &Run, candidate: &Snapshot) -> DomainResult<()> {
    store::owns(row, run)?;
    row.snapshot = Some(model_gateway::encrypt(state, tenant, run.scope.cloud_id, serde_json::to_string(candidate)?)?);
    let stored = row.runs.get_mut(&run.request_id).ok_or_else(scope::stale)?;
    stored.status = "succeeded".into();
    stored.finished_at = Some(candidate.checked_at);
    stored.published = true;
    stored.pages_read = candidate.pages_read;
    stored.endpoints_observed = 1;
    stored.zones_observed = candidate.zones.len() as u64;
    stored.security_groups_observed = candidate.security_groups.len() as u64;
    stored.note = "选定端点及两个子列表已完整观察并原子发布；不代表强一致快照、网络可达或授权通过".into();
    row.active = None;
    store::bounded(row)?;
    Ok(())
}

fn audit(principal: &Principal, run: &Run, candidate: &Snapshot) -> AuditLog {
    let mut entry = store::audit(
        principal,
        run.request_id,
        AuditAction::Execute,
        AuditOutcome::Success,
        "PrivateLink观察、资产及拓扑快照已原子发布",
    );
    entry.after = Some(
        json!({"configuration_version":candidate.scope.configuration_version,"mocked":candidate.scope.mocked,
        "endpoints":1,"zones":candidate.zones.len(),"security_groups":candidate.security_groups.len(),"pages":candidate.pages_read,
        "coverage":"selected_endpoint","consistency":"not_strong_snapshot"}),
    );
    entry
}

async fn sql(
    state: &AppState,
    principal: &Principal,
    run: &Run,
    candidate: Snapshot,
    observation: Asset,
) -> DomainResult<()> {
    let tenant = principal.tenant;
    let db = state.store.database().ok_or_else(scope::stale)?;
    let tx = AssetTransaction::begin(db, tenant).await?;
    store_sql::guarded(&tx, state, tenant, &run.scope).await?;
    tx.configuration_lock(KIND, run.scope.cloud_id).await?;
    let mut row = tx.configuration::<Record>(KIND, run.scope.cloud_id).await?.unwrap_or_default();
    store::owns(&row, run)?;
    let deadline = row.active.as_ref().ok_or_else(scope::stale)?.expires_at;
    if !tx.retired_fingerprints(std::slice::from_ref(&observation.fingerprint)).await?.is_empty() {
        return Err(DomainError::Conflict("PrivateLink端点资产已由用户删除；请先显式恢复，原拓扑保持不变".into()));
    }
    let existing = tx.find_by_fingerprint(tenant, &observation.fingerprint).await?;
    let merged = merge_observation(existing, &observation)?;
    complete(state, tenant, &mut row, run, &candidate)?;
    let payload = serde_json::to_value(&row)?;
    tx.upsert(tenant, &merged).await?;
    // Refresh authority after waiting for resource locks, before either snapshot or audit is committed.
    guard::authorize(state, principal, run.submitted_at.unwrap_or(run.started_at)).await?;
    deadline_current(deadline)?;
    tx.configure(KIND, run.scope.cloud_id, Some(payload)).await?;
    tx.audit(audit(principal, run, &candidate)).await?;
    guard::authorize(state, principal, run.submitted_at.unwrap_or(run.started_at)).await?;
    deadline_current(deadline)?;
    tx.commit(&state.store).await
}

async fn offline(
    state: &AppState,
    principal: &Principal,
    run: &Run,
    candidate: Snapshot,
    observation: Asset,
) -> DomainResult<()> {
    if !crate::tenant_directory::get(state, principal.tenant).await?.enabled {
        return Err(DomainError::Forbidden("盘点租户已停用".into()));
    }
    // Submitted authority is checked before this mutex. The synchronous callback cannot await or re-enter ConfigStore.
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
            |value, row: &mut Record| {
                let cloud: Stored = value
                    .map(serde_json::from_value)
                    .transpose()?
                    .filter(|cloud: &Stored| cloud.enabled)
                    .ok_or_else(scope::stale)?;
                if scope::from_row(state, principal.tenant, &cloud)? != run.scope {
                    return Err(scope::stale());
                }
                store::owns(row, run)?;
                let deadline = row.active.as_ref().ok_or_else(scope::stale)?.expires_at;
                prepared.set(deadline).map_err(|_| DomainError::Internal("PrivateLink离线候选重复准备".into()))?;
                complete(state, principal.tenant, row, run, &candidate)?;
                Ok(MutationDecision::Write(Some(Box::new(audit(principal, run, &candidate)))))
            },
            |entry| {
                let deadline =
                    prepared.get().ok_or_else(|| DomainError::Internal("PrivateLink离线发布缺少租约".into()))?;
                deadline_current(*deadline)?;
                state.store.publish_privatelink_discovery_offline(std::slice::from_ref(&observation), entry).map(Some)
            },
        )
        .await?;
    Ok(())
}

fn deadline_current(deadline: Timestamp) -> DomainResult<()> {
    if deadline <= Timestamp::now() {
        return Err(scope::stale());
    }
    Ok(())
}
