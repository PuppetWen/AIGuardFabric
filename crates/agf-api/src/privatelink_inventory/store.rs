//! Stable request claims and monotonic fencing prevent old or cancelled listings from publishing.
use super::{
    KIND, LEASE_SECS, MAX_BYTES, MAX_RUNS, archive, archive_store,
    contract::{Lease, Progress, Record, Run, Scope, SyncInput},
    scope, store_sql,
};
use crate::{Principal, cloud_store, integration_store::Stored, state::AppState};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_storage::configuration::{BatchDecision, ConditionalMutation, ConfigurationGuard, MutationDecision};
use serde_json::json;

pub(super) async fn load(state: &AppState, tenant: TenantId) -> DomainResult<Record> {
    Ok(state
        .configurations
        .get(tenant, KIND, crate::integration_store::id(tenant, super::NAME))
        .await?
        .unwrap_or_default())
}

pub(super) async fn get(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Run> {
    if let Some(run) = load(state, tenant).await?.runs.remove(&id) {
        return Ok(run);
    }
    archive::get(state, tenant, id)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "PrivateLink inventory run", id: id.to_string() })
}

pub(super) fn bounded(record: &Record) -> DomainResult<Vec<u8>> {
    let bytes = serde_json::to_vec(record)?;
    if record.runs.len() > MAX_RUNS || bytes.len() > MAX_BYTES {
        return Err(DomainError::PreconditionFailed(
            "PrivateLink 盘点台账达到容量上限（512次请求或4MiB）；请通过请求归档入口显式归档已结束条目，旧编号永久不重派"
                .into(),
        ));
    }
    Ok(bytes)
}

pub(super) fn owns(record: &Record, run: &Run) -> DomainResult<()> {
    let Some(active) = &record.active else {
        return Err(scope::stale());
    };
    let same_claim =
        (active.run_id, active.claim_id, active.generation) == (run.request_id, run.claim_id, run.generation);
    if !same_claim
        || active.expires_at <= Timestamp::now()
        || record.runs.get(&run.request_id).is_none_or(|row| row.status != "running")
    {
        return Err(scope::stale());
    }
    Ok(())
}

pub(super) fn audit(
    principal: &Principal,
    run: Id,
    action: AuditAction,
    outcome: AuditOutcome,
    note: &str,
) -> AuditLog {
    let mut entry = AppState::audit_entry(
        principal.tenant,
        action,
        outcome,
        AppState::audit_actor(principal, "privatelink-inventory"),
        AuditTarget::new("privatelink-inventory-run", Some(run.to_string()), None),
        note,
    );
    entry.request_id = Some(run.to_string());
    entry
}

pub(super) async fn mutate<F>(
    state: &AppState,
    tenant: TenantId,
    expected: Option<&Scope>,
    apply: F,
) -> DomainResult<Record>
where
    F: FnOnce(&mut Record) -> DomainResult<Option<AuditLog>> + Send,
{
    if state.store.database().is_some() {
        return store_sql::mutate(state, tenant, expected, apply).await;
    }
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Err(DomainError::Forbidden("租户已停用".into()));
    }
    let id = crate::integration_store::id(tenant, super::NAME);
    let (record, _) = state
        .configurations
        .mutate_conditional_audited(
            tenant,
            ConditionalMutation {
                kind: KIND,
                id,
                guard: expected.map(|scope| ConfigurationGuard { kind: cloud_store::KIND, id: scope.cloud_id }),
            },
            |guard, record: &mut Record| {
                if let Some(expected) = expected {
                    let cloud: Stored = guard
                        .map(serde_json::from_value)
                        .transpose()?
                        .filter(|cloud: &Stored| cloud.enabled)
                        .ok_or_else(scope::stale)?;
                    if scope::from_row(state, tenant, &cloud)? != *expected {
                        return Err(scope::stale());
                    }
                }
                let before = serde_json::to_vec(record)?;
                let audit = apply(record)?;
                let after = bounded(record)?;
                Ok(if before == after {
                    MutationDecision::Unchanged
                } else {
                    MutationDecision::Write(audit.map(Box::new))
                })
            },
            |entry| state.store.audit_append(entry).map(Some),
        )
        .await?;
    Ok(record)
}

pub(super) async fn claim(
    state: &AppState,
    principal: &Principal,
    scope: &Scope,
    input: &SyncInput,
    submitted_at: Timestamp,
) -> DomainResult<(Run, bool)> {
    let hash = scope::hash(&json!({"input":input,"scope":scope}))?;
    let mut created = false;
    let mut archived_replay = None;
    let record =
        archive_store::mutate(state, principal, Some(scope), &[input.request_id], submitted_at, |record, archived| {
            if let Some(old) = archived.get(&input.request_id).and_then(Option::as_ref) {
                let run = archive::as_run(principal.tenant, input.request_id, old)?;
                if run.request_hash != hash {
                    return Err(archive::archived_conflict());
                }
                archived_replay = Some(run);
                return Ok(BatchDecision::Unchanged);
            }
            if let Some(old) = record.runs.get(&input.request_id) {
                if old.request_hash != hash {
                    return Err(DomainError::Conflict("同一PrivateLink盘点请求编号不能用于不同参数或范围".into()));
                }
                return Ok(BatchDecision::Unchanged);
            }
            let now = Timestamp::now();
            if let Some(active) = &record.active {
                let old = record.runs.get_mut(&active.run_id).ok_or_else(scope::stale)?;
                if active.expires_at > now && old.scope.id == scope.id {
                    return Err(DomainError::Conflict("该PrivateLink连接已有盘点进行中，请等待或取消原请求".into()));
                }
                old.status = if old.scope.id == scope.id { "interrupted" } else { "superseded" }.into();
                old.finished_at = Some(now);
                old.note = "旧租约或范围失效，旧请求不会再次派发".into();
            }
            let generation = record.generation.checked_add(1).ok_or_else(scope::stale)?;
            let run = Run {
                request_id: input.request_id,
                request_hash: hash,
                scope: scope.clone(),
                claim_id: Id::new(),
                generation,
                status: "running".into(),
                started_at: now,
                submitted_at: Some(submitted_at),
                finished_at: None,
                pages_read: 0,
                endpoints_observed: 0,
                zones_observed: 0,
                security_groups_observed: 0,
                published: false,
                note: "正在读取选定端点及两个子列表；尚未发布拓扑".into(),
                archived: false,
                archived_at: None,
                original_status: None,
            };
            record.active = Some(Lease {
                run_id: run.request_id,
                claim_id: run.claim_id,
                generation,
                expires_at: now.offset_secs(LEASE_SECS),
            });
            record.generation = generation;
            record.runs.insert(run.request_id, run);
            created = true;
            Ok(BatchDecision::Write {
                related: std::collections::BTreeMap::new(),
                audit: Some(Box::new(audit(
                    principal,
                    input.request_id,
                    AuditAction::Create,
                    AuditOutcome::Success,
                    "领取PrivateLink只读盘点请求；未发布资产",
                ))),
            })
        })
        .await?;
    let run = archived_replay.or_else(|| record.runs.get(&input.request_id).cloned()).ok_or_else(scope::stale)?;
    Ok((run, created))
}

pub(super) async fn progress(state: &AppState, tenant: TenantId, run: &Run, progress: &Progress) -> DomainResult<()> {
    mutate(state, tenant, Some(&run.scope), |record| {
        owns(record, run)?;
        let value = record.runs.get_mut(&run.request_id).ok_or_else(scope::stale)?;
        value.pages_read = progress.pages_read;
        value.endpoints_observed = progress.endpoints_observed;
        value.zones_observed = progress.zones_observed;
        value.security_groups_observed = progress.security_groups_observed;
        Ok(None)
    })
    .await?;
    Ok(())
}

pub(super) async fn cancel(
    state: &AppState,
    principal: &Principal,
    id: Id,
    submitted_at: Timestamp,
) -> DomainResult<Run> {
    // Explicit user cancellation shares the authorized mutation path; internal failure cleanup does not.
    let record = archive_store::mutate(state, principal, None, &[], submitted_at, |record, _| {
        let run = record
            .runs
            .get_mut(&id)
            .ok_or_else(|| DomainError::NotFound { entity: "PrivateLink inventory run", id: id.to_string() })?;
        if run.status != "running" {
            return Ok(BatchDecision::Unchanged);
        }
        run.status = "cancelled".into();
        run.finished_at = Some(Timestamp::now());
        run.note = "已取消后续读取和台账发布；已发送的只读请求不能撤回".into();
        if record.active.as_ref().is_some_and(|active| active.run_id == id) {
            record.active = None;
        }
        Ok(BatchDecision::Write {
            related: std::collections::BTreeMap::new(),
            audit: Some(Box::new(audit(
                principal,
                id,
                AuditAction::Update,
                AuditOutcome::Success,
                "取消PrivateLink盘点；保留原台账",
            ))),
        })
    })
    .await?;
    record.runs.get(&id).cloned().ok_or_else(scope::stale)
}

pub(super) async fn failed(
    state: &AppState,
    principal: &Principal,
    run: &Run,
    status: &str,
    note: &str,
) -> DomainResult<()> {
    mutate(state, principal.tenant, None, |record| {
        let Some(value) = record.runs.get_mut(&run.request_id).filter(|value| value.status == "running") else {
            return Ok(None);
        };
        value.status = status.into();
        value.finished_at = Some(Timestamp::now());
        value.note = note.into();
        if record
            .active
            .as_ref()
            .is_some_and(|active| (active.run_id, active.claim_id) == (run.request_id, run.claim_id))
        {
            record.active = None;
        }
        Ok(Some(audit(principal, run.request_id, AuditAction::Execute, AuditOutcome::Failure, note)))
    })
    .await?;
    Ok(())
}
