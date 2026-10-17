//! Persist known outcomes before atomically publishing a terminal receipt and audit.
use super::*;
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    ids::deterministic_id,
};
use agf_storage::configuration::{ConditionalMutation, ConfigurationGuard, MutationDecision};

const PENDING: &str = "integration-completion";

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Pending {
    pub run: Run,
    audit: AuditLog,
}

pub(super) async fn pending(state: &AppState, tenant: TenantId, run: &Run) -> DomainResult<Option<Pending>> {
    let pending = state.configurations.get::<Pending>(tenant, PENDING, run.id).await?;
    if let Some(pending) = &pending {
        matches_claim(run, &pending.run)?;
        if pending.audit.tenant_id != tenant || pending.run.finished_at.is_none() || pending.run.result.is_none() {
            return Err(DomainError::Config("待发布集成回执不完整或租户绑定不一致".into()));
        }
        // Verify the tenant AAD and ciphertext before any local recovery publication.
        response(state, tenant, &pending.run)?;
    }
    Ok(pending)
}

pub(super) fn pending_metadata(value: &mut Value, pending: &Pending) {
    value["provider_status"] = Value::String(pending.run.status.clone());
    value["status"] = Value::String("uncertain".into());
    value["finished_at"] = Value::Null;
    value["completion_state"] = Value::String("pending_audit".into());
}

pub(super) async fn finish(state: AppState, tenant: TenantId, run: Run, actor: AuditActor) -> DomainResult<Run> {
    let audit = audit(tenant, &run, actor);
    // Only this owned local stage is detached: the borrowed provider future is never spawned.
    join(tokio::spawn(async move {
        let pending = stage(&state, tenant, Pending { run, audit }).await?;
        publish(&state, tenant, &pending).await
    }))
    .await
}

pub(super) async fn resume(state: AppState, tenant: TenantId, pending: Pending) -> DomainResult<Run> {
    join(tokio::spawn(async move { publish(&state, tenant, &pending).await })).await
}

async fn join(task: tokio::task::JoinHandle<DomainResult<Run>>) -> DomainResult<Run> {
    task.await
        .map_err(|_| DomainError::Internal("本地回执完成任务中断；请读取回执并恢复本地发布，不能重发远端操作".into()))?
}

async fn stage(state: &AppState, tenant: TenantId, candidate: Pending) -> DomainResult<Pending> {
    let (stored, _) = state
        .configurations
        .mutate_conditional_audited::<Option<Pending>, _, _>(
            tenant,
            ConditionalMutation {
                kind: PENDING,
                id: candidate.run.id,
                guard: Some(ConfigurationGuard { kind: RUNS, id: candidate.run.id }),
            },
            |guard, current| {
                let prior: Run = guard
                    .map(serde_json::from_value)
                    .transpose()?
                    .ok_or_else(|| DomainError::Conflict("调用领取记录不存在".into()))?;
                matches_claim(&prior, &candidate.run)?;
                if let Some(stored) = current {
                    matches_claim(&stored.run, &candidate.run)?;
                    return Ok(MutationDecision::Unchanged);
                }
                *current = Some(candidate.clone());
                Ok(MutationDecision::Write(None))
            },
            |_| Err(DomainError::Internal("回执暂存不得追加审计".into())),
        )
        .await?;
    stored.ok_or_else(|| DomainError::Conflict("待发布集成回执不存在".into()))
}

async fn publish(state: &AppState, tenant: TenantId, pending: &Pending) -> DomainResult<Run> {
    let (published, sealed) = state
        .configurations
        .mutate_conditional_audited::<Option<Run>, _, _>(
            tenant,
            ConditionalMutation { kind: RUNS, id: pending.run.id, guard: None },
            |_, current| {
                let prior = current.as_mut().ok_or_else(|| DomainError::Conflict("调用领取记录不存在".into()))?;
                matches_claim(prior, &pending.run)?;
                if prior.finished_at.is_some() {
                    return Ok(MutationDecision::Unchanged);
                }
                prior.clone_from(&pending.run);
                Ok(MutationDecision::Write(Some(Box::new(pending.audit.clone()))))
            },
            |audit| state.store.audit_append(audit).map(Some),
        )
        .await?;
    if state.store.database().is_some() {
        if let Some(sealed) = sealed {
            if let Err(error) = state.store.hydrate_audit(&sealed) {
                tracing::warn!(%error, "已提交的集成操作审计投影刷新失败");
            }
        }
    }
    let published = published.ok_or_else(|| DomainError::Conflict("调用记录不存在".into()))?;
    // The committed terminal run is now the receipt authority. Cleanup must not turn
    // that committed success into a failed HTTP result or remove an unfinished claim.
    if let Err(error) = state.configurations.delete(tenant, PENDING, published.id).await {
        tracing::warn!(%error, "已完成的集成回执暂存记录清理失败");
    }
    Ok(published)
}

pub(super) fn matches_claim(prior: &Run, candidate: &Run) -> DomainResult<()> {
    let same_identity = prior.id == candidate.id && prior.request_id == candidate.request_id;
    let same_operation = prior.adapter == candidate.adapter && prior.operation == candidate.operation;
    let same_configuration =
        prior.configuration_version == candidate.configuration_version && prior.mocked == candidate.mocked;
    if !same_identity || !same_operation || !same_configuration || prior.request_hash != candidate.request_hash {
        return Err(DomainError::Conflict("同一请求编号不能用于不同调用".into()));
    }
    Ok(())
}

fn audit(tenant: TenantId, run: &Run, actor: AuditActor) -> AuditLog {
    let mut audit = AppState::audit_entry(
        tenant,
        AuditAction::Execute,
        if run.status == "succeeded" { AuditOutcome::Success } else { AuditOutcome::Failure },
        actor,
        AuditTarget::new(RUNS, Some(run.id.to_string()), Some(run.adapter.clone())),
        "集成操作终态与加密回执已发布；uncertain 表示远端结果未知，禁止盲目重发",
    );
    audit.id = deterministic_id("agf.integration.completion.audit", &format!("{tenant}:{}", run.id));
    audit.request_id = Some(run.request_id.to_string());
    audit.after = Some(serde_json::json!({
        "run_id":run.id,"request_id":run.request_id,"adapter":run.adapter,
        "operation":run.operation,"configuration_version":run.configuration_version,
        "mocked":run.mocked,"status":run.status,
    }));
    audit
}
