//! One model-route configuration and its Configure audit commit together.
use crate::{AppState, model_gateway::StoredEndpoint, store::ModelRoutePolicy};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

mod authority;
mod offline;
mod sql;
#[cfg(test)]
mod tests;
mod validation;
pub(crate) use authority::Submission;

const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
type Rows = BTreeMap<(String, Id), Option<Value>>;

pub(crate) async fn current(
    state: &AppState,
    submission: &Submission,
    id: Id,
) -> DomainResult<Option<ModelRoutePolicy>> {
    submission.authorize(state).await?;
    tokio::time::timeout_at(submission.deadline, async {
        let tenant = submission.principal.tenant;
        let row = state
            .configurations
            .get::<Value>(tenant, super::KIND, id)
            .await?
            .map(serde_json::from_value::<ModelRoutePolicy>)
            .transpose()
            .map_err(|_| corrupt())?;
        let row = match row {
            Some(row) => Some(row),
            None => seed(state, tenant, id)?,
        };
        if let Some(row) = &row {
            validation::identity(row, tenant, id)?;
        }
        submission.budget()?;
        Ok(row)
    })
    .await
    .map_err(|_| expired())?
}

/// No provider action is performed. The deadline covers every lock and audit wait.
pub(crate) async fn save(
    state: &AppState,
    submission: &Submission,
    policy: &ModelRoutePolicy,
    expected: u64,
) -> DomainResult<()> {
    validation::candidate(policy, submission.principal.tenant, expected)?;
    let baseline = if expected == 0 { seed(state, submission.principal.tenant, policy.id)? } else { None };
    tokio::time::timeout_at(submission.deadline, async {
        submission.authorize(state).await?;
        if state.store.database().is_some() {
            Box::pin(sql::save(state, submission, policy, expected, baseline.as_ref())).await
        } else {
            offline::save(state, submission, policy, expected, baseline.as_ref()).await
        }
    })
    .await
    .map_err(|_| expired())??;
    // This cache is a compatibility projection. ConfigStore is authoritative for later saves/reads.
    if let Err(error) = state.store.route_policy_upsert(policy) {
        tracing::warn!(error_kind = error.code(), "Committed route policy projection could not be refreshed");
    }
    Ok(())
}

fn seed(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Option<ModelRoutePolicy>> {
    // The only fallback is the existing, never-persisted version-zero demonstration seed.
    Ok(state.store.route_policy_get(tenant, id)?.filter(|row| row.version == 0))
}

fn compare(current: Option<&ModelRoutePolicy>, seed: Option<&ModelRoutePolicy>, expected: u64) -> DomainResult<()> {
    if current.or(seed).map_or(0, |row| row.version) != expected {
        return Err(DomainError::Conflict("模型路由已被其他人修改，请重新加载后合并变更".into()));
    }
    Ok(())
}

fn audit(submission: &Submission, policy: &ModelRoutePolicy) -> AuditLog {
    let mut log = AppState::audit_entry(
        policy.tenant_id,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(&submission.principal, "model-route-policy-save"),
        AuditTarget::new(super::KIND, Some(policy.id.to_string()), Some(policy.name.clone())),
        "保存模型路由策略，下一请求读取新配置",
    );
    log.after = Some(json!({"version":policy.version,"enabled":policy.enabled,"providerContacted":false}));
    log
}

fn serialized_budget(policy: &ModelRoutePolicy, audit: &AuditLog) -> DomainResult<()> {
    let payload = serde_json::to_value(policy)?;
    if serde_json::to_vec(&payload)?.len() > MAX_POLICY_BYTES {
        return Err(DomainError::PreconditionFailed("模型路由配置超过 64 KiB 编码预算".into()));
    }
    let mut sealed = audit.clone();
    sealed.sequence = i64::MAX;
    sealed.prev_hash = "0".repeat(64);
    sealed.entry_hash = "0".repeat(64);
    let write = json!({"tenant":policy.tenant_id,"kind":super::KIND,"id":policy.id,
        "delete":false,"payload":payload});
    if serde_json::to_vec(&(vec![write], sealed))?.len() > MAX_BATCH_BYTES {
        return Err(DomainError::PreconditionFailed("模型路由写入超过完整批次预算".into()));
    }
    Ok(())
}

fn corrupt() -> DomainError {
    DomainError::Crypto("Stored model-route configuration identity or shape is invalid".into())
}
fn expired() -> DomainError {
    DomainError::Conflict("模型路由提交已超过原时限，请重新加载后确认".into())
}
