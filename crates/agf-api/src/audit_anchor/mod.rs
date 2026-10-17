//! 已认证 Agent 的检查点，以及管理链的周期性锚定。
use crate::{AppState, Principal};
use agf_core::{
    audit::{AgentAuditAcknowledgement, AgentAuditBatch},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use agf_storage::audit_anchor::{self as storage, AnchoredChainVerification, AuditAnchorSigner, AuditWitness};
use std::path::Path;

mod authority;
mod offline;
pub mod routes;

fn signer(state: &AppState) -> DomainResult<AuditAnchorSigner> {
    AuditAnchorSigner::from_base64(&state.config.security.master_key_b64)
}

/// 先提交 Agent 批次，再推进持久外部见证，最后返回确认。
///
/// # Errors
/// 路由执行认证；存储、签名或见证失败时拒绝返回成功确认。
pub(crate) async fn append_agent(
    state: &AppState,
    principal: &Principal,
    agent: Id,
    batch: AgentAuditBatch,
) -> DomainResult<AgentAuditAcknowledgement> {
    let tenant = principal.tenant;
    let signer = signer(state)?;
    if let Some(store) = state.store.database() {
        let witness = AuditWitness::acquire(Path::new(&state.config.data_dir), tenant, Some(agent))?;
        let previous = witness.read()?;
        let mut tx = store.db().begin_tenant(tenant).await?;
        storage::lock_agent_chain(&mut tx, agent).await?;
        authority::lock(&mut tx, principal, agent).await?;
        authority::authorize_transaction(state, &mut tx, principal, agent).await?;
        let ack = storage::append_agent(&mut tx, &signer, agent, &batch, previous.as_ref()).await?;
        authority::authorize_transaction(state, &mut tx, principal, agent).await?;
        tx.commit().await?;
        witness.advance(&ack.checkpoint)?;
        return Ok(ack);
    }
    authority::authorize(state, principal, agent).await?;
    offline::append(state, &signer, tenant, agent, batch).await
}

/// 验证管理链哈希及签名检查点，不隐式创建检查点。
///
/// # Errors
/// 配置的持久见证、签名或数据库操作无效。
pub async fn verify_management(state: &AppState, tenant: TenantId) -> DomainResult<AnchoredChainVerification> {
    let signer = signer(state)?;
    if let Some(store) = state.store.database() {
        let witness = AuditWitness::acquire(Path::new(&state.config.data_dir), tenant, None)?;
        let previous = witness.read()?;
        let mut tx = store.db().begin_tenant(tenant).await?;
        let report = storage::verify_management(&mut tx, &signer, previous.as_ref()).await?;
        tx.commit().await?;
        return Ok(report);
    }
    offline::verify(state, &signer, tenant).await
}

async fn checkpoint_management(state: &AppState, tenant: TenantId) -> DomainResult<()> {
    let signer = signer(state)?;
    if let Some(store) = state.store.database() {
        let witness = AuditWitness::acquire(Path::new(&state.config.data_dir), tenant, None)?;
        let previous = witness.read()?;
        let mut tx = store.db().begin_tenant(tenant).await?;
        let checkpoint = storage::checkpoint_management(&mut tx, &signer, previous.as_ref()).await?;
        tx.commit().await?;
        witness.advance(&checkpoint)?;
    } else {
        offline::checkpoint(state, &signer, tenant).await?;
    }
    Ok(())
}

/// 定期仅为已启用租户的已提交审计记录建立检查点。
/// 记录检查点失败，且绝不因此推进外部见证。
pub async fn run_loop(state: AppState) {
    let mut timer = tokio::time::interval(std::time::Duration::from_mins(1));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        match crate::tenant_directory::list(&state).await {
            Ok(tenants) => {
                for tenant in tenants.into_iter().filter(|entry| entry.enabled) {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(50),
                        checkpoint_management(&state, tenant.id),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::error!(tenant=%tenant.id,%error,"Audit checkpoint rejected; witness unchanged");
                        }
                        Err(_) => tracing::error!(tenant=%tenant.id,"Audit checkpoint timed out; witness unchanged"),
                    }
                }
            }
            Err(error) => tracing::error!(%error,"Audit checkpoint tenant directory unavailable"),
        }
    }
}

fn invalid() -> DomainError {
    DomainError::Crypto("Audit checkpoint does not match its authenticated chain".into())
}
