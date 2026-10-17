//! Meter direct MCP red-team probes separately from registered proxy endpoints.
use crate::{mcp_gateway::usage, runtime_quota::Lease, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    quota::QuotaConsumption,
};
use agf_scan::redteam::{ToolCallOutcome, ToolCallReceipt};

pub(super) async fn reserve(
    state: &AppState,
    tenant: TenantId,
    campaign: Id,
    profile: Id,
    tool: String,
) -> DomainResult<ToolCallReceipt> {
    let state = state.clone();
    tokio::spawn(async move { reserve_inner(&state, tenant, campaign, profile, tool).await }).await.map_err(|_| {
        DomainError::DependencyUnavailable {
            dependency: "mcp-tool-meter".into(),
            cause: "Tool reservation task did not complete".into(),
        }
    })?
}

async fn reserve_inner(
    state: &AppState,
    tenant: TenantId,
    campaign: Id,
    profile: Id,
    tool: String,
) -> DomainResult<ToolCallReceipt> {
    let owner = format!("redteam:{campaign}");
    let lease = Lease::acquire(state, tenant, None, &owner, &owner, &QuotaConsumption::one_request()).await?;
    let sample = match usage::Attempt::begin_redteam(state, tenant, profile, Some(&tool)).await {
        Ok(sample) => sample,
        Err(error) => {
            lease.finish(Some(&QuotaConsumption::default())).await?;
            return Err(error);
        }
    };
    Ok(ToolCallReceipt::new(move |outcome| async move {
        match outcome {
            ToolCallOutcome::NotDelivered => {
                let quota = lease.finish(Some(&QuotaConsumption::default())).await;
                let usage = sample.finish(usage::Outcome::NotDelivered).await;
                quota.and(usage)?;
            }
            ToolCallOutcome::Succeeded | ToolCallOutcome::Failed => {
                let status = if matches!(outcome, ToolCallOutcome::Succeeded) {
                    usage::Outcome::Succeeded
                } else {
                    usage::Outcome::Failed
                };
                let quota = lease.finish(None).await;
                let usage = sample.finish(status).await;
                quota.and(usage)?;
            }
            ToolCallOutcome::Unknown => {
                lease.retain_on_disconnect().detach();
                sample.finish(usage::Outcome::Unknown).await?;
            }
            ToolCallOutcome::Cancelled => {
                let quota = lease.finish(None).await;
                let usage = sample.finish(usage::Outcome::Unknown).await;
                quota.and(usage)?;
            }
        }
        Ok(())
    }))
}
