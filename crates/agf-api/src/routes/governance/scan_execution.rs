//! A bounded execution cannot overwrite cancellation or leave a failed task running.
use super::*;
use agf_core::ids::TenantId;
use agf_scan::{engine::ScanResult, loader::RulePack};
use std::sync::Arc;

pub(super) async fn execute(
    state: &AppState,
    rules: Arc<RulePack>,
    engine: &agf_scan::engine::ScanEngine,
    tenant: TenantId,
    id: Id,
    request: &ScanRequest,
) -> Result<ScanJob, DomainError> {
    let started = state.store.scan_transition_durable(tenant, id, ScanJobState::Running, None).await?;
    if started.state != ScanJobState::Running {
        return Ok(started);
    }
    let remaining = started.created_at.offset_secs(120).since_secs(&Timestamp::now()).max(0);
    let duration = std::time::Duration::from_secs(u64::try_from(remaining).unwrap_or(0));
    let result = tokio::time::timeout(duration, engine.scan(tenant, &rules, request)).await;
    let result = match result {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return fail(state, tenant, id, &error).await,
        Err(_) => return fail(state, tenant, id, &DomainError::PreconditionFailed("Scan timed out".into())).await,
    };
    let assets: std::collections::BTreeSet<_> = request.targets.iter().filter_map(|t| t.asset_id).collect();
    let assets: Vec<_> = assets.into_iter().collect();
    let job = match state.store.scan_complete_durable(tenant, id, &assets, &result).await {
        Ok(job) => job,
        Err(error) => return fail(state, tenant, id, &error).await,
    };
    publish(state, tenant, &job, &result);
    Ok(job)
}

async fn fail(state: &AppState, tenant: TenantId, id: Id, error: &DomainError) -> Result<ScanJob, DomainError> {
    tracing::warn!(task_id = %id, error = %error, "Scan failed before result commit");
    // Do not copy submitted content, database details or provider secrets into the public task error.
    state
        .store
        .scan_transition_durable(
            tenant,
            id,
            ScanJobState::Failed,
            Some("Scan failed or timed out before results were committed; review service health and retry.".into()),
        )
        .await
}

fn publish(state: &AppState, tenant: TenantId, job: &ScanJob, result: &ScanResult) {
    if job.state == ScanJobState::Succeeded && !result.findings.is_empty() {
        state.publish(crate::state::WsEvent {
            kind: "finding".into(), tenant_id: tenant, at: Timestamp::now(),
            payload: serde_json::json!({"task_id":job.id,"findings":result.findings.iter().map(|f|f.id).collect::<Vec<_>>()}),
        });
    }
}

pub(super) fn validate(body: &ScanBody) -> Result<(), ApiError> {
    let invalid = body.targets.is_empty()
        || body.targets.len() > 100
        || body.job_name.as_ref().is_some_and(|name| name.trim().is_empty() || name.len() > 200)
        || body.domains.len() > 5
        || body
            .targets
            .iter()
            .any(|t| t.label.trim().is_empty() || t.label.len() > 200 || t.text.is_empty() || t.text.len() > 1_048_576)
        || body.targets.iter().map(|t| t.text.len()).sum::<usize>() > 4_194_304;
    if invalid {
        return Err(ApiError::new(DomainError::Validation(
            "Use 1–100 targets, nonempty names up to 200 bytes, at most 5 domains, and nonempty text up to 1 MiB per target / 4 MiB total.".into())));
    }
    Ok(())
}
