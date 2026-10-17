use super::{Observation, Scope, fields, parse::Collector};
use crate::{
    http::{RpcClient, RpcResponse},
    openapi,
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};
use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::time::{Duration, Instant, timeout_at};

/// Current source, actor and observation lease checks supplied by the enclosing workflow.
///
/// Validation must not recursively acquire the already-held runtime service mutex.
#[async_trait]
pub trait CurrentGuard: Send + Sync {
    /// Recheck current authority and configured scope before and after every provider read.
    ///
    /// # Errors
    /// Current actor, source, lease or submitted session no longer permits this read.
    async fn validate(&self) -> DomainResult<()>;
}

/// Read GetApp and all ListJobs pages under the original bounded deadline.
///
/// The caller supplies a resolved source client and holds the same runtime mutex throughout.
/// This driver performs no STS lookup, callback, registration or provider write, and never retries.
///
/// # Errors
/// Guard, timeout, catalog, transport, identity or complete-pagination validation fails.
pub async fn observe_current(
    client: &RpcClient,
    scope: &Scope,
    guard: &dyn CurrentGuard,
    original_deadline: Instant,
) -> DomainResult<Observation> {
    let deadline = original_deadline.min(Instant::now() + Duration::from_secs(30));
    timeout_at(deadline, observe_inner(client, scope, guard, deadline))
        .await
        .map_err(|_| fields::unavailable())?
        .map_err(redact)
}

async fn observe_inner(
    client: &RpcClient,
    scope: &Scope,
    guard: &dyn CurrentGuard,
    deadline: Instant,
) -> DomainResult<Observation> {
    scope.validate()?;
    let app = read(client, "GetApp", &json!({"ClusterId":scope.cluster_id,"AppName":scope.app_name}), guard, deadline)
        .await?;
    let mut collector = Collector::new(scope, &app)?;
    loop {
        let number = collector.next_page()?;
        let response = read(
            client,
            "ListJobs",
            &json!({"ClusterId":scope.cluster_id,"AppName":scope.app_name,"PageNum":number,"PageSize":super::PAGE_SIZE}),
            guard,
            deadline,
        ).await?;
        if collector.push(&response)? {
            break;
        }
    }
    let observation = collector.finish()?;
    guard.validate().await?;
    check_deadline(deadline)?;
    Ok(observation)
}

async fn read(
    client: &RpcClient,
    action: &str,
    input: &Value,
    guard: &dyn CurrentGuard,
    deadline: Instant,
) -> DomainResult<RpcResponse> {
    let definition = openapi::contract(AliCloudService::SchedulerX3, action)?;
    if definition.version != "2024-06-24"
        || definition.style != "RPC"
        || definition.method != "GET"
        || definition.path != "/"
        || !definition.read_only
    {
        return Err(DomainError::Config(
            "Scheduler trusted observation requires the exact read-only catalog contract".into(),
        ));
    }
    let request = definition.build(client, input)?;
    guard.validate().await?;
    check_deadline(deadline)?;
    let response = client.execute_async_raw(&request).await?;
    check_deadline(deadline)?;
    guard.validate().await?;
    check_deadline(deadline)?;
    Ok(response)
}

fn check_deadline(deadline: Instant) -> DomainResult<()> {
    if Instant::now() >= deadline {
        Err(DomainError::PreconditionFailed("Scheduler original observation deadline expired".into()))
    } else {
        Ok(())
    }
}

fn redact(error: DomainError) -> DomainError {
    let reason = "Scheduler observation rejected; no complete observation was published";
    match error {
        DomainError::Unauthenticated(_) => DomainError::Unauthenticated(reason.into()),
        DomainError::Forbidden(_) => DomainError::Forbidden(reason.into()),
        DomainError::Conflict(_) => DomainError::Conflict(reason.into()),
        DomainError::PreconditionFailed(_) => DomainError::PreconditionFailed(reason.into()),
        DomainError::Validation(_) => DomainError::Validation(reason.into()),
        DomainError::Parse(_) => fields::invalid(),
        DomainError::Config(_) => DomainError::Config(reason.into()),
        DomainError::Crypto(_) => DomainError::Crypto(reason.into()),
        DomainError::Timeout(_) => DomainError::Timeout(reason.into()),
        DomainError::RateLimited(_) => DomainError::RateLimited(reason.into()),
        _ => fields::unavailable(),
    }
}
