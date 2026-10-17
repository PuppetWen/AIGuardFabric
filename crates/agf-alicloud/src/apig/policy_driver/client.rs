use super::{Binding, Observation, PreparedUpdate, WriteOutcome, contract::Action, observe, profile};
use crate::http::{RpcClient, RpcResponse};
use agf_core::error::{DomainError, DomainResult};
use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::time::{Duration, Instant, timeout_at};

/// Current actor, source configuration, operation lease and policy dependency fence.
///
/// A future API workflow provides this guard; the driver contains no copied authorization rules.
/// The guard must not recursively acquire the same cloud-runtime mutex.
#[async_trait]
pub trait CurrentGuard: Send + Sync {
    /// Recheck current submission authority and operation/source state without sending provider requests.
    ///
    /// # Errors
    /// Current actor or dependencies no longer authorize this operation, or its lease/deadline expired.
    async fn validate(&self) -> DomainResult<()>;
}

/// Read all three exact resources under one bounded budget.
///
/// The supplied client must already be resolved for the configured source and held runtime service mutex.
/// No credential or endpoint override is accepted in this request.
///
/// # Errors
/// Guard, timeout, provider response or exact identity/evidence validation fails.
pub async fn observe_current(
    client: &RpcClient,
    binding: &Binding,
    guard: &dyn CurrentGuard,
    submitted_deadline: Instant,
) -> DomainResult<Observation> {
    let deadline = driver_deadline(submitted_deadline);
    timeout_at(deadline, observe_inner(client, binding, guard, deadline))
        .await
        .map_err(|_| unavailable("APIG observation deadline expired"))?
}

/// Reobserve the authenticated baseline, then invoke UpdatePolicy at most once.
///
/// No provider CAS token exists: another writer can still modify the provider after our final GET.
/// The enclosing workflow owns permanent claims and cancellation-safe receipt staging.
///
/// # Errors
/// Before transport starts, a changed baseline, guard, invalid request or deadline prevents the PUT.
/// Once transport starts, failures return `Unknown`, with no retry.
pub async fn publish_once(
    client: &RpcClient,
    update: &PreparedUpdate,
    guard: &dyn CurrentGuard,
    submitted_deadline: Instant,
) -> DomainResult<WriteOutcome> {
    let deadline = driver_deadline(submitted_deadline);
    let request = timeout_at(deadline, async {
        let current = observe_inner(client, update.baseline.binding(), guard, deadline).await?;
        if current.fingerprint() != update.baseline_fingerprint() {
            return Err(DomainError::Conflict("APIG configuration changed; read and preview a new intent".into()));
        }
        let input = profile::update_input(update)?;
        let request = Action::Update.definition()?.build(client, &input)?;
        guard.validate().await?;
        check_deadline(deadline)?;
        Ok(request)
    })
    .await
    .map_err(|_| unavailable("APIG preflight deadline expired"))??;

    // There is no await or queue acquisition between the final guard and this unique transport call.
    check_deadline(deadline)?;
    let response = timeout_at(deadline, client.execute_async_raw(&request)).await;
    Ok(match response {
        Ok(Ok(response)) => acknowledged(&response),
        Ok(Err(_)) | Err(_) => WriteOutcome::Unknown,
    })
}

async fn observe_inner(
    client: &RpcClient,
    binding: &Binding,
    guard: &dyn CurrentGuard,
    deadline: Instant,
) -> DomainResult<Observation> {
    binding.validate()?;
    let api = read(
        client,
        Action::HttpApi,
        &json!({"httpApiId":binding.http_api_id,"expandPolicyConfigs":false}),
        guard,
        deadline,
    )
    .await?;
    let policy = read(client, Action::Policy, &json!({"policyId":binding.policy_id}), guard, deadline).await?;
    let attachment =
        read(client, Action::Attachment, &json!({"policyAttachmentId":binding.attachment_id}), guard, deadline).await?;
    guard.validate().await?;
    check_deadline(deadline)?;
    observe::parse_current(binding, &api, &policy, &attachment)
}

async fn read(
    client: &RpcClient,
    action: Action,
    input: &Value,
    guard: &dyn CurrentGuard,
    deadline: Instant,
) -> DomainResult<RpcResponse> {
    let request = action.definition()?.build(client, input)?;
    guard.validate().await?;
    check_deadline(deadline)?;
    let response = client.execute_async_raw(&request).await?;
    check_deadline(deadline)?;
    observe::data(&response, action)?;
    Ok(response)
}

pub(super) fn acknowledged(response: &RpcResponse) -> WriteOutcome {
    if !(200..300).contains(&response.status) || response.body["code"].as_str() != Some("Ok") {
        return WriteOutcome::Unknown;
    }
    match observe::text(&response.body, "requestId", 256) {
        Ok(request_id) => WriteOutcome::Accepted { request_id: request_id.into() },
        Err(_) => WriteOutcome::Unknown,
    }
}

pub(super) fn driver_deadline(submitted_deadline: Instant) -> Instant {
    submitted_deadline.min(Instant::now() + Duration::from_secs(30))
}

fn unavailable(cause: &str) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "alicloud-apig".into(), cause: cause.into() }
}

pub(super) fn check_deadline(deadline: Instant) -> DomainResult<()> {
    if Instant::now() >= deadline {
        Err(DomainError::PreconditionFailed("APIG original operation deadline expired".into()))
    } else {
        Ok(())
    }
}
