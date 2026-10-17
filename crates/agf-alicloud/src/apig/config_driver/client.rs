use super::{
    ContentBinding, CurrentGuard, ModelBinding, Observation, Prepared, WriteOutcome,
    parse::{invalid, parse_content, parse_models},
    types::Target,
};
use crate::http::{RpcClient, RpcResponse};
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json};
use tokio::time::{Duration, Instant, timeout_at};

/// Read the one selected installed-plugin attachment; no initialization, retry or write.
///
/// # Errors
/// Authority, deadline or exact evidence validation fails.
pub async fn observe_content(
    client: &RpcClient,
    binding: &ContentBinding,
    guard: &dyn CurrentGuard,
    original_deadline: Instant,
) -> DomainResult<Observation> {
    binding.validate()?;
    let deadline = bounded(original_deadline);
    timeout_at(deadline, async {
        let response =
            read(client, "GetPluginAttachment", &json!({"pluginAttachmentId":binding.attachment_id}), guard, deadline)
                .await?;
        let observation = parse_content(binding, &response)?;
        guard.validate().await?;
        check(deadline)?;
        Ok(observation)
    })
    .await
    .map_err(|_| expired())?
}

/// Read the actual selected ModelAPI without expanding independently managed policy bodies.
///
/// # Errors
/// Authority, deadline, response or identity evidence fails.
pub async fn observe_models(
    client: &RpcClient,
    binding: &ModelBinding,
    guard: &dyn CurrentGuard,
    original_deadline: Instant,
) -> DomainResult<Observation> {
    binding.validate()?;
    let deadline = bounded(original_deadline);
    timeout_at(deadline, async {
        let response = read(
            client,
            "GetHttpApi",
            &json!({"httpApiId":binding.http_api_id,"expandPolicyConfigs":false}),
            guard,
            deadline,
        )
        .await?;
        let observation = parse_models(binding, &response)?;
        guard.validate().await?;
        check(deadline)?;
        Ok(observation)
    })
    .await
    .map_err(|_| expired())?
}

/// Reobserve the complete original fingerprint, then send exactly one configuration write.
///
/// The workflow owns permanent UUID admission and cancellation-safe staging. This driver never retries;
/// Accepted is an acknowledgement, not deployment, consumer application or cloud CAS proof.
///
/// # Errors
/// Preflight changes, revoked authority, invalid request or original deadline prevents dispatch.
/// After dispatch, failure is Unknown and must not be resent automatically.
pub async fn publish_once(
    client: &RpcClient,
    update: &Prepared,
    guard: &dyn CurrentGuard,
    original_deadline: Instant,
) -> DomainResult<WriteOutcome> {
    let deadline = bounded(original_deadline);
    let request = timeout_at(deadline, async {
        let (current, action, input) = match &update.baseline.target {
            Target::Content(binding) => (
                observe_content(client, binding, guard, deadline).await?,
                "UpdatePluginAttachment",
                json!({"pluginAttachmentId":binding.attachment_id,"body":update.body}),
            ),
            Target::Models(binding) => (
                observe_models(client, binding, guard, deadline).await?,
                "UpdateHttpApi",
                json!({"httpApiId":binding.http_api_id,"body":update.body}),
            ),
        };
        if current.fingerprint() != update.baseline.fingerprint() {
            return Err(DomainError::Conflict(
                "APIG configuration changed; observe and preview a new explicit intent".into(),
            ));
        }
        let request = super::contract::definition(action)?.build(client, &input)?;
        guard.validate().await?;
        check(deadline)?;
        Ok(request)
    })
    .await
    .map_err(|_| expired())??;
    check(deadline)?;
    let result = timeout_at(deadline, client.execute_async_raw(&request)).await;
    Ok(match result {
        Ok(Ok(response)) => acknowledge(&response),
        Ok(Err(_)) | Err(_) => WriteOutcome::Unknown,
    })
}
async fn read(
    client: &RpcClient,
    action: &str,
    input: &Value,
    guard: &dyn CurrentGuard,
    deadline: Instant,
) -> DomainResult<RpcResponse> {
    let request = super::contract::definition(action)?.build(client, input)?;
    guard.validate().await?;
    check(deadline)?;
    let response = client.execute_async_raw(&request).await?;
    check(deadline)?;
    Ok(response)
}
fn acknowledge(response: &RpcResponse) -> WriteOutcome {
    if (200..300).contains(&response.status)
        && response.raw.len() <= 128 * 1024
        && response.body.to_string().len() <= 128 * 1024
        && response.body["code"].as_str() == Some("Ok")
    {
        if let Some(id) = response.body["requestId"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
        {
            return WriteOutcome::Accepted { request_id: id.into() };
        }
    }
    WriteOutcome::Unknown
}
fn bounded(original: Instant) -> Instant {
    original.min(Instant::now() + Duration::from_secs(30))
}
fn check(deadline: Instant) -> DomainResult<()> {
    if Instant::now() >= deadline { Err(expired()) } else { Ok(()) }
}
fn expired() -> DomainError {
    invalid("APIG original configuration operation deadline expired")
}
