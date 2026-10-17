use super::{PreparedChange, WriteEvidence, WriteStatus, prepare, validate};
use crate::{
    http::{RpcClient, RpcResponse},
    openapi,
    schedulerx3::native_observation::{CurrentGuard, observe_current},
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};
use tokio::time::{Instant, timeout_at};

/// Reobserve the pinned target, then attempt exactly one write without any retry.
///
/// This requires a server-resolved client and an enclosing authority/source/binding guard.
///
/// All failures before dispatch are errors. Once transport is entered, unknown delivery or
/// post-write revocation returns safe evidence for staging, never a false not-sent result.
///
/// # Errors
/// Original deadline, current guard, complete observation, fingerprint or catalog fails
/// before the single provider write is entered.
pub async fn dispatch_once(
    client: &RpcClient,
    planned: &PreparedChange,
    guard: &dyn CurrentGuard,
    original_deadline: Instant,
) -> DomainResult<WriteEvidence> {
    let current = observe_current(client, &planned.scope, guard, original_deadline).await?;
    let fresh = prepare(&current, &planned.selection, &planned.change)?;
    if fresh.action != planned.action || fresh.input != planned.input || fresh.before != planned.before {
        return Err(validate::precondition());
    }
    let definition = openapi::contract(AliCloudService::SchedulerX3, planned.action)?;
    if definition.version != "2024-06-24"
        || definition.style != "RPC"
        || definition.method != "POST"
        || definition.path != "/"
        || definition.read_only
        || !matches!(planned.action, "UpdateJob" | "OperateDisableJobs" | "OperateEnableJobs")
    {
        return Err(DomainError::Config("Scheduler managed job requires its exact single-write contract".into()));
    }
    let request = definition.build(client, &planned.input)?;
    timeout_at(original_deadline, guard.validate()).await.map_err(|_| expired())??;
    if Instant::now() >= original_deadline {
        return Err(expired());
    }
    let response = timeout_at(original_deadline, client.execute_async_raw(&request)).await;
    let (status, provider_request_id) = match response {
        Ok(Ok(response)) => classify(&response),
        Ok(Err(_)) | Err(_) => (WriteStatus::Unknown, None),
    };
    let authority_current = matches!(timeout_at(original_deadline, guard.validate()).await, Ok(Ok(())));
    Ok(WriteEvidence {
        attempted: true,
        status,
        provider_request_id,
        authority_current,
        original_deadline_current: Instant::now() < original_deadline,
    })
}
fn expired() -> DomainError {
    DomainError::Timeout("Scheduler original write budget expired; inspect the original receipt".into())
}
fn classify(response: &RpcResponse) -> (WriteStatus, Option<String>) {
    if serde_json::to_vec(&response.body).map_or(true, |raw| raw.len() > 4 * 1024 * 1024) {
        return (WriteStatus::Unknown, None);
    }
    let request = response.body["RequestId"].as_str().filter(|value| validate::text(value, 256, false));
    let Some(request) = request else {
        return (WriteStatus::Unknown, None);
    };
    let status = if response.status == 200
        && response.body["Code"].as_i64() == Some(200)
        && response.body["Success"].as_bool() == Some(true)
    {
        WriteStatus::Accepted
    } else if matches!(response.status, 400 | 401 | 403 | 404 | 409 | 412 | 422)
        && response.body["Success"].as_bool() == Some(false)
    {
        WriteStatus::Rejected
    } else {
        WriteStatus::Unknown
    };
    (status, Some(request.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_accepted_ack_requires_the_exact_success_shape_and_safe_identifier() {
        for body in [
            json!({"Code":200,"Success":true}),
            json!({"Code":200,"Success":true,"RequestId":"bad\nidentifier"}),
            json!({"Code":0,"Success":true,"RequestId":"owned"}),
            json!({"Code":200,"Success":false,"RequestId":"owned"}),
            json!({"Code":200,"RequestId":"owned"}),
        ] {
            assert_eq!(classify(&RpcResponse { status: 200, body, raw: String::new() }).0, WriteStatus::Unknown);
        }
        assert_eq!(
            classify(&RpcResponse {
                status: 200,
                body: json!({"Code":200,"Success":true,"RequestId":"owned"}),
                raw: String::new()
            })
            .0,
            WriteStatus::Accepted
        );
    }

    #[test]
    fn only_explicit_client_rejection_is_rejected_and_server_failure_stays_unknown() {
        let body = json!({"Code":"Forbidden","Success":false,"RequestId":"owned","Message":"private response"});
        assert_eq!(
            classify(&RpcResponse { status: 403, body: body.clone(), raw: String::new() }),
            (WriteStatus::Rejected, Some("owned".into()))
        );
        assert_eq!(classify(&RpcResponse { status: 500, body, raw: String::new() }).0, WriteStatus::Unknown);
    }
}
