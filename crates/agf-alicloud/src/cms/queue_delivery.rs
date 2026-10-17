//! Single-item CMS delivery with an acknowledgement boundary suitable for durable queues.
use crate::http::{RpcClient, RpcResponse};
use agf_core::error::{DomainError, DomainResult};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio::time::{Instant, timeout_at};

/// Current original actor, source, claim and operation budget.
#[async_trait]
pub trait CurrentGuard: Send + Sync {
    /// Validate locally without recursively acquiring the provider runtime mutex.
    async fn validate(&self) -> DomainResult<()>;
}

/// A bounded CMS event or metric. Raw provider actions and URLs are not accepted.
#[derive(Clone)]
pub struct Request {
    action: &'static str,
    input: Value,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmsQueueRequest").field("action", &self.action).finish_non_exhaustive()
    }
}

impl Request {
    /// Prepare one event. Its content is never included in diagnostics.
    pub fn event(group: &str, name: &str, content: &str, timestamp_ms: i64) -> DomainResult<Self> {
        if !text(group, 128) || !text(name, 128) || content.is_empty() || content.len() > 4096 {
            return Err(invalid());
        }
        Self::bounded(
            "PutCustomEvent",
            json!({"EventInfo":[{"GroupId":group,"EventName":name,
            "Content":content,"Time":timestamp_ms.to_string()}]}),
        )
    }
    /// Prepare one raw-value metric with explicit dimensions.
    pub fn metric(
        group: &str,
        name: &str,
        value: f64,
        dimensions: &BTreeMap<String, String>,
        timestamp_ms: i64,
    ) -> DomainResult<Self> {
        if !text(group, 128)
            || !text(name, 128)
            || !value.is_finite()
            || dimensions.len() > 16
            || dimensions.iter().any(|(key, value)| !text(key, 128) || !text(value, 256))
        {
            return Err(invalid());
        }
        Self::bounded(
            "PutCustomMetric",
            json!({"MetricList":[{"GroupId":group,"MetricName":name,
            "Type":"0","Time":timestamp_ms.to_string(),"Values":json!({"value":value}).to_string(),
            "Dimensions":serde_json::to_string(dimensions)?}]}),
        )
    }
    fn bounded(action: &'static str, input: Value) -> DomainResult<Self> {
        if serde_json::to_vec(&input)?.len() > 32 * 1024 {
            return Err(invalid());
        }
        Ok(Self { action, input })
    }
}

/// Observed acknowledgement, explicit rejection or an unconfirmed send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// HTTP 200, exact Code 200 and a bounded provider RequestId.
    Accepted(String),
    /// A recognized rejection on a matching non-success HTTP response.
    Rejected(String),
    /// Transport, body, contradictory or incomplete acknowledgement evidence.
    Unknown,
}

/// Invoke the transport once under the original operation deadline.
///
/// Errors occur before transport; after entering transport every ambiguous result is Unknown.
pub async fn send_once(
    client: &RpcClient,
    input: &Request,
    guard: &dyn CurrentGuard,
    deadline: Instant,
) -> DomainResult<Outcome> {
    let request = timeout_at(deadline, async {
        guard.validate().await?;
        let definition = crate::openapi::contract(agf_core::enums::AliCloudService::Cms, input.action)?;
        let request = definition.build(client, &input.input)?;
        guard.validate().await?;
        if Instant::now() >= deadline {
            return Err(expired());
        }
        Ok::<_, DomainError>(request)
    })
    .await
    .map_err(|_| expired())??;
    if Instant::now() >= deadline {
        return Err(expired());
    }
    Ok(match timeout_at(deadline, client.execute_async_raw(&request)).await {
        Ok(Ok(response)) => classify(&response),
        Ok(Err(_)) | Err(_) => Outcome::Unknown,
    })
}

fn classify(response: &RpcResponse) -> Outcome {
    let Some(body) = response.body.as_object() else {
        return Outcome::Unknown;
    };
    if body.len() > 16
        || body.contains_key("FailedItems")
        || body.contains_key("Errors")
        || body.contains_key("PartialSuccess")
        || body.get("Success").is_some_and(|v| !v.is_boolean())
    {
        return Outcome::Unknown;
    }
    let Some(code) = body.get("Code").and_then(Value::as_str) else {
        return Outcome::Unknown;
    };
    let Some(id) = body.get("RequestId").and_then(Value::as_str).filter(|id| safe_id(id)) else {
        return Outcome::Unknown;
    };
    if response.status == 200 && code == "200" && body.get("Success").is_none_or(|v| v == &json!(true)) {
        return Outcome::Accepted(id.into());
    }
    let rejection = matches!(response.status, 400 | 401 | 403 | 404 | 429)
        && matches!(
            code,
            "InvalidParameter"
                | "InvalidParameterValue"
                | "MissingParameter"
                | "Forbidden"
                | "Forbidden.RAM"
                | "InvalidAccessKeyId.NotFound"
                | "SignatureDoesNotMatch"
                | "Throttling"
        );
    if rejection && body.get("Success").is_none_or(|v| v == &json!(false)) {
        Outcome::Rejected(id.into())
    } else {
        Outcome::Unknown
    }
}

fn safe_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|v| v.is_ascii_alphanumeric() || b"-_.:".contains(&v))
}
fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn invalid() -> DomainError {
    DomainError::Validation("Invalid typed CMS queue delivery".into())
}
fn expired() -> DomainError {
    DomainError::Timeout("CMS original delivery budget expired".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(status: u16, body: Value) -> RpcResponse {
        RpcResponse { status, body, raw: String::new() }
    }
    #[test]
    fn strict_ack_is_not_inferred_from_message_or_missing_request_id() {
        assert_eq!(
            classify(&response(200, json!({"Code":"200","RequestId":"owned-id","Message":"irrelevant"}))),
            Outcome::Accepted("owned-id".into())
        );
        for body in [
            json!({"Code":"200"}),
            json!({"Code":200,"RequestId":"owned-id"}),
            json!({"Code":"200","RequestId":"owned-id","Success":false}),
            json!({"Code":"200","RequestId":"owned-id","FailedItems":[]}),
        ] {
            assert_eq!(classify(&response(200, body)), Outcome::Unknown);
        }
    }
    #[test]
    fn server_fault_is_unknown_and_recognized_rejection_requires_http_and_id() {
        let body = json!({"Code":"Forbidden","RequestId":"owned-id"});
        assert_eq!(classify(&response(403, body.clone())), Outcome::Rejected("owned-id".into()));
        for status in [200, 500, 503] {
            assert_eq!(classify(&response(status, body.clone())), Outcome::Unknown);
        }
    }
    #[test]
    fn typed_values_are_bounded_and_invalid_floats_never_prepare() {
        assert!(Request::metric("owned", "x", f64::NAN, &BTreeMap::new(), 0).is_err());
        assert!(Request::event("owned", "x", &"x".repeat(4097), 0).is_err());
        assert!(Request::event("owned", "x", "private-value", 0).is_ok());
    }
    #[test]
    fn explicit_false_supports_only_a_matching_known_non_success_rejection() {
        for (status, code) in [(400, "InvalidParameter"), (403, "Forbidden")] {
            assert_eq!(
                classify(&response(status, json!({"Code":code,"RequestId":"owned-rejection","Success":false}))),
                Outcome::Rejected("owned-rejection".into())
            );
            for flag in [json!(true), json!("false"), Value::Null] {
                assert_eq!(
                    classify(&response(status, json!({"Code":code,"RequestId":"owned-rejection","Success":flag}))),
                    Outcome::Unknown
                );
            }
            for wrong_status in [200, 500, 503] {
                assert_eq!(
                    classify(&response(
                        wrong_status,
                        json!({"Code":code,"RequestId":"owned-rejection","Success":false})
                    )),
                    Outcome::Unknown
                );
            }
        }
    }
}
