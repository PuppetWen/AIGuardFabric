//! Exact structured absence evidence; failures never become an empty resource.
use super::Contract;
use crate::http::{RpcClient, RpcResponse, check_response};
use agf_core::error::{DomainError, DomainResult};
use serde_json::Value;

/// Successful read or exact vendor absence; all ambiguous outcomes return an error.
pub enum ResourceObservation {
    Present(RpcResponse),
    Absent { http_status: u16, provider_code: String, provider_request_id: String },
}

impl std::fmt::Debug for ResourceObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Present(response) => {
                f.debug_struct("Present").field("http_status", &response.status).finish_non_exhaustive()
            }
            Self::Absent { http_status, provider_code, .. } => f
                .debug_struct("Absent")
                .field("http_status", http_status)
                .field("provider_code", provider_code)
                .finish_non_exhaustive(),
        }
    }
}

impl Contract {
    /// Only audited AgentTeams resource reads can classify vendor absence.
    pub async fn observe_resource(&self, client: &RpcClient, input: &Value) -> DomainResult<ResourceObservation> {
        require_resource_read(self)?;
        let response = client.execute_async_raw(&self.build(client, input)?).await?;
        classify_resource_observation(self, response)
    }
}

pub fn classify_resource_observation(operation: &Contract, response: RpcResponse) -> DomainResult<ResourceObservation> {
    require_resource_read(operation)?;
    let request_id = response
        .body
        .get("RequestId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control));
    let consistent = response.body.get("Success").is_none_or(|value| value == &Value::Bool(false))
        && response.body.get("HttpStatusCode").is_none_or(|value| value.as_u64() == Some(404));
    if response.status == 404
        && response.body.get("Code").and_then(Value::as_str) == Some("Resource.NotFound")
        && consistent
    {
        if let Some(request_id) = request_id {
            return Ok(ResourceObservation::Absent {
                http_status: response.status,
                provider_code: "Resource.NotFound".into(),
                provider_request_id: request_id.into(),
            });
        }
    }
    check_response(&response)?;
    Ok(ResourceObservation::Present(response))
}

fn require_resource_read(operation: &Contract) -> DomainResult<()> {
    if operation.read_only
        && operation.version == "2026-06-05"
        && matches!(operation.action.as_str(), "GetTeam" | "GetUser")
    {
        Ok(())
    } else {
        Err(DomainError::Validation("只有 AgentTeams GetTeam/GetUser 支持资源存在性观察".into()))
    }
}
