//! A complete fixed existing endpoint example. Unknown targets are never synthesized.
use super::scope;
use crate::{integration_store::Stored, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use serde_json::Value;

pub(crate) fn supports(action: &str) -> bool {
    matches!(action, "GetVpcEndpointAttribute" | "ListVpcEndpointZones" | "ListVpcEndpointSecurityGroups")
}

pub(crate) async fn response(
    state: &AppState,
    tenant: TenantId,
    config: &Stored,
    action: &str,
    input: &Value,
    fixture: Value,
) -> DomainResult<Value> {
    if !supports(action) {
        return Ok(fixture);
    }
    let (_, current) = scope::load(state, tenant).await?;
    if !current.mocked || !config.enabled || scope::from_row(state, tenant, config)? != current {
        return Err(scope::stale());
    }
    if current.endpoint_id != "ep-agf-demo"
        || current.region != "cn-hangzhou"
        || input["EndpointId"] != current.endpoint_id
        || input["RegionId"] != current.region
    {
        return Err(DomainError::PreconditionFailed(
            "PrivateLink Mock仅提供cn-hangzhou中的现有示例端点ep-agf-demo；未知端点不会被创建".into(),
        ));
    }
    if action != "GetVpcEndpointAttribute" {
        if input["MaxResults"].as_u64() != Some(50) || input.get("NextToken").is_some() {
            return Err(DomainError::Validation(
                "PrivateLink Mock示例只有一页；分页参数必须为MaxResults=50且无NextToken".into(),
            ));
        }
    }
    let examples: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/alicloud/privatelink-inventory.json"))?;
    examples.get(action).cloned().ok_or_else(|| DomainError::Internal("PrivateLink本地完整示例缺少只读动作".into()))
}
