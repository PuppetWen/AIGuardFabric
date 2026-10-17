//! Original-budget sequential full reads; no write, retry or background network task.
use super::{CreateEndpoint, CurrentGuard, EndpointObservation, expired, invalid, verify_observation};
use crate::{
    http::{RpcClient, RpcResponse},
    openapi,
};
use agf_core::{enums::AliCloudService, error::DomainResult};
use serde_json::{Value, json};
use tokio::time::{Instant, timeout_at};
/// Observe exactly the planned endpoint resources; connectivity remains unverified.
///
/// # Errors
/// Current authority, source, original budget, complete pagination or exact resources differ.
pub async fn observe_current(
    client: &RpcClient,
    plan: &CreateEndpoint,
    endpoint: &str,
    guard: &dyn CurrentGuard,
    deadline: Instant,
) -> DomainResult<EndpointObservation> {
    validate_reference(plan, endpoint)?;
    let mut remaining = 512 * 1024;
    let attributes = read(
        client,
        "GetVpcEndpointAttribute",
        &json!({"RegionId":plan.region_id,"EndpointId":endpoint}),
        guard,
        deadline,
        &mut remaining,
    )
    .await?;
    let zones = pages(client, "ListVpcEndpointZones", plan, endpoint, guard, deadline, &mut remaining).await?;
    let groups =
        pages(client, "ListVpcEndpointSecurityGroups", plan, endpoint, guard, deadline, &mut remaining).await?;
    let result = verify_observation(plan, endpoint, &attributes, &zones, &groups)?;
    timeout_at(deadline, guard.validate()).await.map_err(|_| expired())??;
    Ok(result)
}
async fn read(
    client: &RpcClient,
    action: &str,
    input: &Value,
    guard: &dyn CurrentGuard,
    deadline: Instant,
    remaining: &mut usize,
) -> DomainResult<RpcResponse> {
    timeout_at(deadline, guard.validate()).await.map_err(|_| expired())??;
    let contract = openapi::contract(AliCloudService::Privatelink, action)?;
    if !contract.read_only || contract.version != "2020-04-15" || contract.style != "RPC" || contract.path != "/" {
        return Err(invalid());
    }
    let request = contract.build(client, input)?;
    let response = timeout_at(deadline, client.execute_async_raw(&request)).await.map_err(|_| expired())??;
    if response.status != 200
        || response.body.get("Code").is_some()
        || serde_json::to_vec(&response.body)?.len() > 128 * 1024
    {
        return Err(invalid());
    }
    *remaining = remaining.checked_sub(serde_json::to_vec(&response.body)?.len()).ok_or_else(invalid)?;
    timeout_at(deadline, guard.validate()).await.map_err(|_| expired())??;
    Ok(response)
}
async fn pages(
    client: &RpcClient,
    action: &str,
    plan: &CreateEndpoint,
    endpoint: &str,
    guard: &dyn CurrentGuard,
    deadline: Instant,
    remaining: &mut usize,
) -> DomainResult<Vec<RpcResponse>> {
    let mut responses = vec![];
    let mut next = None;
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..20 {
        let mut input = json!({"RegionId":plan.region_id,"EndpointId":endpoint,"MaxResults":50});
        if let Some(token) = &next {
            input["NextToken"] = json!(token);
        }
        let response = read(client, action, &input, guard, deadline, remaining).await?;
        next = match response.body.get("NextToken") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(Value::String(s)) if s.len() <= 4096 && !s.chars().any(char::is_control) && seen.insert(s.clone()) => {
                Some(s.clone())
            }
            _ => return Err(invalid()),
        };
        responses.push(response);
        if next.is_none() {
            return Ok(responses);
        }
    }
    Err(invalid())
}

/// Validate existing resource references without inventing a Create bandwidth or carrying user payload.
///
/// # Errors
/// Region, service/VPC/endpoint, selected zones/switches or groups are invalid or duplicate.
pub fn validate_reference(plan: &CreateEndpoint, endpoint: &str) -> DomainResult<()> {
    let token = |s: &str| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let resource = |s: &str, prefix: &str| s.strip_prefix(prefix).is_some_and(token);
    if !token(&plan.region_id)
        || !token(&plan.service_region_id)
        || !resource(&plan.service_id, "epsrv-")
        || !resource(&plan.vpc_id, "vpc-")
        || !resource(endpoint, "ep-")
        || !(1..=10).contains(&plan.zones.len())
        || !(1..=10).contains(&plan.security_group_ids.len())
        || plan.zones.iter().any(|z| {
            !token(&z.zone_id)
                || !z.zone_id.starts_with(&format!("{}-", plan.region_id))
                || !resource(&z.vswitch_id, "vsw-")
        })
        || plan.security_group_ids.iter().any(|s| !resource(s, "sg-"))
        || plan.zones.iter().map(|z| &z.zone_id).collect::<std::collections::BTreeSet<_>>().len() != plan.zones.len()
        || plan.zones.iter().map(|z| &z.vswitch_id).collect::<std::collections::BTreeSet<_>>().len() != plan.zones.len()
        || plan.security_group_ids.iter().collect::<std::collections::BTreeSet<_>>().len()
            != plan.security_group_ids.len()
    {
        return Err(invalid());
    }
    Ok(())
}
