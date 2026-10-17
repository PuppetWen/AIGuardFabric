use super::{CreateEndpoint, invalid, validate};
use crate::http::RpcResponse;
use agf_core::{error::DomainResult, ids::Id};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// 三项独立只读 API 的完整观察，仍不证明网络/业务认证可达。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointObservation {
    pub endpoint_id: String,
    pub endpoint_state: String,
    pub connection_state: String,
    pub requested_resources_match: bool,
    pub connectivity_verified: bool,
}

fn trusted(response: &RpcResponse) -> DomainResult<()> {
    let request_id = response.body["RequestId"].as_str().and_then(|text| Id::parse(text).ok());
    if response.status != 200
        || request_id.is_none_or(|id| id.as_uuid().is_nil())
        || response.body.get("Code").is_some()
        || serde_json::to_vec(&response.body).map_or(true, |raw| raw.len() > 4 * 1024 * 1024)
    {
        return Err(invalid());
    }
    Ok(())
}

fn pages<'a>(responses: &'a [RpcResponse], key: &str) -> DomainResult<Vec<&'a Value>> {
    if !(1..=20).contains(&responses.len()) {
        return Err(invalid());
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total = None;
    for (index, response) in responses.iter().enumerate() {
        trusted(response)?;
        let count = response.body["TotalCount"].as_u64().filter(|count| *count <= 1000).ok_or_else(invalid)?;
        if total.is_some_and(|previous| previous != count) {
            return Err(invalid());
        }
        total = Some(count);
        let values = response.body[key].as_array().filter(|rows| rows.len() <= 50).ok_or_else(invalid)?;
        result.extend(values);
        if result.len() > 1000 {
            return Err(invalid());
        }
        let next = match response.body.get("NextToken") {
            None | Some(Value::Null) => "",
            Some(Value::String(value)) => value,
            Some(_) => return Err(invalid()),
        };
        let last = index + 1 == responses.len();
        if next.is_empty() != last || (!next.is_empty() && (next.len() > 4096 || !seen.insert(next))) {
            return Err(invalid());
        }
    }
    if total != u64::try_from(result.len()).ok() {
        return Err(invalid());
    }
    Ok(result)
}

/// 核对 GetVpcEndpointAttribute、完整 Zones 和 SecurityGroups；只比较明确选定资源。
///
/// # Errors
/// API身份、返回来源、分页完整性或原请求资源不符；不会把状态当作TCP证明。
pub fn verify_observation(
    planned: &CreateEndpoint,
    endpoint_id: &str,
    attributes: &RpcResponse,
    zone_pages: &[RpcResponse],
    group_pages: &[RpcResponse],
) -> DomainResult<EndpointObservation> {
    trusted(attributes)?;
    if !validate::resource(endpoint_id, "ep-")
        || attributes.body["EndpointId"] != endpoint_id
        || attributes.body["RegionId"] != planned.region_id
        || attributes.body["VpcId"] != planned.vpc_id
        || attributes.body["ServiceId"] != planned.service_id
        || attributes.body["ServiceRegionId"] != planned.service_region_id
    {
        return Err(invalid());
    }
    let mut observed_zones = BTreeSet::new();
    for zone in pages(zone_pages, "Zones")? {
        let zone_id = zone["ZoneId"].as_str().ok_or_else(invalid)?;
        let vswitch_id = zone["VSwitchId"].as_str().ok_or_else(invalid)?;
        if !validate::token(zone_id, 64)
            || !validate::resource(vswitch_id, "vsw-")
            || !observed_zones.insert((zone_id, vswitch_id))
        {
            return Err(invalid());
        }
    }
    let expected_zones = planned.zones.iter().map(|zone| (zone.zone_id.as_str(), zone.vswitch_id.as_str())).collect();
    if observed_zones != expected_zones {
        return Err(invalid());
    }
    let mut observed_groups = BTreeSet::new();
    for group in pages(group_pages, "SecurityGroups")? {
        let id = group["SecurityGroupId"].as_str().ok_or_else(invalid)?;
        if !validate::resource(id, "sg-") || !observed_groups.insert(id) {
            return Err(invalid());
        }
    }
    if observed_groups != planned.security_group_ids.iter().map(String::as_str).collect() {
        return Err(invalid());
    }
    let state = attributes.body["EndpointStatus"]
        .as_str()
        .filter(|state| matches!(*state, "Creating" | "Active" | "Pending" | "Deleting" | "Deleted" | "Failed"))
        .unwrap_or("Unknown");
    let connection = attributes.body["ConnectionStatus"]
        .as_str()
        .filter(|state| matches!(*state, "Disconnected" | "Connecting" | "Connected" | "Disconnecting"))
        .unwrap_or("Unknown");
    Ok(EndpointObservation {
        endpoint_id: endpoint_id.into(),
        endpoint_state: state.into(),
        connection_state: connection.into(),
        requested_resources_match: true,
        connectivity_verified: false,
    })
}
