//! Required arrays and matching totals establish bounded observation, not a strong cloud snapshot.
use super::contract::{EndpointObservation, Scope, SecurityGroup, Zone};
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use serde_json::Value;

pub(super) struct Page {
    pub total: u64,
    pub items: Vec<Value>,
    pub next_token: Option<String>,
}

pub(super) fn endpoint(value: &Value, scope: &Scope, at: Timestamp) -> DomainResult<EndpointObservation> {
    if !value.is_object() {
        return Err(invalid("endpoint object"));
    }
    let id = required_id(value, "EndpointId")?;
    if id != scope.endpoint_id {
        return Err(invalid("EndpointId scope"));
    }
    let region = optional_id(value, "RegionId")?;
    if region.as_ref().is_some_and(|region| region != &scope.region) {
        return Err(invalid("RegionId scope"));
    }
    Ok(EndpointObservation {
        id,
        name: text(value, "EndpointName", 512)?,
        region,
        vpc_id: optional_id(value, "VpcId")?,
        service_id: optional_id(value, "ServiceId")?,
        service_region_id: optional_id(value, "ServiceRegionId")?,
        domain: text(value, "EndpointDomain", 1024)?,
        endpoint_type: text(value, "EndpointType", 128)?,
        status: text(value, "EndpointStatus", 128)?,
        connection_status: text(value, "ConnectionStatus", 128)?,
        business_status: text(value, "EndpointBusinessStatus", 128)?,
        observed_at: at,
    })
}

pub(super) fn page(value: &Value, key: &str) -> DomainResult<Page> {
    let items = value.get(key).and_then(Value::as_array).ok_or_else(|| invalid(key))?;
    if items.len() > 50 {
        return Err(invalid("page size"));
    }
    let total = value.get("TotalCount").and_then(Value::as_u64).ok_or_else(|| invalid("TotalCount"))?;
    if total > 1000 || items.len() as u64 > total {
        return Err(invalid("TotalCount bound"));
    }
    if value.get("MaxResults").is_some_and(|value| value.as_u64() != Some(50)) {
        return Err(invalid("MaxResults"));
    }
    // The documented absence of a token ends pagination. Arrays and totals are
    // still checked by the collector; absent records are never inferred from 403/404.
    let next_token = match value.get("NextToken") {
        None | Some(Value::Null) => None,
        Some(Value::String(token)) if token.is_empty() => None,
        Some(Value::String(token)) if token.len() <= 4096 && !token.chars().any(char::is_control) => {
            Some(token.clone())
        }
        _ => return Err(invalid("NextToken")),
    };
    Ok(Page { total, items: items.clone(), next_token })
}

pub(super) fn zone(value: &Value, scope: &Scope, at: Timestamp) -> DomainResult<Zone> {
    if !value.is_object() {
        return Err(invalid("zone object"));
    }
    let region = optional_id(value, "RegionId")?;
    if region.as_ref().is_some_and(|region| region != &scope.region) {
        return Err(invalid("zone RegionId scope"));
    }
    Ok(Zone {
        id: required_id(value, "ZoneId")?,
        region,
        status: text(value, "ZoneStatus", 128)?,
        eni_id: optional_id(value, "EniId")?,
        vswitch_id: optional_id(value, "VSwitchId")?,
        eni_ip: address(value, "EniIp", false)?,
        ipv6: address(value, "ZoneIpv6Address", true)?,
        domain: text(value, "ZoneDomain", 1024)?,
        observed_at: at,
    })
}

pub(super) fn security_group(value: &Value, at: Timestamp) -> DomainResult<SecurityGroup> {
    if !value.is_object() {
        return Err(invalid("security group object"));
    }
    Ok(SecurityGroup {
        id: required_id(value, "SecurityGroupId")?,
        status: text(value, "SecurityGroupStatus", 128)?,
        observed_at: at,
    })
}

fn address(value: &Value, key: &str, ipv6: bool) -> DomainResult<Option<String>> {
    let Some(text) = text(value, key, 128)? else {
        return Ok(None);
    };
    let address: std::net::IpAddr = text.parse().map_err(|_| invalid(key))?;
    if ipv6 != address.is_ipv6() {
        return Err(invalid(key));
    }
    Ok(Some(text))
}

pub(super) fn required_id(value: &Value, key: &str) -> DomainResult<String> {
    optional_id(value, key)?.ok_or_else(|| invalid(key))
}

fn optional_id(value: &Value, key: &str) -> DomainResult<Option<String>> {
    let result = text(value, key, 256)?;
    if result.as_ref().is_some_and(|value| value.is_empty() || value.chars().any(char::is_whitespace)) {
        return Err(invalid(key));
    }
    Ok(result)
}

fn text(value: &Value, key: &str, maximum: usize) -> DomainResult<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.len() <= maximum && !value.chars().any(char::is_control) => {
            Ok(Some(value.clone()))
        }
        _ => Err(invalid(key)),
    }
}

fn invalid(field: &str) -> DomainError {
    DomainError::Parse(format!("PrivateLink观测字段 {field} 缺失、格式错误或与范围矛盾；保留原快照"))
}
