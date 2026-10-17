//! Only fields present in the public ListAnsServices contract become source observations.
use super::{
    contract::{Scope, Service},
    scope,
};
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json};

#[derive(Debug)]
pub(super) struct Page {
    pub total: u64,
    pub services: Vec<Service>,
}

pub(super) fn page(value: &Value, scope: &Scope, number: u64) -> DomainResult<Page> {
    for (key, expected) in [("InstanceId", scope.instance_id.as_str()), ("NamespaceId", scope.namespace_id.as_str())] {
        if let Some(actual) = value.get(key) {
            if actual.as_str() != Some(expected) {
                return Err(invalid());
            }
        }
    }
    let total = value["TotalCount"].as_u64().filter(|total| *total <= 2000).ok_or_else(invalid)?;
    if value.get("PageNumber").is_some_and(|page| page.as_u64() != Some(number))
        || value.get("PageSize").is_some_and(|size| size.as_u64() != Some(100))
    {
        return Err(invalid());
    }
    let data = value["Data"].as_array().filter(|items| items.len() <= 100).ok_or_else(invalid)?;
    let services = data.iter().map(|item| service(item, scope)).collect::<DomainResult<Vec<_>>>()?;
    Ok(Page { total, services })
}

fn service(value: &Value, scope: &Scope) -> DomainResult<Service> {
    let name = text(value, "Name", 512)?.filter(|value| !value.is_empty()).ok_or_else(invalid)?;
    let group = text(value, "GroupName", 512)?.filter(|value| !value.is_empty()).ok_or_else(invalid)?;
    for (key, expected) in [("InstanceId", scope.instance_id.as_str()), ("NamespaceId", scope.namespace_id.as_str())] {
        if value.get(key).is_some_and(|actual| actual.as_str() != Some(expected)) {
            return Err(invalid());
        }
    }
    let instance_count = count(value, "IpCount")?;
    let healthy_count = count(value, "HealthyInstanceCount")?;
    if instance_count.zip(healthy_count).is_some_and(|(total, healthy)| healthy > total) {
        return Err(invalid());
    }
    Ok(Service {
        key: scope::hash(&json!([group, name]))?,
        name,
        group,
        instance_count,
        healthy_count,
        cluster_count: count(value, "ClusterCount")?,
        source: text(value, "Source", 64)?,
        asset_id: None,
    })
}

fn count(value: &Value, key: &str) -> DomainResult<Option<u64>> {
    value
        .get(key)
        .filter(|value| !value.is_null())
        .map(|value| value.as_u64().filter(|value| u32::try_from(*value).is_ok()).ok_or_else(invalid))
        .transpose()
}

fn text(value: &Value, key: &str, max: usize) -> DomainResult<Option<String>> {
    value
        .get(key)
        .filter(|value| !value.is_null())
        .map(|value| {
            value.as_str().filter(|value| scope::valid_text(value, max)).map(str::to_owned).ok_or_else(invalid)
        })
        .transpose()
}

fn invalid() -> DomainError {
    DomainError::Parse("MSE 清单的分页、资源身份或字段类型不完整可信，原台账保持不变".into())
}
