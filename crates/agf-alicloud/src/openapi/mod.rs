//! Audited public API contracts. Protocol facts are from api.aliyun.com metadata (2026-09-20).
//! Only catalogued actions may be invoked; query, form, path and JSON body remain distinct.
use crate::{
    http::{RoaCall, RpcClient, RpcRequest, RpcResponse},
    signer::percent_encode,
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod observation;
mod validation;
pub use observation::{ResourceObservation, classify_resource_observation};
pub fn fixture(service: AliCloudService, action: &str) -> DomainResult<Value> {
    contract(service, action)?;
    let raw = match service {
        AliCloudService::Cms => include_str!("../../../../tests/fixtures/alicloud/openapi-cms.json"),
        AliCloudService::Apig => include_str!("../../../../tests/fixtures/alicloud/openapi-apig.json"),
        AliCloudService::Mse => include_str!("../../../../tests/fixtures/alicloud/openapi-mse.json"),
        AliCloudService::Privatelink => include_str!("../../../../tests/fixtures/alicloud/openapi-privatelink.json"),
        AliCloudService::SchedulerX3 => include_str!("../../../../tests/fixtures/alicloud/openapi-schedulerx3.json"),
        AliCloudService::AgentTeams => include_str!("../../../../tests/fixtures/alicloud/openapi-agentteams.json"),
    };
    let values: Value = serde_json::from_str(raw)?;
    values.get(action).cloned().ok_or_else(|| DomainError::Config("该云 API 缺少测试样本".into()))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub location: String,
    pub style: String,
    pub schema: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub action: String,
    pub version: String,
    pub method: String,
    pub path: String,
    pub style: String,
    pub read_only: bool,
    pub parameters: Vec<Parameter>,
}
pub fn contracts(service: AliCloudService) -> DomainResult<Vec<Contract>> {
    let raw = match service {
        AliCloudService::Cms => include_str!("contracts/cms.json"),
        AliCloudService::Apig => include_str!("contracts/apig.json"),
        AliCloudService::Mse => include_str!("contracts/mse.json"),
        AliCloudService::Privatelink => include_str!("contracts/privatelink.json"),
        AliCloudService::SchedulerX3 => include_str!("contracts/schedulerx3.json"),
        AliCloudService::AgentTeams => include_str!("contracts/agentteams.json"),
    };
    serde_json::from_str(raw).map_err(|_| DomainError::Internal("内置云 API 定义无效".into()))
}
pub fn contract(service: AliCloudService, action: &str) -> DomainResult<Contract> {
    contracts(service)?
        .into_iter()
        .find(|entry| entry.action == action)
        .ok_or_else(|| DomainError::Validation(format!("{} 不支持操作 {action}", service.as_str())))
}
impl Contract {
    pub fn validate(&self, input: &Value) -> DomainResult<()> {
        let object = input.as_object().ok_or_else(|| DomainError::Validation("云 API 参数必须是 JSON 对象".into()))?;
        if input.to_string().len() > 128 * 1024 {
            return Err(DomainError::Validation("每次云 API 参数最多 128 KiB".into()));
        }
        for key in object.keys() {
            if !self.parameters.iter().any(|parameter| parameter.name == *key) {
                return Err(DomainError::Validation(format!("{} 不接受参数 {key}", self.action)));
            }
        }
        for parameter in &self.parameters {
            validation::validate(&parameter.schema, object.get(&parameter.name), &parameter.name)?;
        }
        Ok(())
    }
    pub fn build(&self, client: &RpcClient, input: &Value) -> DomainResult<RpcRequest> {
        self.validate(input)?;
        let mut query = Vec::new();
        let mut form = Vec::new();
        let mut path = self.path.clone();
        let mut body = String::new();
        for parameter in &self.parameters {
            let Some(value) = input.get(&parameter.name).filter(|value| !value.is_null()) else { continue };
            match parameter.location.as_str() {
                "path" => {
                    let raw = scalar(value)?;
                    if raw.is_empty() || matches!(raw.as_str(), "." | "..") || raw.contains(['/', '\\']) {
                        return Err(DomainError::Validation(format!("{} 不是有效资源标识", parameter.name)));
                    }
                    path = path.replace(&format!("{{{}}}", parameter.name), &percent_encode(&raw));
                }
                "body" => body = value.to_string(),
                "query" | "formData" => {
                    let dest = if parameter.location == "query" { &mut query } else { &mut form };
                    if parameter.style == "json" {
                        dest.push((parameter.name.clone(), value.to_string()));
                    } else {
                        flatten(&parameter.name, value, dest)?;
                    }
                }
                _ => return Err(DomainError::Internal("不支持的云 API 参数位置".into())),
            }
        }
        if path.contains(['{', '}']) {
            return Err(DomainError::Validation("请填写全部资源路径参数".into()));
        }
        if self.style == "ROA" {
            client.build_roa(&RoaCall {
                action: &self.action,
                version: &self.version,
                method: &self.method,
                path: &path,
                params: &query,
                body: &body,
            })
        } else if !form.is_empty() {
            client.build_form(&self.action, &self.version, &query, &form)
        } else {
            client.build(&self.action, &self.version, &self.method, &query)
        }
    }
    pub async fn call(&self, client: &RpcClient, input: &Value) -> DomainResult<RpcResponse> {
        client.execute_async(&self.build(client, input)?).await
    }
}
fn scalar(value: &Value) -> DomainResult<String> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Number(_) | Value::Bool(_) => Ok(value.to_string()),
        _ => Err(DomainError::Validation("云 API 标量参数类型无效".into())),
    }
}
fn flatten(key: &str, value: &Value, out: &mut Vec<(String, String)>) -> DomainResult<()> {
    match value {
        Value::Null => {}
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                flatten(&format!("{key}.{}", index + 1), value, out)?;
            }
        }
        Value::Object(values) => {
            for (name, value) in values {
                flatten(&format!("{key}.{name}"), value, out)?;
            }
        }
        _ => out.push((key.into(), scalar(value)?)),
    }
    Ok(())
}
