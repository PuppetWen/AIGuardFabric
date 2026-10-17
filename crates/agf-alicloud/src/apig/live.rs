//! APIG uses ROA paths and ACS3 signatures, not RPC action query strings.
use super::*;
use crate::openapi::contract;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

impl ApigAdapter {
    async fn pages(&self, action: &str, mut input: Value) -> DomainResult<Vec<Value>> {
        let api = contract(AliCloudService::Apig, action)?;
        let mut result = Vec::new();
        let mut previous = None;
        for page in 1..=20 {
            input["pageNumber"] = json!(page);
            input["pageSize"] = json!(100);
            let response = api.call(self.live_client()?, &input).await?;
            let items = response
                .body
                .pointer("/data/items")
                .and_then(Value::as_array)
                .ok_or_else(|| DomainError::Parse(format!("APIG {action} 缺少 data.items")))?;
            if !items.is_empty() && previous.as_ref() == Some(items) {
                return Err(DomainError::Parse("APIG 返回重复页，盘点未完成".into()));
            }
            let total = response.body.pointer("/data/totalSize").and_then(Value::as_u64);
            result.extend(items.iter().cloned());
            if total.is_some_and(|n| result.len() as u64 >= n) || (total.is_none() && items.len() < 100) {
                return Ok(result);
            }
            if items.is_empty() {
                return Err(DomainError::Parse("APIG 分页提前结束".into()));
            }
            previous = Some(items.clone());
        }
        Err(DomainError::Validation("APIG 超过 20 页，请按网关缩小范围".into()))
    }
}

fn string(value: &Value, path: &str) -> String {
    value.pointer(path).and_then(Value::as_str).unwrap_or_default().into()
}
fn required(value: &Value, path: &str) -> DomainResult<String> {
    let value = string(value, path);
    if value.is_empty() { Err(DomainError::Parse(format!("APIG 响应缺少 {path}"))) } else { Ok(value) }
}

#[async_trait]
impl ApigApi for ApigAdapter {
    async fn pull_gateways(&self) -> DomainResult<Vec<ApigGateway>> {
        if self.core.is_mock() {
            return Ok(mock::apig_gateways());
        }
        self.pages("ListGateways", json!({}))
            .await?
            .iter()
            .map(|item| {
                Ok(ApigGateway {
                    gateway_id: required(item, "/gatewayId")?,
                    name: string(item, "/name"),
                    spec: string(item, "/spec"),
                    status: string(item, "/status"),
                    vpc_id: string(item, "/vpc/vpcId"),
                    region: self.core.region.clone(),
                    tags: item["tags"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|tag| Some(format!("{}:{}", tag["key"].as_str()?, tag["value"].as_str()?)))
                        .collect(),
                })
            })
            .collect()
    }

    async fn pull_routes(&self, gateway_id: Option<&str>) -> DomainResult<Vec<ApigRoute>> {
        if self.core.is_mock() {
            let mut routes = mock::apig_routes();
            if let Some(id) = gateway_id {
                routes.retain(|route| route.gateway_id == id);
            }
            return Ok(routes);
        }
        let mut filter = json!({});
        if let Some(id) = gateway_id {
            filter["gatewayId"] = json!(id);
        }
        let apis = self.pages("ListHttpApis", filter).await?;
        let mut ids = std::collections::BTreeSet::new();
        for api in &apis {
            if let Some(id) = api["httpApiId"].as_str() {
                ids.insert(id.to_owned());
            }
            for version in api["versionedHttpApis"].as_array().into_iter().flatten() {
                ids.insert(required(version, "/httpApiId")?);
            }
        }
        if !apis.is_empty() && ids.is_empty() {
            return Err(DomainError::Parse("APIG API 清单缺少 httpApiId".into()));
        }
        if ids.len() > 100 {
            return Err(DomainError::Validation("一次最多盘点 100 个 HTTP API，请按网关缩小范围".into()));
        }
        let mut result = Vec::new();
        for id in ids {
            let mut input = json!({"httpApiId":id});
            if let Some(id) = gateway_id {
                input["gatewayId"] = json!(id);
            }
            for item in self.pages("ListHttpApiRoutes", input).await? {
                result.push(ApigRoute {
                    route_id: required(&item, "/routeId")?,
                    gateway_id: gateway_id.unwrap_or_default().into(),
                    name: string(&item, "/name"),
                    path: string(&item, "/match/path/value"),
                    upstream: item
                        .pointer("/backend/services")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|service| service["serviceId"].as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                    plugins: Vec::new(),
                });
                if result.len() > 2000 {
                    return Err(DomainError::Validation("路由盘点超过 2000 项，请缩小范围".into()));
                }
            }
        }
        Ok(result)
    }

    async fn pull_plugins(&self) -> DomainResult<Vec<ApigPlugin>> {
        if self.core.is_mock() {
            return Ok(mock::apig_plugins());
        }
        self.pages("ListPlugins", json!({"withAttachmentInfo":true}))
            .await?
            .iter()
            .map(|item| {
                Ok(ApigPlugin {
                    plugin_id: required(item, "/pluginId")?,
                    name: string(item, "/pluginClassInfo/name"),
                    plugin_type: string(item, "/pluginClassInfo/pluginClassId"),
                    enabled: matches!(item.pointer("/attachmentInfo/enable"), Some(Value::Bool(true)))
                        || string(item, "/attachmentInfo/enable") == "true",
                    // ListPlugins does not contain raw config. Do not fabricate one.
                    config: Value::Null,
                })
            })
            .collect()
    }

    async fn push_policy(&self, gateway_id: &str, policy: &ApigPolicy) -> DomainResult<String> {
        if self.core.is_mock() {
            return Ok(format!("plugin-mock-{}", policy.kind.as_str()));
        }
        let client = self.live_client()?;
        let plugin = policy.config["plugin_id"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
            DomainError::Validation("请先安装实际插件，再提供 config.plugin_id 和 plugin_config 原文".into())
        })?;
        let raw = policy.config["plugin_config"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| DomainError::Validation("config.plugin_config 必须为所选插件的 YAML/JSON 原文".into()))?;
        if gateway_id.trim().is_empty() || raw.len() > 64 * 1024 {
            return Err(DomainError::Validation("网关不能为空，插件配置最多 64 KiB".into()));
        }
        let (resource_type, ids) = if policy.route_ids.is_empty() {
            ("Gateway", vec![gateway_id.to_string()])
        } else {
            ("GatewayRoute", policy.route_ids.clone())
        };
        let mut body = json!({"gatewayId":gateway_id,"pluginId":plugin,"pluginConfig":STANDARD.encode(raw),
            "enable":policy.enabled,"attachResourceType":resource_type,"attachResourceIds":ids});
        if let Some(environment) = policy.config["environment_id"].as_str() {
            body["environmentId"] = json!(environment);
        }
        let response =
            contract(AliCloudService::Apig, "CreatePluginAttachment")?.call(client, &json!({"body":body})).await?;
        required(&response.body, "/data/pluginAttachmentId")
    }

    async fn pull_access_logs(&self, req: &PullRequest) -> DomainResult<Vec<Value>> {
        if self.core.is_mock() {
            let mut logs = mock::apig_access_logs();
            if let Some(limit) = req.limit {
                logs.truncate(limit as usize);
            }
            return Ok(logs);
        }
        self.live_client()?;
        Err(DomainError::Config("APIG 无 ListAccessLogs API；请在日志源中接入该网关的 SLS/Kafka 访问日志".into()))
    }
}
