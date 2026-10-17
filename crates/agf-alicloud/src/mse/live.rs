//! Public MSE APIs: bounded pagination and explicit configuration publication.
use super::*;
use crate::openapi::contract;
use serde_json::{Value, json};

impl MseAdapter {
    fn instance(&self) -> DomainResult<&str> {
        self.instance_id
            .as_deref()
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| DomainError::Config("MSE 服务/配置操作需要 instance_id".into()))
    }

    async fn pages(&self, action: &str, mut input: Value, path: &str, total: &str) -> DomainResult<Vec<Value>> {
        let api = contract(AliCloudService::Mse, action)?;
        let page_key = if action == "ListGateway" { "PageNumber" } else { "PageNum" };
        let mut result = Vec::new();
        let mut previous = None;
        for page in 1..=20 {
            input[page_key] = json!(page);
            input["PageSize"] = json!(100);
            let response = api.call(self.live_client()?, &input).await?;
            let items = response
                .body
                .pointer(path)
                .and_then(Value::as_array)
                .ok_or_else(|| DomainError::Parse(format!("MSE {action} 响应缺少 {path} 数组")))?;
            if !items.is_empty() && previous.as_ref() == Some(items) {
                return Err(DomainError::Parse("MSE 返回重复分页，盘点未完成".into()));
            }
            let count = response.body.pointer(total).and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()));
            result.extend(items.iter().cloned());
            if count.is_some_and(|count| result.len() as u64 >= count) || (count.is_none() && items.len() < 100) {
                return Ok(result);
            }
            if items.is_empty() {
                return Err(DomainError::Parse("MSE 分页提前结束，盘点未完成".into()));
            }
            previous = Some(items.clone());
        }
        Err(DomainError::Validation("MSE 盘点超过 20 页，请缩小实例/命名空间范围".into()))
    }
}

#[async_trait]
impl MseApi for MseAdapter {
    async fn pull_clusters(&self) -> DomainResult<Vec<MseCluster>> {
        if self.core.is_mock() {
            return Ok(mock::mse_clusters());
        }
        let items = self.pages("ListClusters", json!({"RegionId":self.core.region}), "/Data", "/TotalCount").await?;
        Ok(parse_clusters(&json!({"Data":items})))
    }

    async fn pull_services(&self) -> DomainResult<Vec<MseService>> {
        if self.core.is_mock() {
            return Ok(mock::mse_services());
        }
        let instance = self.instance()?;
        let items = self
            .pages(
                "ListAnsServices",
                json!({"InstanceId":instance,"NamespaceId":self.namespace,
            "RegionId":self.core.region,"HasIpCount":"true"}),
                "/Data",
                "/TotalCount",
            )
            .await?;
        let mut services = parse_services(&json!({"Data":items}));
        for service in &mut services {
            if service.service_name.is_empty() {
                return Err(DomainError::Parse("MSE 服务缺少名称".into()));
            }
            service.cluster_id = instance.into();
            service.namespace.clone_from(&self.namespace);
        }
        Ok(services)
    }

    async fn pull_configs(&self) -> DomainResult<Vec<MseConfig>> {
        if self.core.is_mock() {
            return Ok(mock::mse_configs());
        }
        let instance = self.instance()?;
        let items = self
            .pages(
                "ListNacosConfigs",
                json!({"InstanceId":instance,"NamespaceId":self.namespace}),
                "/Configurations",
                "/TotalCount",
            )
            .await?;
        if items.len() > 200 {
            return Err(DomainError::Validation("配置详情读取最多 200 项，请缩小命名空间范围".into()));
        }
        let mut configs = Vec::new();
        for item in items {
            let response = contract(AliCloudService::Mse, "GetNacosConfig")?
                .call(
                    self.live_client()?,
                    &json!({
                        "InstanceId":instance,"NamespaceId":self.namespace,"DataId":item["DataId"],"Group":item["Group"]
                    }),
                )
                .await?;
            let mut detail = response
                .body
                .get("Configuration")
                .filter(|v| v.is_object())
                .cloned()
                .ok_or_else(|| DomainError::Parse("MSE 配置详情缺少 Configuration".into()))?;
            if detail.get("Content").and_then(Value::as_str).is_none() {
                return Err(DomainError::Parse("MSE 配置详情缺少 Content，不能当作空配置".into()));
            }
            detail["NamespaceId"] = json!(self.namespace);
            configs.extend(parse_configs(&json!({"Configurations":[detail]})));
        }
        Ok(configs)
    }

    async fn push_config(&self, config: &MseConfig) -> DomainResult<String> {
        if self.core.is_mock() {
            return Ok(agf_core::secret::content_hash(&config.content).chars().take(16).collect());
        }
        // The console RPC documents Md5 as an MD5 value, not a verified CAS precondition.
        // Preserve its request shape; explicit CAS uses config_cas and the engine casMd5 header.
        let action = if config.md5.is_empty() { "CreateNacosConfig" } else { "UpdateNacosConfig" };
        let mut input = json!({"InstanceId":self.instance()?,"NamespaceId":config.namespace,
            "DataId":config.data_id,"Group":config.group_name,"Content":config.content});
        if !config.md5.is_empty() {
            input["Md5"] = json!(config.md5);
        }
        let response = contract(AliCloudService::Mse, action)?.call(self.live_client()?, &input).await?;
        json_str(&response.body, "RequestId").ok_or_else(|| DomainError::Parse("MSE 发布响应缺少 RequestId".into()))
    }

    async fn pull_gateways(&self) -> DomainResult<Vec<MseGateway>> {
        if self.core.is_mock() {
            return Ok(mock::mse_gateways());
        }
        let items = self.pages("ListGateway", json!({}), "/Data/Result", "/Data/TotalSize").await?;
        items
            .iter()
            .map(|item| {
                let gateway_id = json_str(item, "GatewayUniqueId")
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| DomainError::Parse("MSE 网关缺少 GatewayUniqueId".into()))?;
                Ok(MseGateway {
                    gateway_id,
                    name: json_str(item, "Name").unwrap_or_default(),
                    version: json_str(item, "GatewayVersion")
                        .or_else(|| json_str(item, "CurrentVersion"))
                        .unwrap_or_default(),
                    traffic_kind: json_str(item, "GatewayType").unwrap_or_default(),
                    status: json_str(item, "StatusDesc").unwrap_or_else(|| "Unknown".into()),
                })
            })
            .collect()
    }
}
