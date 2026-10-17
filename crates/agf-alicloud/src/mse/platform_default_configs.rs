//! 由 `mse.rs` 拆分：`platform_default_configs` 等 6 个函数（纯搬移，逻辑不变）。
use super::*;

/// 平台默认下发的 Nacos 配置（策略 + 配额）。
#[must_use]
pub fn platform_default_configs() -> Vec<MseConfig> {
    let content = |s: &str| s.to_string();
    let config = |data_id: &str, raw: String| MseConfig {
        data_id: data_id.to_string(),
        group_name: "AGF".to_string(),
        namespace: "public".to_string(),
        md5: agf_core::secret::content_hash(&raw),
        content: raw,
    };
    vec![
        config("agf-policy.json", content("{\"version\":1,\"mode\":\"enforce\"}")),
        config("agf-quota.json", content("{\"tokens\":1000000,\"requests\":50000}")),
    ]
}

/// 解析集群列表响应。
#[must_use]
pub fn parse_clusters(body: &serde_json::Value) -> Vec<MseCluster> {
    json_array(body, &["Data", "Cluster", "Clusters"])
        .into_iter()
        .map(|item| MseCluster {
            cluster_id: json_str(item, "ClusterId").or_else(|| json_str(item, "InstanceId")).unwrap_or_default(),
            name: json_str(item, "ClusterAliasName")
                .or_else(|| json_str(item, "Name"))
                .or_else(|| json_str(item, "ClusterName"))
                .unwrap_or_default(),
            cluster_type: json_str(item, "ClusterType").unwrap_or_else(|| "Nacos".to_string()),
            version: json_str(item, "AppVersion").or_else(|| json_str(item, "Version")).unwrap_or_default(),
            instance_count: json_i64(item, "InstanceCount")
                .or_else(|| json_i64(item, "IpCount"))
                .unwrap_or(0)
                .max(0)
                .unsigned_abs() as u32,
            vpc_id: json_str(item, "VpcId").unwrap_or_default(),
            status: json_str(item, "InitStatus")
                .or_else(|| json_str(item, "Status"))
                .unwrap_or_else(|| "Unknown".to_string()),
        })
        .collect()
}

/// 解析 Nacos 服务列表响应。
#[must_use]
pub fn parse_services(body: &serde_json::Value) -> Vec<MseService> {
    json_array(body, &["Data", "Service", "Services"])
        .into_iter()
        .map(|item| MseService {
            namespace: json_str(item, "NamespaceId").or_else(|| json_str(item, "Namespace")).unwrap_or_default(),
            group_name: json_str(item, "GroupName").or_else(|| json_str(item, "Group")).unwrap_or_default(),
            service_name: json_str(item, "ServiceName").or_else(|| json_str(item, "Name")).unwrap_or_default(),
            cluster_id: json_str(item, "ClusterId").unwrap_or_default(),
            instance_count: json_i64(item, "InstanceCount")
                .or_else(|| json_i64(item, "IpCount"))
                .unwrap_or(0)
                .max(0)
                .unsigned_abs() as u32,
            healthy_count: json_i64(item, "HealthyInstanceCount").unwrap_or(0).max(0).unsigned_abs() as u32,
            metadata: item
                .get("Metadata")
                .and_then(serde_json::Value::as_object)
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default(),
        })
        .collect()
}

/// 解析配置列表响应。
#[must_use]
pub fn parse_configs(body: &serde_json::Value) -> Vec<MseConfig> {
    json_array(body, &["Configurations", "Config", "Configs"])
        .into_iter()
        .map(|item| MseConfig {
            data_id: json_str(item, "DataId").unwrap_or_default(),
            group_name: json_str(item, "Group").or_else(|| json_str(item, "GroupName")).unwrap_or_default(),
            namespace: json_str(item, "NamespaceId").unwrap_or_default(),
            content: json_str(item, "Content").unwrap_or_default(),
            md5: json_str(item, "Md5").unwrap_or_default(),
        })
        .collect()
}

/// 把 Nacos 服务清单映射为云资源映射（§5.2 资产自动发现源）。
#[must_use]
pub fn services_to_resource_mappings(
    tenant_id: TenantId,
    integration_id: Id,
    services: &[MseService],
) -> Vec<CloudResourceMapping> {
    let now = Timestamp::now();
    services
        .iter()
        .map(|service| {
            let mut attributes: BTreeMap<String, serde_json::Value> = service.metadata.clone();
            attributes.insert("namespace".to_string(), serde_json::Value::from(service.namespace.clone()));
            attributes.insert("group".to_string(), serde_json::Value::from(service.group_name.clone()));
            attributes.insert("instance_count".to_string(), serde_json::Value::from(service.instance_count));
            attributes.insert("healthy_count".to_string(), serde_json::Value::from(service.healthy_count));
            CloudResourceMapping {
                id: deterministic_id("aiguardfabric.alicloud.mse", &service.fingerprint()),
                tenant_id,
                integration_id,
                service: AliCloudService::Mse,
                resource_id: service.unique_key(),
                resource_kind: format!("mse-{}", service.asset_kind().as_str()),
                asset_id: None,
                attributes,
                discovered_at: now,
                updated_at: now,
                // 不健康（无健康实例）的服务标记 stale：云侧可能已下线，但**不删除**台账
                stale: !service.is_healthy(),
            }
        })
        .collect()
}

/// 把 Nacos 服务清单转换为平台资产（供 `AssetRepo::upsert` 直接落库）。
#[must_use]
pub fn services_to_assets(tenant_id: TenantId, services: &[MseService]) -> Vec<Asset> {
    services
        .iter()
        .map(|service| {
            let fingerprint = service.fingerprint();
            let mut asset = Asset::new(tenant_id, service.asset_kind(), service.service_name.clone(), &fingerprint);
            asset.id = deterministic_id(NS_ASSET, &fingerprint);
            asset.protocol = service.protocol();
            asset.endpoint = service.meta_str("endpoint").map(ToString::to_string);
            asset.vendor = service.meta_str("vendor").map(ToString::to_string);
            asset.version = service.meta_str("version").map(ToString::to_string);
            asset.runtime = Some("k8s".to_string());
            asset.network_zone = Some("endpoint".to_string());
            asset.cloud_resource_id = Some(service.unique_key());
            asset.data_class = service.data_class();
            asset.discovery_source = DiscoverySource::CloudApi;
            asset.tags = vec![format!("mse:{}", service.cluster_id), format!("ns:{}", service.namespace)];
            asset.attributes = service.metadata.clone();
            asset
        })
        .collect()
}
