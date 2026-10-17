//! 由 `apig.rs` 拆分：`parse_gateways` 等 4 个函数（纯搬移，逻辑不变）。
use super::*;

/// 解析网关列表响应。
#[must_use]
pub fn parse_gateways(body: &serde_json::Value) -> Vec<ApigGateway> {
    json_array(body, &["Gateway", "Gateways"])
        .into_iter()
        .map(|item| ApigGateway {
            gateway_id: json_str(item, "GatewayId").or_else(|| json_str(item, "Id")).unwrap_or_default(),
            name: json_str(item, "Name").or_else(|| json_str(item, "GatewayName")).unwrap_or_default(),
            spec: json_str(item, "Spec").unwrap_or_default(),
            status: json_str(item, "Status").unwrap_or_else(|| "Unknown".to_string()),
            vpc_id: json_str(item, "VpcId").unwrap_or_default(),
            region: json_str(item, "RegionId").unwrap_or_default(),
            tags: item
                .get("Tags")
                .and_then(serde_json::Value::as_array)
                .map(|tags| {
                    tags.iter()
                        .filter_map(|t| json_str(t, "Key").zip(json_str(t, "Value")))
                        .map(|(k, v)| format!("{k}:{v}"))
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect()
}

/// 解析路由列表响应。
#[must_use]
pub fn parse_routes(body: &serde_json::Value) -> Vec<ApigRoute> {
    json_array(body, &["Route", "Routes"])
        .into_iter()
        .map(|item| ApigRoute {
            route_id: json_str(item, "RouteId").or_else(|| json_str(item, "Id")).unwrap_or_default(),
            gateway_id: json_str(item, "GatewayId").unwrap_or_default(),
            name: json_str(item, "Name").or_else(|| json_str(item, "RouteName")).unwrap_or_default(),
            path: json_str(item, "Path").or_else(|| json_str(item, "MatchPath")).unwrap_or_default(),
            upstream: json_str(item, "Upstream").or_else(|| json_str(item, "Backend")).unwrap_or_default(),
            plugins: item
                .get("Plugins")
                .and_then(serde_json::Value::as_array)
                .map(|p| p.iter().filter_map(|v| v.as_str().map(ToString::to_string)).collect())
                .unwrap_or_default(),
        })
        .collect()
}

/// 解析插件列表响应。
#[must_use]
pub fn parse_plugins(body: &serde_json::Value) -> Vec<ApigPlugin> {
    json_array(body, &["Plugin", "Plugins"])
        .into_iter()
        .map(|item| ApigPlugin {
            plugin_id: json_str(item, "PluginId").or_else(|| json_str(item, "Id")).unwrap_or_default(),
            name: json_str(item, "PluginName").or_else(|| json_str(item, "Name")).unwrap_or_default(),
            plugin_type: json_str(item, "PluginType").unwrap_or_default(),
            enabled: item.get("Enabled").and_then(serde_json::Value::as_bool).unwrap_or(true),
            config: item.get("PluginConfig").cloned().unwrap_or(serde_json::Value::Null),
        })
        .collect()
}

/// 把网关清单映射为云资源映射（供资产发现）。
#[must_use]
pub fn gateways_to_resource_mappings(
    tenant_id: agf_core::ids::TenantId,
    integration_id: agf_core::ids::Id,
    gateways: &[ApigGateway],
) -> Vec<agf_core::cloud::CloudResourceMapping> {
    let now = Timestamp::now();
    gateways
        .iter()
        .map(|g| agf_core::cloud::CloudResourceMapping {
            id: agf_core::ids::deterministic_id("aiguardfabric.alicloud.apig", &g.gateway_id),
            tenant_id,
            integration_id,
            service: AliCloudService::Apig,
            resource_id: g.gateway_id.clone(),
            resource_kind: "apig-gateway".to_string(),
            asset_id: None,
            attributes: BTreeMap::from([
                ("name".to_string(), serde_json::Value::from(g.name.clone())),
                ("spec".to_string(), serde_json::Value::from(g.spec.clone())),
                ("vpc_id".to_string(), serde_json::Value::from(g.vpc_id.clone())),
                ("status".to_string(), serde_json::Value::from(g.status.clone())),
                ("region".to_string(), serde_json::Value::from(g.region.clone())),
                ("tags".to_string(), serde_json::to_value(&g.tags).unwrap_or(serde_json::Value::Null)),
            ]),
            discovered_at: now,
            updated_at: now,
            stale: false,
        })
        .collect()
}
