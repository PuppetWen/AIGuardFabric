//! Asset topology and graph projection helpers.

use super::*;

// ===========================================================================
// 拓扑
// ===========================================================================

/// 资产拓扑（`GET /api/v1/topology`）。
///
/// # Errors
/// 权限不足（`assets:read`）或存储错误。
pub(super) async fn topology(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<TopologyGraphView>> {
    principal.require(&state, "assets", "read")?;
    let assets = state.store.asset_list_all_durable(principal.tenant).await?;

    // 只有能映射到前端 5 种节点类型的资产才上图；其余（凭据/算力节点/IDE 插件/采集器/其他）
    // 在 domain.ts 的 `TopologyNodeType` 里没有取值，宁可不画也不篡改类型。
    let by_id: BTreeMap<Id, &Asset> = assets.iter().map(|asset| (asset.id, asset)).collect();
    let by_name: BTreeMap<String, Id> = assets.iter().map(|asset| (asset.name.to_lowercase(), asset.id)).collect();

    let mut nodes: Vec<TopologyNodeView> = Vec::new();
    let mut node_types: BTreeMap<Id, &'static str> = BTreeMap::new();
    for asset in &assets {
        let Some(node_type) = topology_node_type(asset.kind) else { continue };
        node_types.insert(asset.id, node_type);
        nodes.push(TopologyNodeView {
            id: asset.id.to_string(),
            label: asset.name.clone(),
            node_type: node_type.to_string(),
            risk_score: asset_risk_score(asset),
            shadow: asset.lifecycle != LifecycleState::Production && asset.discovery_source != DiscoverySource::Manual,
            classification: Some(asset.data_class.as_str().to_string()),
            detail: format!(
                "{} · {} · {}",
                asset.kind.as_str(),
                asset.endpoint.clone().unwrap_or_else(|| "-".to_string()),
                asset.owner.clone().unwrap_or_else(|| "-".to_string())
            ),
        });
    }

    // 边：`Asset.dependencies`（台账真实关系）+ `attributes` 里的引用键（发现侧写入的扩展关系）。
    let mut edges: Vec<TopologyEdgeView> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for asset in &assets {
        let Some(source_type) = node_types.get(&asset.id).copied() else { continue };
        let mut targets: Vec<Id> = asset.dependencies.clone();
        for key in ATTRIBUTE_REFERENCE_KEYS {
            targets.extend(attribute_references(asset, key, &by_name));
        }
        for target in targets {
            if target == asset.id {
                continue;
            }
            let Some(target_type) = node_types.get(&target).copied() else { continue };
            let edge_id = format!("{}->{}", asset.id, target);
            if !seen.insert(edge_id.clone()) {
                continue;
            }
            edges.push(TopologyEdgeView {
                id: edge_id,
                source: asset.id.to_string(),
                target: target.to_string(),
                kind: topology_edge_kind(source_type, target_type).to_string(),
                egress: by_id.get(&target).is_some_and(|t| is_egress_target(t, target_type)),
                calls_24h: attribute_u64(asset, "calls_24h").and_then(|v| i64::try_from(v).ok()).unwrap_or(0),
            });
        }
    }

    let egress_paths = egress_paths(&node_types, &edges);
    Ok(Json(TopologyGraphView { nodes, edges, egress_paths }))
}

/// `attributes` 中按引用解析依赖的键（发现侧写入的扩展关系）。
const ATTRIBUTE_REFERENCE_KEYS: [&str; 7] =
    ["mcp_server", "mcp_servers", "tools", "datasources", "data_sources", "models", "model"];

/// 资产类型 → 拓扑节点类型；无法映射时 `None`（不上图）。
pub(super) fn topology_node_type(kind: AssetKind) -> Option<&'static str> {
    match kind {
        AssetKind::Agent => Some("agent"),
        AssetKind::McpServer | AssetKind::McpClient => Some("mcp"),
        AssetKind::Skill | AssetKind::PromptTemplate => Some("tool"),
        AssetKind::DataSource | AssetKind::RagKb | AssetKind::VectorStore => Some("datasource"),
        AssetKind::ModelEndpoint => Some("model"),
        _ => None,
    }
}

/// 拓扑边类型（前端 `TopologyEdgeKind`）。
pub(super) fn topology_edge_kind(source: &str, target: &str) -> &'static str {
    match (source, target) {
        ("agent", "mcp" | "tool" | "model") => "invokes",
        ("mcp", "tool") => "exposes",
        ("tool" | "mcp", "model") | ("agent", "datasource") => "routes-to",
        (_, "datasource") => "reads",
        (_, "model") => "routes-to",
        _ => "invokes",
    }
}

/// 边是否携带数据出域：目标是机密级及以上数据源，或目标是**非本地**模型端点。
fn is_egress_target(target: &Asset, target_type: &str) -> bool {
    match target_type {
        "datasource" => matches!(target.data_class, DataClass::Confidential | DataClass::Restricted),
        "model" => !attribute_bool(target, "local_deployment").unwrap_or(false),
        _ => false,
    }
}

/// 从 `attributes.<key>` 解析依赖引用（支持 id 字符串、名称、字符串数组）。
fn attribute_references(asset: &Asset, key: &str, by_name: &BTreeMap<String, Id>) -> Vec<Id> {
    let Some(value) = asset.attributes.get(key) else { return Vec::new() };
    let mut out = Vec::new();
    collect_references(value, by_name, &mut out);
    out
}

/// 递归收集引用（对象取 `id` 字段，字符串按 UUID 或名称解析）。
fn collect_references(value: &serde_json::Value, by_name: &BTreeMap<String, Id>, out: &mut Vec<Id>) {
    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if let Ok(id) = Id::parse(trimmed) {
                out.push(id);
            } else if let Some(id) = by_name.get(&trimmed.to_lowercase()) {
                out.push(*id);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_references(item, by_name, out);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(text)) = map.get("id") {
                if let Ok(id) = Id::parse(text.trim()) {
                    out.push(id);
                }
            }
            if let Some(serde_json::Value::String(text)) = map.get("name") {
                if let Some(id) = by_name.get(&text.trim().to_lowercase()) {
                    out.push(*id);
                }
            }
        }
        _ => {}
    }
}

/// 枚举从 agent 节点出发、以出域边结束的路径（有界：深度 ≤ [`TOPOLOGY_MAX_DEPTH`]、条数 ≤
/// [`TOPOLOGY_MAX_PATHS`]）。
pub(super) fn egress_paths(node_types: &BTreeMap<Id, &'static str>, edges: &[TopologyEdgeView]) -> Vec<Vec<String>> {
    let adjacency: Vec<(String, String, bool)> =
        edges.iter().map(|edge| (edge.source.clone(), edge.target.clone(), edge.egress)).collect();
    let mut paths: Vec<Vec<String>> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for (id, node_type) in node_types {
        if *node_type != "agent" {
            continue;
        }
        let start = id.to_string();
        let mut stack: Vec<(String, Vec<String>)> = vec![(start.clone(), vec![start.clone()])];
        while let Some((current, path)) = stack.pop() {
            if path.len() > TOPOLOGY_MAX_DEPTH || paths.len() >= TOPOLOGY_MAX_PATHS {
                break;
            }
            for (source, target, egress) in &adjacency {
                if source != &current || path.contains(target) {
                    continue;
                }
                let mut next = path.clone();
                next.push(target.clone());
                if *egress {
                    let key = next.join(">");
                    if seen.insert(key) {
                        paths.push(next);
                    }
                    continue;
                }
                stack.push((target.clone(), next));
            }
        }
    }
    paths.truncate(TOPOLOGY_MAX_PATHS);
    paths
}
