//! 资源组元数据（权限点 / 资产类型 / 视图投影 / 详情键名）与分组列表、详情、`kind` 解析。

use super::*;

// ===========================================================================
// 分组元数据
// ===========================================================================

/// 资源组（权限点 / 资产类型 / 视图 / 详情键名的唯一来源）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Group {
    /// Agent。
    Agents,
    /// MCP Server（含 MCP Client）。
    Mcps,
    /// Skill。
    Skills,
    /// 模型端点。
    ModelEndpoints,
}

impl Group {
    /// RBAC 资源组名（权限点前缀）。
    const fn permission(self) -> &'static str {
        match self {
            Self::Agents => "agents",
            Self::Mcps => "mcps",
            Self::Skills => "skills",
            Self::ModelEndpoints => "models",
        }
    }

    /// 归属的资产类型集合。
    const fn kinds(self) -> &'static [AssetKind] {
        match self {
            Self::Agents => &[AssetKind::Agent],
            Self::Mcps => &[AssetKind::McpServer, AssetKind::McpClient],
            Self::Skills => &[AssetKind::Skill],
            Self::ModelEndpoints => &[AssetKind::ModelEndpoint],
        }
    }

    /// 404 用的实体名。
    const fn entity(self) -> &'static str {
        match self {
            Self::Agents => "agent",
            Self::Mcps => "mcp-server",
            Self::Skills => "skill",
            Self::ModelEndpoints => "model-endpoint",
        }
    }

    /// 详情响应的包裹键名。
    const fn detail_key(self) -> &'static str {
        match self {
            Self::Agents => "agent",
            Self::Mcps => "mcp_server",
            Self::Skills => "skill",
            Self::ModelEndpoints => "model_endpoint",
        }
    }

    /// 台账资产 → 对外视图。
    ///
    /// # Errors
    /// 序列化失败（视图只含基础类型，实际不会发生）。
    fn project(self, asset: &Asset) -> Result<serde_json::Value, DomainError> {
        Ok(match self {
            Self::Agents => serde_json::to_value(agent_view(asset))?,
            Self::Mcps => serde_json::to_value(mcp_view(asset))?,
            Self::Skills => serde_json::to_value(skill_view(asset))?,
            Self::ModelEndpoints => serde_json::to_value(model_endpoint_view(asset))?,
        })
    }
}

/// 分组列表：类型过滤 → 视图投影 → `q`/`sort`/分页/字段裁剪。
pub(super) async fn list_group(
    state: &AppState,
    principal: &Principal,
    query: &ListQuery,
    group: Group,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(state, group.permission(), "read")?;
    let kinds: Vec<AssetKind> = match query.filter("kind") {
        // `kind` 只能在本资源组的类型集合内收窄（如 `/mcps?kind=mcp-client`）：
        // 跨组取值会让"视图形状"与资源组不一致，因此按参数非法处理。
        Some(raw) => {
            let kind = parse_asset_kind(raw)?;
            if !group.kinds().contains(&kind) {
                let allowed = group.kinds().iter().map(AssetKind::as_str).collect::<Vec<_>>().join(" / ");
                return Err(ApiError::new(DomainError::Validation(format!(
                    "资源组 {} 不支持 kind={raw}（可选：{allowed}）",
                    group.permission()
                ))));
            }
            vec![kind]
        }
        None => group.kinds().to_vec(),
    };
    let mut filters = crate::store::AssetSelection::from_query(query)?;
    filters.kinds = kinds.iter().map(|kind| kind.as_str().to_string()).collect();
    let mut request = query.to_page_request();
    if request.sort_by.is_none() {
        request.sort_by = Some("name".into());
        request.sort_dir = agf_core::pagination::SortDirection::Asc;
    }
    let assets = state.store.asset_page_durable(principal.tenant, &request, filters).await?;
    let views = assets.items.iter().map(|asset| group.project(asset)).collect::<Result<Vec<_>, _>>()?;
    let page = agf_core::pagination::Page::new(views, assets.total.unwrap_or(0), &request);
    Ok(Json(query.render_page(&page)?))
}

/// 分组详情。
pub(super) async fn get_group_asset(
    state: &AppState,
    principal: &Principal,
    id: &str,
    group: Group,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(state, group.permission(), "read")?;
    let asset_id = parse_id(id, "asset")?;
    let not_found = || ApiError::new(DomainError::NotFound { entity: group.entity(), id: id.to_string() });
    let Some(asset) = state.store.asset_get_durable(principal.tenant, asset_id).await? else {
        return Err(not_found());
    };
    if !group.kinds().contains(&asset.kind) {
        // 类型不匹配按"该资源组内不存在"处理，避免用 /agents/{mcp 的 id} 探测其他资源组
        return Err(not_found());
    }
    let mut body = serde_json::Map::new();
    body.insert(group.detail_key().to_string(), group.project(&asset)?);
    Ok(Json(serde_json::Value::Object(body)))
}

/// 解析 `kind` 过滤条件（兼容前端 `mcp` / `model` / `tool` 别名）。
///
/// # Errors
/// 未知资产类型。
fn parse_asset_kind(raw: &str) -> Result<AssetKind, ApiError> {
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    let mapped = match normalized.as_str() {
        "mcp" => "mcp-server",
        "model" => "model-endpoint",
        "tool" => "skill",
        other => other,
    };
    AssetKind::parse(mapped).map_err(|e| ApiError::new(DomainError::Validation(e)))
}
