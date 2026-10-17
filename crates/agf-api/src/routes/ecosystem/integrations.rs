//! 集成适配器视图与路由（自 `routes/ecosystem.rs` 拆出，逻辑未变）。

use super::*;
use agf_core::ids::TenantId;

// ===========================================================================
// 集成适配器
// ===========================================================================

/// Vendor state is read from the tenant configuration and actual invocation history.
async fn device_adapter_views(
    state: &AppState,
    tenant: TenantId,
) -> agf_core::error::DomainResult<Vec<serde_json::Value>> {
    let (metadata, health) = crate::integration_store::snapshot(state, tenant).await?;
    let mut rows = Vec::new();
    for meta in metadata {
        let record = &health[&meta.name];
        let stored = crate::integration_store::load(state, tenant, &meta.name).await?;
        rows.push(serde_json::json!({
            "name":meta.name,"display_name":meta.display_name,"category":"device","vendor_category":meta.category,
            "configured":record.configured,"enabled":stored.is_some_and(|row| row.enabled),
            "mode":record.mode.as_str(),"real_implementation":meta.real_transport,
            "mock_location":meta.mock_location,"degradation":meta.degradation,"doc_anchor":meta.doc_anchor,
            "semantics":meta.semantics,"note":record.message,
        }));
    }
    Ok(rows)
}
pub(super) async fn alicloud_views(
    state: &AppState,
    tenant: TenantId,
) -> agf_core::error::DomainResult<Vec<serde_json::Value>> {
    crate::cloud_status::services(state, tenant).await
}

async fn llm_adapter_views(
    state: &AppState,
    tenant: TenantId,
) -> agf_core::error::DomainResult<Vec<serde_json::Value>> {
    let mock = state.config.force_mock();
    let endpoints = state
        .configurations
        .list::<crate::model_gateway::StoredEndpoint>(tenant, crate::model_gateway::ENDPOINT_KIND)
        .await?;
    Ok(LlmProvider::all()
        .into_iter()
        .map(|provider| {
            serde_json::json!({
                "name": provider.as_str(),
                "display_name": provider.as_str(),
                "category": "llm",
                "configured": endpoints.iter().any(|row|row.endpoint.provider==provider),
                "enabled": endpoints.iter().any(|row|row.endpoint.provider==provider && row.endpoint.enabled),
                "mode": if mock { "mock" } else { "live" },
                "real_implementation": true,
                "mock_location": "crates/agf-aigw/src/mock.rs",
                "degradation": "无 API Key 或 AGF_MOCK_MODE=1 时返回录制响应，平台不报错",
                "doc_anchor": "docs/adapter-spec.md#52-大模型厂商适配器agf-aigw",
            })
        })
        .collect())
}

/// 集成适配器总览（`GET /api/v1/integrations`）。
///
/// # Errors
/// 权限不足。
pub async fn list_integrations(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "integrations", "read")?;
    let mut adapters = alicloud_views(&state, principal.tenant).await?;
    adapters.extend(device_adapter_views(&state, principal.tenant).await?);
    adapters.extend(llm_adapter_views(&state, principal.tenant).await?);
    if let Some(category) = query.filter("category") {
        adapters.retain(|a| a.get("category").and_then(|c| c.as_str()) == Some(category));
    }
    if let Some(enabled) = query.filter_bool("enabled")? {
        adapters.retain(|a| a.get("enabled").and_then(serde_json::Value::as_bool).unwrap_or(false) == enabled);
    }
    Ok(Json(serde_json::json!({
        "items": adapters,
        "total": adapters.len(),
        "mock_mode": state.config.force_mock(),
        "degrade_on_missing": state.config.degrade_on_missing,
        "note": "阿里云 6 个服务适配器为「五适配器 + AgentTeams」；设备适配器与 LLM 适配器的降级行为见 docs/adapter-spec.md",
    })))
}

/// 单个适配器（`GET /api/v1/integrations/{name}`，name 为适配器名或服务名）。
///
/// # Errors
/// 适配器不存在。
pub async fn get_integration(
    State(state): State<AppState>,
    principal: Principal,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "integrations", "read")?;
    let mut adapters = alicloud_views(&state, principal.tenant).await?;
    adapters.extend(device_adapter_views(&state, principal.tenant).await?);
    adapters.extend(llm_adapter_views(&state, principal.tenant).await?);
    let wanted = name.trim().to_ascii_lowercase();
    let Some(found) = adapters.into_iter().find(|a| {
        a.get("name").and_then(|v| v.as_str()).is_some_and(|v| v.eq_ignore_ascii_case(&wanted))
            || a.get("service").and_then(|v| v.as_str()).is_some_and(|v| v.eq_ignore_ascii_case(&wanted))
    }) else {
        return Err(ApiError::new(DomainError::NotFound { entity: "integration", id: name }));
    };
    Ok(Json(serde_json::json!({ "integration": found })))
}

/// 适配器健康（`GET /api/v1/integrations/health`）。
///
/// # Errors
/// 权限不足或云适配器探测失败。
pub async fn integrations_health(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "integrations", "read")?;
    let mut health = std::collections::BTreeMap::new();
    for row in crate::cloud_status::services(&state, principal.tenant).await? {
        let name = row["name"].as_str().unwrap_or_default();
        let note = row["note"].as_str().unwrap_or_default();
        let mut record = agf_core::adapter::AdapterHealth::unconfigured(name, note);
        record.state = match row["health"].as_str() {
            Some("healthy") => agf_core::enums::HealthState::Healthy,
            Some("unhealthy") => agf_core::enums::HealthState::Unhealthy,
            Some("degraded") => agf_core::enums::HealthState::Degraded,
            _ => agf_core::enums::HealthState::Unconfigured,
        };
        health.insert(name.to_string(), record);
    }
    let (metadata, records) = crate::integration_store::snapshot(&state, principal.tenant).await?;
    for meta in metadata {
        if let Some(record) = records.get(&meta.name) {
            health.insert(meta.name.clone(), record.to_core_health(meta));
        }
    }
    let healthy = health.values().filter(|h| h.state.is_serving()).count();
    Ok(Json(serde_json::json!({
        "adapters": health,
        "summary": { "total": health.len(), "serving": healthy },
        "degraded_services": state.alicloud.degraded_services().iter().map(agf_core::enums::AliCloudService::as_str).collect::<Vec<_>>(),
    })))
}
