//! 生态类控制台端点：日志接入源 / 解析器、适配器、阿里云自检、Agent 团队与跨团队调用、服务绑定。

use super::*;

// ===========================================================================
// C. 生态与别名
// ===========================================================================

/// 接入面清单（`GET /api/v1/ingest/sources`）。
///
/// **别名**：与既有 `GET /api/v1/sources` 是**同一个处理器**（[`crate::routes::ingest::list_sources`]），
/// 响应也是同一份分页信封——控制台 `IngestPage` 正是按 `data?.data?.items` 消费的。
///
/// # Errors
/// 权限不足（`sources:read`，由既有处理器判定）。
pub async fn ingest_sources(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    crate::routes::ingest::list_sources(State(state), principal, query).await
}

/// 解析器列表（`GET /api/v1/ingest/parsers`）。
///
/// **别名**：与既有 `GET /api/v1/parsers` 是同一个处理器
/// （[`crate::routes::ingest::list_parsers`]），控制台按 `data?.data?.items` 消费。
///
/// # Errors
/// 权限不足（`parsers:read`，由既有处理器判定）。
pub async fn ingest_parsers(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    crate::routes::ingest::list_parsers(State(state), principal, query).await
}

/// 集成适配器注册表（`GET /api/v1/integrations/adapters`，控制台裸数组）。
///
/// 数据源：`agf_adapters::AdapterRegistry::mock_only`（11 个内置适配器的注册表：**构造过程**
/// 零配置、不发任何请求）+ `health_map()` 的健康记录。注意注册表元数据 ≠ 调用行为：
/// `agf-adapters` 的 12 个内置适配器均有真实传输；email 使用 SMTP。
/// 逐条映射成前端 `Adapter`：
///
/// - `id`：注册名（`feishu`/`jira`/`syslog`…）；`name`：显示名；
/// - `category`：见 [`frontend_adapter_category`]（后端 `AdapterCategory` 的 `message`/`itsm`
///   不在前端词表里，按厂商语义映射到 `notify`/`soar`/`siem`/`edr`）；
/// - `health`：`HealthStatus` → 前端 `AdapterHealth`（`available`→`healthy`、`degraded`→`degraded`、
///   `unavailable`→`unhealthy`）；Mock 态恒为 `degraded`（降级不是失败）；
/// - `mock`/`configured`/`latencyMs`：来自健康记录；`version`：适配器实现版本；
/// - `lastSyncAt`：恒 `null`——注册表不保存同步时间（不编造）；
/// - `config`：恒 `{}`——注册表未持有平台侧配置值（无凭据即未配置），前端据此渲染"未配置"提示；
/// - `degradedBehavior`：适配器元信息里的降级行为说明（`docs/adapter-spec.md` 强制字段）。
///
/// # Errors
/// 权限不足（`integrations:read`）或内置注册表装配失败。
pub async fn list_adapters(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "integrations", "read")?;
    let (metadata, health) = adapter_registry_snapshot(&state, &principal).await?;
    let views: Vec<serde_json::Value> =
        metadata.iter().map(|meta| adapter_json(meta, health.get(&meta.name))).collect();
    Ok(Json(serde_json::Value::Array(views)))
}

/// 单个集成适配器（`GET /api/v1/integrations/adapters/{id}`，`id` = 注册名）。
///
/// 与 [`list_adapters`] 同一数据源与同一投影，只是取单条；未登记的注册名 → 404。
///
/// # Errors
/// 权限不足（`integrations:read`）、适配器未登记或注册表装配失败。
pub async fn get_adapter(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "integrations", "read")?;
    let wanted = id.trim().to_ascii_lowercase();
    let (metadata, health) = adapter_registry_snapshot(&state, &principal).await?;
    let Some(meta) = metadata.iter().find(|m| m.name.eq_ignore_ascii_case(&wanted)) else {
        return Err(ApiError::new(DomainError::NotFound { entity: "adapter", id }));
    };
    Ok(Json(adapter_json(meta, health.get(&meta.name))))
}

/// 云环境自检项（`GET|POST /api/v1/alicloud/self-check`，控制台裸数组）。
///
/// 与 `GET /api/v1/alicloud/selfcheck` 共用当前租户已保存的检查回执，投影为前端
/// `SelfCheckItem[]`（连通性/最小权限/配额三类）。GET/POST 都只读取记录；新的只读检查
/// 必须从相应连接的 `/probe` 发起。
///
/// 未检查项目的 `checkedAt` 为 null；只读探针不提供配额实测时间。
///
/// # Errors
/// 权限不足（`alicloud:read`）。
pub async fn alicloud_self_check(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alicloud", "read")?;
    Ok(Json(serde_json::Value::Array(crate::cloud_status::checks(&state, principal.tenant).await?)))
}

/// 阿里云 AgentTeams 团队（`GET /api/v1/alicloud/agentteams`，控制台裸数组）。
///
/// 数据源：`agf_alicloud` 的 AgentTeams Mock fixtures（`agf_alicloud::mock::agentteams_teams`，
/// 无云凭据环境的默认路径，**零网络**）。字段投影见 [`agent_team_json`]：
/// `workspaceId` 取云侧 team id；`members[].role` 由云侧角色名映射到前端词表；
/// `dag` 由编排节点投影（节点角色取该节点首个成员的角色）；`crossTeamCalls24h` 由
/// fixtures 的跨 Team 调用链按团队统计；`riskScore` 取该团队的**未纳管 Agent 占比**
/// （与 `agf_alicloud::agentteams::managed_summary` 同口径，不编造评分）。
/// `members[].invocations24h` 恒 0：云侧 fixtures 不含调用计数（不编造）。
///
/// # Errors
/// 权限不足（`alicloud:read`）。
pub async fn list_agent_teams(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alicloud", "read")?;
    if let Some(context) = crate::agentteams_audit::binding::context(&state, principal.tenant).await? {
        return Ok(Json(serde_json::Value::Array(
            crate::agentteams_audit::views::teams(&state, principal.tenant, &context).await?,
        )));
    }
    if crate::cloud_store::load(&state, principal.tenant, crate::cloud_inventory::NAME).await?.is_some()
        || !crate::cloud_inventory_views::mocked(&state, principal.tenant).await?
    {
        return Ok(Json(serde_json::json!([])));
    }
    let teams = agf_alicloud::mock::agentteams_teams();
    let calls = agf_alicloud::mock::agentteams_cross_calls();
    let views: Vec<serde_json::Value> = teams
        .iter()
        .map(|team| {
            let mut value = agent_team_json(team, &calls);
            value["mocked"] = serde_json::json!(true);
            value
        })
        .collect();
    Ok(Json(serde_json::Value::Array(views)))
}

/// 跨 Team 调用链（`GET /api/v1/alicloud/cross-team-calls`，控制台裸数组）。
///
/// 数据源：`agf_alicloud::mock::agentteams_cross_calls()`。按
/// `(调用方 team, 被调用 team, 被调用 agent)` 聚合：`count24h` 为窗口内记录条数；
/// `authorized` 取 `!blocked`；`sensitiveData` 取 `cross_account`（跨账号调用即跨数据边界，
/// 控制台据此高亮）。同一记录只有一条时 `count24h = 1`。
///
/// # Errors
/// 权限不足（`alicloud:read`）。
pub async fn list_cross_team_calls(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alicloud", "read")?;
    if let Some(context) = crate::agentteams_audit::binding::context(&state, principal.tenant).await? {
        return Ok(Json(serde_json::Value::Array(
            crate::agentteams_audit::views::cross_calls(&state, principal.tenant, &context).await?,
        )));
    }
    if crate::cloud_store::load(&state, principal.tenant, crate::cloud_inventory::NAME).await?.is_some()
        || !crate::cloud_inventory_views::mocked(&state, principal.tenant).await?
    {
        return Ok(Json(serde_json::json!([])));
    }
    let calls = agf_alicloud::mock::agentteams_cross_calls();
    // 键 = （调用方 team, 被调用 team, 被调用 agent）；值 = （条数, 是否全部授权, 是否跨账号）
    let mut grouped: std::collections::BTreeMap<(String, String, String), (u64, bool, bool)> =
        std::collections::BTreeMap::new();
    for call in &calls {
        let key = (call.from_team_id.clone(), call.to_team_id.clone(), call.to_agent_id.clone());
        let entry = grouped.entry(key).or_insert((0, true, false));
        entry.0 += 1;
        entry.1 &= !call.blocked;
        entry.2 |= call.cross_account;
    }
    let views: Vec<serde_json::Value> = grouped
        .into_iter()
        .map(|((caller, callee, callee_agent), (count, authorized, sensitive))| {
            serde_json::json!({
                "id": format!("{caller}->{callee}:{callee_agent}"),
                "mocked": true,
                "callerTeam": caller,
                "calleeTeam": callee,
                "calleeAgent": callee_agent,
                "count24h": count,
                "authorized": authorized,
                "sensitiveData": sensitive,
            })
        })
        .collect();
    Ok(Json(serde_json::Value::Array(views)))
}

/// 阿里云服务绑定视图（`GET /api/v1/alicloud/service-bindings`，控制台裸数组）。
///
/// 数据源：与既有 `GET /api/v1/alicloud/services` **同一实现**
/// （`AliCloudRegistry::records`），只做字段投影成前端 `ServiceBinding`：
///
/// - 只覆盖前端 `AliCloudService` 词表里的五个服务（`agentteams` 不在该词表里，跳过）；
///   `service` 由 [`binding_service`] 从适配器注册名（`alicloud-cms`…）映射成前端取值（`cms`…）；
/// - `bound` = `ServiceRecord.configured`（是否已配置凭据/绑定云资源；无凭据环境恒 `false`）；
/// - `resourceId` = `integration_id` → 退化 `config_id`（都没有则 `null`，不编造资源 id）；
/// - `region`：Mock 态取 `agf_alicloud` 的 fixture 地域（`cn-hangzhou`）；非 Mock 态
///   `ServiceRecord` 不暴露地域（地域在适配器 settings 里），留空串如实表示"未在该视图中暴露"；
/// - `health`：见 [`binding_health`]；`note`：记录自身的说明。
///
/// # Errors
/// 权限不足（`alicloud:read`）。
pub async fn list_service_bindings(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alicloud", "read")?;
    let mut views = Vec::new();
    for row in crate::cloud_status::services(&state, principal.tenant).await? {
        let name = row["name"].as_str().unwrap_or_default();
        let selected = crate::cloud_store::service(name)?;
        let Some(service) = binding_service(selected) else { continue };
        views.push(serde_json::json!({"service":service,"displayName":row["display_name"],
            "bound":row["enabled"],"resourceId":row["resource_id"],"region":row["region"],
            "health":if row["health"]=="unconfigured" {"unknown"}else{row["health"].as_str().unwrap_or("unknown")},"note":row["note"]}));
    }
    Ok(Json(serde_json::Value::Array(views)))
}
