//! AI 资产资源组（§4.11）：agents / mcps / skills / model-endpoints 的视图、隔离与权限。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

// ===========================================================================
// 16. AI 资产资源组：agents / mcps / skills / models（§4.11）
// ===========================================================================

#[tokio::test]
async fn agents_resource_group_is_paged_and_requires_auth() {
    let h = setup().await;
    let body = assert_group_list_empty(&h, "/api/v1/agents").await;
    assert_eq!(body["page"], 1);
    assert_eq!(body["page_size"], agf_core::pagination::DEFAULT_PAGE_SIZE);
}

#[tokio::test]
async fn mcps_resource_group_serves_both_paths() {
    let h = setup().await;
    let canonical = assert_group_list_empty(&h, "/api/v1/mcps").await;
    let alias = assert_group_list_empty(&h, "/api/v1/mcp-servers").await;
    assert_eq!(canonical["total"], alias["total"], "/mcps 与 /mcp-servers 必须是同一份数据");
}

#[tokio::test]
async fn skills_resource_group_is_paged_and_requires_auth() {
    let h = setup().await;
    let body = assert_group_list_empty(&h, "/api/v1/skills").await;
    assert!(body["next_cursor"].is_null(), "无数据时不应有游标: {body}");
}

#[tokio::test]
async fn model_endpoints_resource_group_is_paged_and_requires_auth() {
    let h = setup().await;
    let body = assert_group_list_empty(&h, "/api/v1/models/endpoints").await;
    assert_eq!(body["total"], 0);
}

#[tokio::test]
async fn ai_asset_views_project_ledger_by_kind() {
    let h = setup().await;
    let seeded = seed_ai_assets(&h).await;
    assert_eq!(seeded.status, StatusCode::OK, "{}", seeded.text);
    assert_eq!(seeded.json()["stats"]["created"], 4);

    // Agent：字段名对齐前端 Agent（camelCase），值来自台账
    let agents = h.get("/api/v1/agents").await.json();
    assert_eq!(agents["total"], 1, "{agents}");
    let agent = &agents["items"][0];
    assert_eq!(agent["name"], "客服智能助手");
    assert_eq!(agent["flavor"], "langgraph", "vendor 命中前端枚举时应直接使用");
    assert_eq!(agent["version"], "1.2.3");
    assert_eq!(agent["host"], "10.20.30.40");
    assert_eq!(agent["ip"], "10.20.30.40", "endpoint 是 IP 字面量时应回填 ip");
    assert_eq!(agent["owner"], "alice");
    assert_eq!(agent["department"], "客户运营部");
    assert!(agent["riskScore"].is_null(), "exposure points cannot replace a risk assessment");
    assert_eq!(agent["management"], "unmanaged", "台账无纳管模式字段，如实取 unmanaged");
    assert_eq!(agent["online"], true, "刚上报的资产应判为在线");
    assert!(agent["toolCount"].is_null(), "未采集不等于零");
    assert!(agent["lastHeartbeatAt"].as_str().is_some_and(|t| t.ends_with('Z')), "{agent}");

    // MCP：/mcps 与前端别名 /mcp-servers 均可用，且同一条数据
    for uri in ["/api/v1/mcps", "/api/v1/mcp-servers"] {
        let mcps = h.get(uri).await.json();
        assert_eq!(mcps["total"], 1, "{uri}: {mcps}");
        let mcp = &mcps["items"][0];
        assert_eq!(mcp["name"], "运维数据查询 MCP");
        assert_eq!(mcp["transport"], "stdio");
        assert_eq!(mcp["shadow"], true, "试用态且非手工登记应视为影子 MCP");
        assert_eq!(mcp["plaintextCredential"], true);
        assert!(mcp["riskScore"].is_null());
    }

    // Skill：审批状态由生命周期映射（发现即 trial → approved），审批人/时间如实留空
    let skills = h.get("/api/v1/skills").await.json();
    assert_eq!(skills["total"], 1, "{skills}");
    let skill = &skills["items"][0];
    assert_eq!(skill["name"], "日志检索 Skill");
    assert_eq!(skill["status"], "pending");
    assert_eq!(skill["publisher"], "自研");
    assert!(skill["decidedAt"].is_null(), "台账无审批流，不得编造审批时间");
    assert!(skill["decidedBy"].is_null());
    assert_eq!(skill["whitelist"]["domains"].as_array().map(Vec::len), Some(0));
    assert!(skill["capabilities"].is_array());

    // 模型端点：字段名对齐前端 ModelEndpoint
    let endpoints = h.get("/api/v1/models/endpoints").await.json();
    assert_eq!(endpoints["total"], 1, "{endpoints}");
    let endpoint = &endpoints["items"][0];
    assert_eq!(endpoint["vendor"], "qwen");
    assert_eq!(endpoint["model"], "qwen-max-2025-01-25");
    assert_eq!(endpoint["endpoint"], "https://dashscope.aliyuncs.com/compatible-mode/v1");
    assert_eq!(endpoint["health"], "unknown", "台账无健康信号时必须为 unknown");
    assert!(endpoint["mockMode"].is_null());
    assert!(endpoint["latencyP95Ms"].is_null());
}

#[tokio::test]
async fn ai_asset_kind_forces_group_isolation_and_details() {
    let h = setup().await;
    let seeded = seed_ai_assets(&h).await;
    assert_eq!(seeded.status, StatusCode::OK, "{}", seeded.text);

    let agents = h.get("/api/v1/agents").await.json();
    let agent_id = agents["items"][0]["id"].as_str().unwrap().to_string();
    let mcps = h.get("/api/v1/mcps").await.json();
    let mcp_id = mcps["items"][0]["id"].as_str().unwrap().to_string();

    // 详情：正确的资源组能取到，包裹键名与既有 {"asset": …} 风格一致
    let agent = h.get(&format!("/api/v1/agents/{agent_id}")).await;
    assert_eq!(agent.status, StatusCode::OK, "{}", agent.text);
    assert_eq!(agent.json()["agent"]["id"], agent_id);
    let mcp = h.get(&format!("/api/v1/mcps/{mcp_id}")).await;
    assert_eq!(mcp.status, StatusCode::OK, "{}", mcp.text);
    assert_eq!(mcp.json()["mcp_server"]["id"], mcp_id);
    let alias = h.get(&format!("/api/v1/mcp-servers/{mcp_id}")).await;
    assert_eq!(alias.status, StatusCode::OK, "{}", alias.text);

    // 跨资源组取 id 必须 404（不得用 /agents/{mcp_id} 探测其他资源组）
    let crossed = h.get(&format!("/api/v1/agents/{mcp_id}")).await;
    assert_eq!(crossed.status, StatusCode::NOT_FOUND, "{}", crossed.text);
    // 不存在的 id → 404；非法 id → 400
    let missing = h.get(&format!("/api/v1/skills/{}", agf_core::ids::Id::new())).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let malformed = h.get("/api/v1/skills/not-a-uuid").await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);

    // `kind` 过滤（含前端别名 mcp/model）：只允许在本资源组的类型集合内收窄
    let aliased = h.get("/api/v1/mcps?kind=mcp").await.json();
    assert_eq!(aliased["total"], 1, "kind=mcp 是 mcp-server 的前端别名: {aliased}");
    assert_eq!(aliased["items"][0]["transport"], "stdio");
    let narrowed = h.get("/api/v1/mcps?kind=mcp-client").await.json();
    assert_eq!(narrowed["total"], 0, "mcp-client 类型下没有资产: {narrowed}");
    let crossed_kind = h.get("/api/v1/agents?kind=model-endpoint").await;
    assert_eq!(crossed_kind.status, StatusCode::BAD_REQUEST, "跨资源组 kind 必须拒绝: {}", crossed_kind.text);
    let bad = h.get("/api/v1/agents?kind=nope").await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    // 分页与字段裁剪沿用平台既有约定
    let paged = h.get("/api/v1/agents?page_size=1&fields=id,name").await.json();
    assert_eq!(paged["items"][0].as_object().map(serde_json::Map::len), Some(2), "{paged}");
}

#[tokio::test]
async fn ai_asset_groups_enforce_permissions() {
    let h = setup().await;
    // viewer 与 api_key（仅 assets:*）都无权读这四组
    for uri in ["/api/v1/agents", "/api/v1/mcps", "/api/v1/skills", "/api/v1/models/endpoints"] {
        let viewer = h.request("GET", uri, Some(&h.viewer), None).await;
        assert_eq!(viewer.status, StatusCode::FORBIDDEN, "{uri} viewer 必须 403: {}", viewer.text);
        let key = h.request_with("GET", uri, &[("x-agf-key", h.api_key.as_str())], None).await;
        assert_eq!(key.status, StatusCode::FORBIDDEN, "{uri} 越权 API Key 必须 403: {}", key.text);
    }
}

#[tokio::test]
async fn ai_asset_resource_groups_are_in_openapi() {
    let h = setup().await;
    let doc = h.get("/api/v1/openapi.json").await.json();
    let paths = doc["paths"].as_object().expect("paths 缺失");
    for path in [
        "/api/v1/agents",
        "/api/v1/agents/{id}",
        "/api/v1/mcps",
        "/api/v1/mcps/{id}",
        "/api/v1/mcp-servers",
        "/api/v1/mcp-servers/{id}",
        "/api/v1/skills",
        "/api/v1/skills/{id}",
        "/api/v1/models/endpoints",
        "/api/v1/models/endpoints/{id}",
    ] {
        assert!(paths.contains_key(path), "OpenAPI 缺少 {path}");
        assert!(paths[path]["get"]["responses"]["200"].is_object(), "{path} 必须声明 200");
        assert!(paths[path]["get"]["responses"]["401"].is_object(), "{path} 必须声明 401");
    }
    // 响应视图进了 components（前端可据此生成类型）
    let schemas = doc["components"]["schemas"].as_object().expect("components.schemas 缺失");
    for name in ["AgentView", "McpServerView", "SkillView", "ModelEndpointView"] {
        assert!(schemas.contains_key(name), "components 缺少 {name}");
    }
}
