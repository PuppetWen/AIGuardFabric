//! 控制台只读端点（routes::console）：总览 / 搜索 / 拓扑 / 身份 / 设置 / 运行时。
//! 末尾附带控制台端点的未认证 401、权限与路径覆盖校验。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

// ===========================================================================
// 18. 控制台只读端点（routes::console）：总览 / 搜索 / 拓扑 / 身份 / 设置 / 运行时
// ===========================================================================
//
// 每条端点至少一个断言：**未认证 401**（末尾统一覆盖）+ 认证后 **200 关键字段/形状**。
// 这里独立挂载 `console::router()`，因此**父代理接线前后都成立**（接线不会导致重复注册）。

#[tokio::test]
async fn console_overview_returns_dashboard_shape() {
    let h = setup_console().await;
    let resp = h.get("/api/v1/overview").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();

    let kpis = body["kpis"].as_array().expect("kpis 必须是数组");
    assert_eq!(kpis.len(), 5, "KPI 卡片数固定为 5: {body}");
    let keys: Vec<&str> = kpis.iter().filter_map(|kpi| kpi["key"].as_str()).collect();
    for key in ["assets", "openAlerts", "criticalFindings", "redteamSuccessRate", "tokenSpend"] {
        assert!(keys.contains(&key), "缺少 KPI {key}: {body}");
    }
    assert_eq!(body["domain_distribution"].as_array().map(Vec::len), Some(5), "{body}");
    for field in ["risk_trend", "top_risk_assets", "recent_alerts", "adapter_health"] {
        assert!(body[field].is_array(), "{field} 必须是数组: {body}");
    }
    // 适配器健康条来自真实的阿里云适配器注册表（Mock 模式）
    assert!(body["adapter_health"].as_array().is_some_and(|items| !items.is_empty()), "{body}");
}

#[tokio::test]
async fn console_overview_counts_real_ledger_data() {
    let h = setup_console().await;
    let full = full_app(&h);
    let ingested = ingest_mcp(&full, "console-overview-01", "http://10.0.0.11:9000").await;
    assert_eq!(ingested.status, StatusCode::OK, "{}", ingested.text);

    let body = h.get("/api/v1/overview").await.json();
    let assets_kpi = body["kpis"]
        .as_array()
        .and_then(|kpis| kpis.iter().find(|kpi| kpi["key"] == "assets"))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(assets_kpi["value"].as_f64(), Some(1.0), "资产 KPI 必须来自真实台账: {body}");
    let names: Vec<&str> = body["top_risk_assets"]
        .as_array()
        .map(|items| items.iter().filter_map(|asset| asset["name"].as_str()).collect())
        .unwrap_or_default();
    assert!(names.contains(&"mcp-console-overview-01"), "TOP 风险资产必须含真实资产: {body}");
}

#[tokio::test]
async fn console_search_returns_bare_array_and_matches_ledger() {
    let h = setup_console().await;
    let full = full_app(&h);
    let _ = ingest_mcp(&full, "console-search-01", "http://10.0.0.12:9000").await;

    let empty = h.get("/api/v1/search?q=").await;
    assert_eq!(empty.status, StatusCode::OK, "{}", empty.text);
    assert_eq!(empty.json().as_array().map(Vec::len), Some(0), "空关键词返回空数组而不是 404/400");

    let resp = h.get("/api/v1/search?q=console-search-01").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let hits = body.as_array().expect("控制台声明 callApi<SearchHit[]>，必须是裸数组");
    assert!(!hits.is_empty(), "按指纹搜索必须命中刚导入的 MCP 资产: {body}");
    assert!(
        hits.iter()
            .any(|item| item["kind"] == "mcp" && item["to"] == format!("/assets/{}", item["id"].as_str().unwrap())),
        "MCP 资产必须映射为 kind=mcp 且跳转 /mcps: {body}"
    );
}

#[tokio::test]
async fn console_topology_uses_asset_dependencies() {
    let h = setup_console().await;
    let full = full_app(&h);
    let mut agent =
        agf_core::asset::Asset::new(h.tenant, agf_core::enums::AssetKind::Agent, "console-agent", "fp-console-agent");
    let mcp =
        agf_core::asset::Asset::new(h.tenant, agf_core::enums::AssetKind::McpServer, "console-mcp", "fp-console-mcp");
    // 台账依赖（Agent → MCP）是拓扑边的真实来源
    agent.dependencies = vec![mcp.id];
    full.state.store.asset_upsert(&agent).expect("写入 agent 资产失败");
    full.state.store.asset_upsert(&mcp).expect("写入 mcp 资产失败");

    let body = h.get("/api/v1/topology").await.json();
    let nodes = body["nodes"].as_array().expect("nodes 必须是数组");
    let edges = body["edges"].as_array().expect("edges 必须是数组");
    assert!(nodes.iter().any(|n| n["id"] == agent.id.to_string() && n["type"] == "agent"), "{body}");
    assert!(
        edges.iter().any(|e| {
            e["source"] == agent.id.to_string() && e["target"] == mcp.id.to_string() && e["kind"] == "invokes"
        }),
        "台账 dependencies 必须投影成拓扑边: {body}"
    );
    assert!(body["egress_paths"].is_array(), "egress_paths 必须是数组: {body}");
}

#[tokio::test]
async fn console_users_lists_bootstrap_admin() {
    let h = setup_console().await;
    let resp = h.get("/api/v1/users").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let users = body.as_array().expect("控制台声明 callApi<User[]>，必须是裸数组");
    let admin = users.iter().find(|user| user["username"] == "admin").expect("必须至少返回 admin");
    assert_eq!(admin["role"], "owner", "superadmin 必须映射为 owner: {body}");
    assert_eq!(admin["tenant_id"], h.tenant.to_string());
    assert!(admin["last_login_at"].as_str().is_some_and(|v| v.ends_with('Z')));
}

#[tokio::test]
async fn console_tenants_returns_default_tenant_with_real_quota_defaults() {
    let h = setup_console().await;
    let resp = h.get("/api/v1/tenants").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let tenants = body.as_array().expect("控制台声明 callApi<Tenant[]>，必须是裸数组");
    assert_eq!(tenants.len(), 2, "平台超管可见测试目录中的两个租户: {body}");
    let tenant = &tenants[0];
    assert_eq!(tenant["id"], "00000000-0000-0000-0000-000000000001");
    assert!(tenant["white_label"]["product_name"].as_str().is_some_and(|v| !v.is_empty()), "{body}");
    // 配额默认值来自真实配额表（AppState::build 写入的租户级默认配额）
    assert_eq!(tenant["quota_defaults"]["tenant_tokens_per_day"], 5_000_000, "{body}");
    assert_eq!(tenant["quota_defaults"]["max_concurrent_sessions"], 64, "{body}");
}

#[tokio::test]
async fn console_api_keys_are_projected_without_fingerprint() {
    let h = setup_console().await;
    let resp = h.get("/api/v1/api-keys").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let keys = body.as_array().expect("控制台声明 callApi<ApiKey[]>，必须是裸数组");
    let key = keys.iter().find(|k| k["name"] == "integration-test").expect("必须返回已签发的 Key");
    assert!(key["prefix"].as_str().is_some_and(|p| p.starts_with("agf_live_")), "{body}");
    assert!(key["scopes"].as_array().is_some_and(|s| s.iter().any(|v| v == "assets:*")), "{body}");
    assert!(key.get("key_fingerprint").is_none(), "指纹绝不能外泄: {body}");
    assert!(key.get("allowed_cidrs").is_none(), "未在 domain.ts 声明的字段不外泄: {body}");
}

#[tokio::test]
async fn console_password_policy_reflects_effective_policy() {
    let h = setup_console().await;
    let resp = h.get("/api/v1/settings/password-policy").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert_eq!(body["min_length"], 12, "必须反映 AGF_PASSWORD_MIN_LENGTH=12: {body}");
    assert_eq!(body["lockout_threshold"], 3, "必须反映 AGF_LOGIN_MAX_FAILURES=3: {body}");
    assert_eq!(body["require_uppercase"], false, "逐类要求与三类组合要求分别表达: {body}");
    assert_eq!(body["require_classes"], true, "{body}");
    assert_eq!(body["mfa_enforced"], false, "平台无租户级强制 MFA 开关: {body}");
}

#[tokio::test]
async fn console_blacklists_expose_builtin_command_and_domain_rules() {
    let h = setup_console().await;
    let resp = h.get("/api/v1/runtime/blacklists").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let rules = body.as_array().expect("控制台声明 callApi<BlacklistEntry[]>，必须是裸数组");
    assert!(rules.len() >= 20, "内置黑名单的命令行 + 域名规则应 ≥ 20 条，实际 {}: {body}", rules.len());
    assert!(
        rules.iter().all(|rule| rule["kind"] == "command" || rule["kind"] == "domain"),
        "只输出 domain.ts 支持的 kind（path/tool/hash 类无对应取值，应跳过）: {body}"
    );
    assert!(rules.iter().any(|rule| rule["id"] == "cmd.rm-rf-root" && rule["action"] == "deny"), "{body}");
    assert!(rules.iter().any(|rule| rule["id"] == "domain.pastebin"), "{body}");
    assert!(rules.iter().all(|rule| rule["scope"] == "tenant" && rule["hits_24h"] == 0), "{body}");
}

#[tokio::test]
async fn console_runtime_events_reads_the_interception_chain() {
    let h = setup_console().await;
    let full = full_app(&h);
    let mut record = agf_runtime::audit::InterceptionRecord::new(
        h.tenant,
        "s-console",
        agf_core::enums::InterceptPoint::McpProxy,
        agf_runtime::audit::InterceptionVerdict::Blocked,
        "命中黑名单规则 cmd.rm-rf-root",
    )
    .with_tool("run_command");
    // 链上条目的实际动作（`new` 的缺省是 allow，这里显式置为 deny 以断言映射）
    record.action = agf_core::enums::PolicyAction::Deny;
    full.state.runtime.record_interception(record).expect("写入拦截链失败");

    let resp = h.get("/api/v1/runtime/events").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let events = body.as_array().expect("控制台声明 callApi<InterceptEvent[]>，必须是裸数组");
    assert_eq!(events.len(), 1, "拦截链里的记录必须被投影: {body}");
    assert_eq!(events[0]["point"], "mcp-proxy", "{body}");
    assert_eq!(events[0]["action"], "deny", "{body}");
    assert_eq!(events[0]["tool_name"], "run_command", "{body}");
    assert!(events[0]["payload_digest"].as_str().is_some_and(|v| v.len() == 64), "载荷摘要取链条目哈希: {body}");
}

#[tokio::test]
async fn console_intercept_points_cover_frontend_enum_and_real_block_counts() {
    let h = setup_console().await;
    let full = full_app(&h);
    for point in [agf_core::enums::InterceptPoint::McpProxy, agf_core::enums::InterceptPoint::AiGateway] {
        let record = agf_runtime::audit::InterceptionRecord::new(
            h.tenant,
            "s-points",
            point,
            agf_runtime::audit::InterceptionVerdict::Blocked,
            "命中策略",
        );
        full.state.runtime.record_interception(record).expect("写入拦截链失败");
    }
    let resp = h.get("/api/v1/runtime/intercept-points").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let points = body.as_array().expect("控制台声明 callApi<InterceptPointStatus[]>，必须是裸数组");
    let names: Vec<&str> = points.iter().filter_map(|p| p["point"].as_str()).collect();
    assert_eq!(names, vec!["mcp-proxy", "ai-gateway", "process-hook", "egress-proxy"], "{body}");
    let blocked: Vec<i64> = points.iter().map(|p| p["blocked_24h"].as_i64().unwrap_or(-1)).collect();
    assert_eq!(blocked, vec![1, 1, 0, 0], "阻断计数必须来自拦截链: {body}");
    assert!(points[..2].iter().all(|p| p["enabled"] == true && p["health"] == "healthy"), "{body}");
    assert!(points[2..].iter().all(|p| p["enabled"] == false && p["health"] == "unknown"), "{body}");
    assert!(points[2..].iter().all(|p| p["last_error"].as_str().is_some_and(|v| !v.is_empty())), "{body}");
}

#[tokio::test]
async fn console_runtime_quotas_match_quota_snapshot() {
    let h = setup_console().await;
    let resp = h.get("/api/v1/runtime/quotas").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let usages = body.as_array().expect("控制台声明 callApi<QuotaUsage[]>，必须是裸数组");
    assert!(!usages.is_empty(), "默认租户至少有配额行: {body}");
    let tokens = usages
        .iter()
        .find(|usage| usage["scope"] == "tenant" && usage["unit"] == "tokens")
        .expect("必须有租户级 Token 配额");
    assert_eq!(tokens["limit"], 5_000_000, "{body}");
    assert_eq!(tokens["throttled"], false, "{body}");
    assert!(tokens["window_start"].as_str().is_some_and(|v| v.ends_with('Z')), "{body}");
    // 与既有 /quotas/snapshot 同源：维度数必须与行数一致
    let full = full_app(&h);
    let snapshot = full.get("/api/v1/quotas/snapshot").await.json();
    let dimensions = snapshot["dimensions"].as_object().expect("dimensions 缺失");
    assert_eq!(dimensions.len(), usages.len(), "两个端点的配额行数必须一致: {body}");
}

#[tokio::test]
async fn console_onboarding_plan_supports_get_and_post() {
    let h = setup_console().await;
    // 缺参数：给一份默认计划（sidecar）并说明未指定资产
    let default_plan = h.get("/api/v1/agents/onboarding-plan").await;
    assert_eq!(default_plan.status, StatusCode::OK, "{}", default_plan.text);
    let plan = default_plan.json();
    assert_eq!(plan["mode"], "sidecar", "{plan}");
    assert_eq!(plan["agent_id"], "", "{plan}");
    assert!(plan["steps"].as_array().is_some_and(|steps| !steps.is_empty()), "{plan}");
    assert!(plan["env_snippet"].as_str().is_some_and(|v| v.contains("AGF_AGENT_TENANT_ID=")), "{plan}");

    assert!(plan["artifact_url"].is_null());
    assert!(plan["steps"][1]["command"].as_str().unwrap().contains("run --once"));
    assert!(!default_plan.text.contains("agf-sidecar"));
    // 控制台用法：POST {agentId, mode}
    let full = full_app(&h);
    let agent = agf_core::asset::Asset::new(
        h.tenant,
        agf_core::enums::AssetKind::Agent,
        "console-plan-agent",
        "fp-console-plan-agent",
    );
    full.state.store.asset_upsert(&agent).expect("写入 agent 失败");
    let posted =
        h.post("/api/v1/agents/onboarding-plan", json!({"agentId": agent.id.to_string(), "mode": "sdk-inject"})).await;
    assert_eq!(posted.status, StatusCode::OK, "{}", posted.text);
    let plan = posted.json();
    assert_eq!(plan["agent_id"], agent.id.to_string(), "{plan}");
    assert_eq!(plan["mode"], "sdk-inject", "{plan}");
    assert!(plan["estimated_downtime_sec"].is_null(), "{plan}");
    assert!(plan["endpoint"].as_str().is_some_and(|v| v.starts_with("http")), "{plan}");

    // 参数校验：未知模式 / 非 agent 资产 / 不存在的资产
    let bad_mode = h.get("/api/v1/agents/onboarding-plan?mode=nope").await;
    assert_eq!(bad_mode.status, StatusCode::BAD_REQUEST, "{}", bad_mode.text);
    let mcp = agf_core::asset::Asset::new(
        h.tenant,
        agf_core::enums::AssetKind::McpServer,
        "console-plan-mcp",
        "fp-console-plan-mcp",
    );
    full.state.store.asset_upsert(&mcp).expect("写入 mcp 失败");
    let wrong_kind = h.get(&format!("/api/v1/agents/onboarding-plan?agent_id={}", mcp.id)).await;
    assert_eq!(wrong_kind.status, StatusCode::BAD_REQUEST, "{}", wrong_kind.text);
    let missing = h.get(&format!("/api/v1/agents/onboarding-plan?agent_id={}", agf_core::ids::Id::new())).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND, "{}", missing.text);
}

#[tokio::test]
async fn console_endpoints_require_authentication() {
    let h = setup_console().await;
    for uri in [
        "/api/v1/overview",
        "/api/v1/search?q=admin",
        "/api/v1/topology",
        "/api/v1/users",
        "/api/v1/tenants",
        "/api/v1/api-keys",
        "/api/v1/settings/password-policy",
        "/api/v1/runtime/blacklists",
        "/api/v1/runtime/events",
        "/api/v1/runtime/intercept-points",
        "/api/v1/runtime/quotas",
        "/api/v1/agents/onboarding-plan",
        "/api/v1/ingest/replay?sourceId=x",
    ] {
        let resp = h.request("GET", uri, None, None).await;
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{uri} 未认证必须 401: {}", resp.text);
    }
    let posted = h.request("POST", "/api/v1/ingest/replay", None, Some(json!({"sourceId": "x"}))).await;
    assert_eq!(posted.status, StatusCode::UNAUTHORIZED, "{}", posted.text);
}

#[tokio::test]
async fn console_endpoints_enforce_permissions() {
    let h = setup_console().await;
    // viewer 无 policies:read → 运行时黑名单 403；有 assets:read → 总览 200
    let denied = h.request("GET", "/api/v1/runtime/blacklists", Some(&h.viewer), None).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{}", denied.text);
    let allowed = h.request("GET", "/api/v1/overview", Some(&h.viewer), None).await;
    assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.text);
    // API Key 只有 assets:* → /api-keys（settings:read）必须 403
    let key = h.request_with("GET", "/api/v1/api-keys", &[("x-agf-key", h.api_key.as_str())], None).await;
    assert_eq!(key.status, StatusCode::FORBIDDEN, "{}", key.text);
}

#[tokio::test]
async fn console_endpoint_specs_cover_all_console_paths() {
    let specs = agf_api::routes::console::endpoint_specs();
    assert_eq!(specs.len(), 16, "控制台端点清单应包含用户写入及预览/回放的独立方法");
    let users: Vec<_> = specs.iter().filter(|spec| spec.path == "/api/v1/users").collect();
    assert!(users.iter().any(|spec| spec.method == utoipa::openapi::path::HttpMethod::Get));
    assert!(users.iter().any(|spec| spec.method == utoipa::openapi::path::HttpMethod::Post));
    assert!(
        specs.iter().any(|spec| {
            spec.path == "/api/v1/users/{id}" && spec.method == utoipa::openapi::path::HttpMethod::Patch
        })
    );
    let replay_specs: Vec<_> = specs.iter().filter(|spec| spec.path == "/api/v1/ingest/replay").collect();
    assert_eq!(replay_specs.len(), 2);
    assert!(replay_specs.iter().any(|spec| spec.method == utoipa::openapi::path::HttpMethod::Get));
    assert!(replay_specs.iter().any(|spec| spec.method == utoipa::openapi::path::HttpMethod::Post));
    for spec in &specs {
        assert!(spec.path.starts_with("/api/v1/"), "清单路径必须是完整路径: {}", spec.path);
        assert!(!spec.path.ends_with('/'), "路径不应以斜杠结尾: {}", spec.path);
    }
    for path in [
        "/overview",
        "/search",
        "/topology",
        "/users",
        "/tenants",
        "/api-keys",
        "/settings/password-policy",
        "/runtime/blacklists",
        "/runtime/events",
        "/runtime/intercept-points",
        "/runtime/quotas",
        "/agents/onboarding-plan",
        "/ingest/replay",
    ] {
        // 清单里的 path 是**完整路径**（与 platform 的既有条目一致），这里补前缀后比对。
        let absolute = format!("/api/v1{path}");
        assert!(specs.iter().any(|spec| spec.path == absolute), "端点清单缺少 {absolute}");
    }
}
