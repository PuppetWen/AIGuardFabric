//! 演示数据灌入后，「接口通但恒为空」的端点必须有真实数据。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

// ===========================================================================
// 演示数据：5 条"接口通但恒为空"的端点必须有真实数据
// ===========================================================================
//
// 说明：本文件的既有测试**不开** `AGF_SEED_FIXTURES`（进程级环境变量，改它会影响同进程的
// 其它测试），因此这里直接调用灌库入口把演示数据灌进测试夹具的 `AppState`
// （真实 fixtures + 真实引擎/Meter/剧本引擎），再走 HTTP 校验端点。
// 生产启动路径由 `seed.rs` 的单元测试与 `state.rs` 的装配顺序覆盖。

#[tokio::test]
async fn seeded_runtime_events_and_intercept_points_share_one_audit_chain() {
    let h = setup().await;
    seed_into(&h);

    assert_unauthorized(&h, "GET", "/api/v1/runtime/events", None).await;
    let resp = h.get("/api/v1/runtime/events").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let events = resp.json();
    let events = events.as_array().expect("client.ts 声明 InterceptEvent[]，必须是裸数组");
    assert!(events.len() >= 2, "演示灌库后必须有多条真实拦截事件: {events:?}");

    let blocked: Vec<&Value> = events
        .iter()
        .filter(|e| ["deny", "quarantine", "throttle"].contains(&e["action"].as_str().unwrap_or("")))
        .collect();
    assert!(!blocked.is_empty(), "至少 1 条事件的 action 是拦截类: {events:?}");
    assert!(
        blocked.iter().any(|e| e["reason"].as_str().is_some_and(|r| r.contains("cmd.curl-pipe-sh"))),
        "被拦原因必须来自引擎命中的内置黑名单规则: {blocked:?}"
    );
    // 链上条目哈希（payloadDigest）与时间戳必须真实存在
    assert!(events.iter().all(|e| e["payload_digest"].as_str().is_some_and(|d| !d.is_empty())), "{events:?}");
    assert!(events[0]["ts"].as_str().is_some_and(|t| t.ends_with('Z')), "{events:?}");
    assert!(
        events.iter().any(|e| e["point"] == "mcp-proxy" && e["tool_name"] == "http_request"),
        "MCP 工具调用的审计事件应显示帧中的工具名: {events:?}"
    );
    assert!(
        events.iter().any(|e| e["latency_ms"].as_f64().is_some_and(|v| v > 0.0)),
        "有实测时延的事件不应展示固定零值: {events:?}"
    );
    // 引擎自己的哈希链校验：由测试侧再验一次（拦截不得破坏链）
    assert!(h.state.runtime.audit().verify().passed, "拦截审计哈希链必须可校验");

    // 拦截点计数与事件出自同一份链 ⇒ 必须一致
    let points = h.get("/api/v1/runtime/intercept-points").await;
    assert_eq!(points.status, StatusCode::OK, "{}", points.text);
    let rows = points.json();
    let rows = rows.as_array().expect("client.ts 声明 InterceptPointStatus[]，必须是裸数组");
    let blocked_24h: i64 = rows.iter().map(|r| r["blocked_24h"].as_i64().unwrap_or(0)).sum();
    assert_eq!(
        blocked_24h as usize,
        blocked.len(),
        "blocked_24h 合计必须等于 /runtime/events 里拦截类事件的条数: {rows:?}"
    );
    assert!(blocked_24h > 0, "期望有非零 blocked_24h: {rows:?}");
}

#[tokio::test]
async fn seeded_mcp_server_exposes_tool_list() {
    let h = setup().await;
    seed_into(&h);
    let server_id = asset_id_of(&h, agf_core::enums::AssetKind::McpServer);
    let uri = format!("/api/v1/mcp-servers/{server_id}/tools");

    let resp = h.get(&uri).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let tools = resp.json();
    let tools = tools.as_array().expect("client.ts 声明 McpTool[]，必须是裸数组");
    assert!(tools.len() >= 3, "演示 MCP 资产应至少带 3 个工具: {tools:?}");
    // 注：该端点的投影用的是**驼峰键**（`mcp_tools_from_asset`，前端 camelizeDeep 对已是驼峰的键
    // 原样保留），这里按实际响应断言，不虚报成 snake_case。
    assert_eq!(tools[0]["serverId"], server_id.to_string().as_str());
    assert!(tools[0]["name"].as_str().is_some_and(|n| !n.is_empty()), "{tools:?}");
    assert!(tools[0]["description"].as_str().is_some_and(|d| !d.is_empty()), "{tools:?}");
    // 能力/风险由 ToolTraits::infer 推断（不是空数组、也不越出前端词表）
    let capabilities = tools[0]["capabilities"].as_array().expect("capabilities 必须是数组");
    assert!(!capabilities.is_empty(), "{tools:?}");
    assert!(
        ["info", "low", "medium", "high", "critical"].contains(&tools[0]["riskLevel"].as_str().unwrap_or("")),
        "{tools:?}"
    );
}

#[tokio::test]
async fn seeded_model_route_policies_are_bare_array_with_frontend_fields() {
    let h = setup().await;
    seed_into(&h);

    assert_unauthorized(&h, "GET", "/api/v1/models/route-policies", None).await;
    let resp = h.get("/api/v1/models/route-policies").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let policies = resp.json();
    let policies = policies.as_array().expect("client.ts 声明 ModelRoutePolicy[]，必须是裸数组");
    assert!(policies.len() >= 2, "演示灌库后应至少有 2 条路由策略: {policies:?}");
    let first = &policies[0];
    assert!(first["id"].is_string() && first["name"].is_string(), "{first}");
    // 主端点必须指向台账里真实存在的模型端点（不是编造的 id）
    let endpoint_id = asset_id_of(&h, agf_core::enums::AssetKind::ModelEndpoint);
    assert_eq!(first["primary_endpoint_id"], endpoint_id.to_string().as_str());
    assert!(
        ["priority", "weighted", "cost-first", "latency-first"].contains(&first["strategy"].as_str().unwrap_or("")),
        "strategy 必须在 domain.ts 的词表内: {first}"
    );
    assert!(first["fallback_endpoint_ids"].is_array() && first["weights"].is_object(), "{first}");
    assert!(first["budget_usd_per_day"].is_number() && first["enabled"].is_boolean(), "{first}");
    // 保存接口已接线：把演示策略改成禁用并落库，再用读路径确认（同一份记录面）
    let policy_id = first["id"].as_str().expect("策略 id 缺失").to_string();
    let put = h
        .request(
            "PUT",
            &format!("/api/v1/models/route-policies/{policy_id}"),
            Some(&h.admin),
            Some(json!({"expectedVersion":first["version"], "enabled": false, "budgetUsdPerDay": 3.5})),
        )
        .await;
    assert_eq!(put.status, StatusCode::OK, "PUT 必须真实落库: {}", put.text);
    let saved = put.json();
    assert_eq!(saved["enabled"], false);
    assert_eq!(saved["budget_usd_per_day"], 3.5);
    assert_eq!(saved["primary_endpoint_id"], endpoint_id.to_string().as_str(), "未提供的字段保持原值: {saved}");
    let reread = h.get("/api/v1/models/route-policies").await.json();
    let reread = reread
        .as_array()
        .and_then(|items| items.iter().find(|item| item["id"] == policy_id.as_str()))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(reread["enabled"], false, "读路径必须看到写入结果: {reread}");
    assert_eq!(reread["budget_usd_per_day"], 3.5);
}

#[tokio::test]
async fn seeded_model_usage_and_aggregate_come_from_the_meter() {
    let h = setup().await;
    seed_into(&h);

    assert_unauthorized(&h, "GET", "/api/v1/models/usage", None).await;
    let resp = h.get("/api/v1/models/usage?page=1&page_size=10").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let items = body["items"].as_array().expect("分页信封的 items 必须是数组");
    assert!(body["total"].as_u64().unwrap_or(0) >= 1, "计量灌入后 total 必须非零: {body}");
    assert_eq!(items.len(), body["total"].as_u64().unwrap_or(0) as usize);
    let first = &items[0];
    assert!(first["ts"].as_str().is_some_and(|t| t.ends_with('Z')), "{first}");
    assert_eq!(first["tenant_id"], h.tenant.to_string().as_str());
    assert!(first["endpoint_id"].is_string() && first["model"].is_string(), "{first}");
    assert!(first["input_tokens"].as_u64().unwrap_or(0) > 0, "token 必须由真实 estimator 给出: {first}");
    assert!(first["output_tokens"].as_u64().unwrap_or(0) > 0, "{first}");
    assert!(first["cost_usd"].is_number(), "{first}");
    assert!(first["agent_id"].is_string() && first["agent_name"].is_string(), "{first}");

    let aggregate = h.get("/api/v1/models/usage/aggregate").await;
    assert_eq!(aggregate.status, StatusCode::OK, "{}", aggregate.text);
    let rows = aggregate.json();
    let rows = rows.as_array().expect("client.ts 声明 ModelUsageAggregate[]，必须是裸数组");
    assert!(!rows.is_empty(), "聚合必须至少 1 行: {rows:?}");
    let calls: u64 = rows.iter().map(|r| r["calls"].as_u64().unwrap_or(0)).sum();
    assert_eq!(calls, body["total"].as_u64().unwrap_or(0), "聚合 calls 合计必须等于明细 total: {rows:?}");
    assert_eq!(rows[0]["endpoint_id"], first["endpoint_id"], "聚合与明细必须同源");
    assert!(rows[0]["vendor"].is_string() && rows[0]["cost_usd"].is_number(), "{rows:?}");
}

#[tokio::test]
async fn seeded_case_soar_runs_are_real_playbook_executions() {
    let h = setup().await;
    let report = seed_into(&h);
    let case = h.state.store.case_list(h.tenant).expect("读取案件失败").into_iter().next().expect("案件应存在");
    let uri = format!("/api/v1/cases/{}/soar-runs", case.id);

    assert_unauthorized(&h, "GET", &uri, None).await;
    let resp = h.get(&uri).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let runs = resp.json();
    let runs = runs.as_array().expect("client.ts 声明 SoarRun[]，必须是裸数组");
    assert!(!runs.is_empty(), "灌库阶段已真实执行过剧本，必须有轨迹: {runs:?}");
    assert!(report.total_errors() == 0, "灌库不应有失败条数: {report:?}");
    let run = &runs[0];
    assert_eq!(run["case_id"], case.id.to_string().as_str());
    assert!(run["playbook"].as_str().is_some_and(|p| !p.is_empty()), "{run}");
    assert_eq!(run["status"], "succeeded", "Mock 执行器 + 批准的审批门 ⇒ 成功: {run}");
    assert!(run["started_at"].as_str().is_some_and(|t| t.ends_with('Z')), "{run}");
    assert!(run["finished_at"].as_str().is_some_and(|t| t.ends_with('Z')), "{run}");
    let steps = run["steps"].as_array().expect("steps 必须是数组");
    assert!(steps.len() >= 5, "5 步剧本应有 5 条轨迹: {steps:?}");
    assert!(
        steps
            .iter()
            .all(|s| ["pending", "running", "done", "failed", "skipped"].contains(&s["status"].as_str().unwrap_or(""))),
        "步骤状态必须在 domain.ts 词表内: {steps:?}"
    );
    assert!(steps.iter().any(|s| s["status"] == "done"), "{steps:?}");
    assert!(steps.iter().all(|s| s["duration_ms"].is_number() && s["output"].is_string()), "{steps:?}");
}

#[tokio::test]
async fn api_keys_are_never_seeded_by_demo_data() {
    let h = setup().await;
    // 夹具自身为测试签发过 1 个 Key（见 `Harness::setup`）；演示灌库**不得**再预置任何凭据。
    let before = h.state.store.api_key_list(h.tenant).expect("读取失败").len();
    let report = seed_into(&h);
    let after = h.state.store.api_key_list(h.tenant).expect("读取失败");
    assert_eq!(after.len(), before, "演示灌库不得新增 API Key（凭据不预置）: {after:?}");
    assert!(
        !report.datasets.keys().any(|key| key.contains("api_key")),
        "灌库报告里不应存在 api_keys 数据集: {:?}",
        report.datasets.keys().collect::<Vec<_>>()
    );
    // 端点本身照常可用（200 + 裸数组），只是没有"演示凭据"
    let resp = h.get("/api/v1/api-keys").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    assert!(resp.json().is_array(), "{}", resp.text);
}
