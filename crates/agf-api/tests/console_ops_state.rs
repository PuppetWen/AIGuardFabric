//! 控制台补齐端点（routes::console_ops）：模型网关与 SOC 动作端点的形状与状态流转。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

// ===========================================================================
// 17. 控制台补齐端点（routes::console_ops）：模型网关 / SOC 动作 / 生态与别名
// ===========================================================================
//
// 每条端点一个集成测试：**未认证 401** + 认证后 **200/501** + **形状断言**（以 client.ts 的声明
// 与页面消费方式为准）。22 条端点与 `console_ops::endpoint_specs()` 的一致性由本节最后一个测试校验。

// ---------------------------------------------------------------- A. 模型网关

#[tokio::test]
async fn console_route_policies_is_bare_array() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/models/route-policies", None).await;
    let resp = h.get("/api/v1/models/route-policies").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert!(body.is_array(), "client.ts 声明 ModelRoutePolicy[]，必须是裸数组: {body}");
    assert_eq!(body.as_array().map(Vec::len), Some(0), "网关未持久化路由策略时必须为空集合而非 404: {body}");
}

#[tokio::test]
async fn console_route_policy_save_persists_and_round_trips() {
    let h = setup().await;
    let mut endpoints = Vec::new();
    for name in ["primary", "fallback"] {
        let endpoint = h
            .post(
                "/api/v1/gateway/endpoints",
                json!({"name":name,"provider":"mock",
            "model":name,"base_url":"http://mock.invalid/v1"}),
            )
            .await;
        assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
        endpoints.push(endpoint.json()["id"].as_str().unwrap().to_string());
    }
    let primary = &endpoints[0];
    let fallback = &endpoints[1];
    let id = agf_core::ids::Id::new();
    let uri = format!("/api/v1/models/route-policies/{id}");
    // 新建：必须给 name + primary_endpoint_id（否则 400，不静默创建空策略）
    let incomplete = json!({"name": "cost-first"});
    assert_unauthorized(&h, "PUT", &uri, Some(incomplete.clone())).await;
    let incomplete_resp = h.request("PUT", &uri, Some(&h.admin), Some(incomplete)).await;
    assert_eq!(incomplete_resp.status, StatusCode::BAD_REQUEST, "{}", incomplete_resp.text);

    // 正例：真实落库 + 返回更新后的对象（裸对象，与 client.ts 声明的类型一致）
    let payload = json!({
        "id": id.to_string(),
        "name": "cost-first",
        "primaryEndpointId": primary,
        "fallbackEndpointIds": [fallback],
        "strategy": "cost-first",
        "weights": {(primary): 0.7, (fallback): 0.3},
        "budgetUsdPerDay": 12.5,
        "enabled": true
    });
    let resp = h.request("PUT", &uri, Some(&h.admin), Some(payload.clone())).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let saved = resp.json();
    assert_eq!(saved["id"], id.to_string().as_str());
    assert_eq!(saved["name"], "cost-first");
    assert_eq!(saved["version"], 1);
    assert_eq!(saved["primary_endpoint_id"], primary.as_str());
    assert_eq!(saved["fallback_endpoint_ids"], json!([fallback]));
    assert_eq!(saved["strategy"], "cost-first");
    assert_eq!(saved["weights"][fallback], 0.3);
    assert_eq!(saved["budget_usd_per_day"], 12.5);
    assert!(saved["tenant_id"].is_null(), "租户是存储侧字段，不外泄: {saved}");

    // 读路径闭环：列表里读回来字段一致（同一份记录面）
    let listed = h.get("/api/v1/models/route-policies").await.json();
    let row = listed
        .as_array()
        .and_then(|items| items.iter().find(|item| item["id"] == id.to_string().as_str()))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(row["strategy"], "cost-first", "{listed}");
    assert_eq!(row["primary_endpoint_id"], primary.as_str());

    // 部分更新：前端开关只传 {id, enabled}
    let toggled = h
        .request(
            "PUT",
            &uri,
            Some(&h.admin),
            Some(json!({"id": id.to_string(), "expectedVersion":1, "enabled": false})),
        )
        .await;
    assert_eq!(toggled.status, StatusCode::OK, "{}", toggled.text);
    let toggled = toggled.json();
    assert_eq!(toggled["enabled"], false);
    assert_eq!(toggled["version"], 2);
    assert_eq!(
        h.request("PUT", &uri, Some(&h.admin), Some(json!({"expectedVersion":1,"enabled":true}))).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(toggled["name"], "cost-first", "未提供的字段必须保持原值: {toggled}");
    let stored = h.state.store.route_policy_get(h.tenant, id).expect("读取失败").expect("策略应已落库");
    assert!(!stored.enabled);
    assert_eq!(stored.name, "cost-first");

    // 边界：id 非法 400；字段非法（策略词表外/预算为负/权重非数字）400
    let bad_id = h.request("PUT", "/api/v1/models/route-policies/nope", Some(&h.admin), Some(json!({}))).await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST, "{}", bad_id.text);
    let bad_strategy = h.request("PUT", &uri, Some(&h.admin), Some(json!({"strategy": "cheapest"}))).await;
    assert_eq!(bad_strategy.status, StatusCode::BAD_REQUEST, "{}", bad_strategy.text);
    let bad_budget = h.request("PUT", &uri, Some(&h.admin), Some(json!({"budgetUsdPerDay": -1}))).await;
    assert_eq!(bad_budget.status, StatusCode::BAD_REQUEST, "{}", bad_budget.text);
    let bad_weights = h.request("PUT", &uri, Some(&h.admin), Some(json!({"weights": {"ep": "high"}}))).await;
    assert_eq!(bad_weights.status, StatusCode::BAD_REQUEST, "{}", bad_weights.text);
    // 权限：viewer 无 models:write → 403
    let viewer = h.request("PUT", &uri, Some(&h.viewer), Some(payload)).await;
    assert_eq!(viewer.status, StatusCode::FORBIDDEN, "{}", viewer.text);
}

#[tokio::test]
async fn console_model_usage_is_paged_envelope_with_zero_total() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/models/usage", None).await;
    let resp = h.get("/api/v1/models/usage?page=1&page_size=10").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert!(body["items"].as_array().is_some_and(Vec::is_empty), "计量未接入时必须是空 items: {body}");
    assert_eq!(body["total"], 0);
    assert_eq!(body["page"], 1);
    assert_eq!(body["page_size"], 10);
    assert_eq!(body["has_more"], false);
    assert!(body["next_cursor"].is_null(), "无数据时不应有游标: {body}");
}

#[tokio::test]
async fn console_model_usage_aggregate_is_bare_array() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/models/usage/aggregate", None).await;
    let resp = h.get("/api/v1/models/usage/aggregate").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert!(body.is_array(), "client.ts 声明 ModelUsageAggregate[]，必须是裸数组: {body}");
    assert_eq!(body.as_array().map(Vec::len), Some(0), "{body}");
}

// ------------------------------------------------------- B. SOC / 生态动作

#[tokio::test]
async fn console_skill_status_updates_skill_and_round_trips() {
    let h = setup().await;
    let skill_id = seed_console_skill(&h).await;
    let uri = format!("/api/v1/skills/{skill_id}/status");
    assert_unauthorized(&h, "POST", &uri, Some(json!({"status": "approved"}))).await;

    let pending = h.get(&format!("/api/v1/skills/{skill_id}")).await.json();
    assert_eq!(pending["skill"]["status"], "pending");
    assert!(pending["skill"]["decidedAt"].is_null());
    let approved = h
        .post(
            &uri,
            json!({"status":"approved","owner":"carol",
        "data_class":"internal","note":"Reviewed ownership and data access",
        "expected_updated_at":pending["skill"]["review"]["updatedAt"]}),
        )
        .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text);
    assert_eq!(approved.json()["status"], "approved");
    assert!(approved.json()["decidedAt"].is_string());
    assert!(approved.json()["decidedBy"].is_string());
    // 读路径闭环：/skills 列表里读回来必须也是 approved（读写同一份台账口径）
    let listed = h.get("/api/v1/skills").await.json();
    assert_eq!(listed["items"][0]["status"], "approved", "{listed}");

    // 变更台账留痕（/assets/{id} 可查）
    let changes = h.get(&format!("/api/v1/assets/{skill_id}")).await.json();
    assert!(changes["changes"].as_array().is_some_and(|c| !c.is_empty()), "状态流转必须留变更记录: {changes}");

    let bad = h.post(&uri, json!({"status": "nope"})).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.text);
    let empty = h.post(&uri, json!({})).await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST, "缺 status 必须 400: {}", empty.text);
    let missing = h
        .post(
            &format!("/api/v1/skills/{}/status", agf_core::ids::Id::new()),
            json!({"status": "approved", "note":"Reviewed"}),
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn console_skill_whitelist_updates_and_returns_skill() {
    let h = setup().await;
    let skill_id = seed_console_skill(&h).await;
    let uri = format!("/api/v1/skills/{skill_id}/whitelist");
    let payload = json!({"domains": ["api.intra", "kb.intra"], "paths": ["/v1/query"]});
    assert_unauthorized(&h, "PUT", &uri, Some(payload.clone())).await;

    let resp = h.request("PUT", &uri, Some(&h.admin), Some(payload)).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let skill = resp.json();
    assert_eq!(skill["id"], skill_id.as_str());
    assert_eq!(skill["whitelist"]["domains"], json!(["api.intra", "kb.intra"]), "{skill}");
    assert_eq!(skill["whitelist"]["paths"], json!(["/v1/query"]));

    // 读路径闭环：/skills 列表里也是新白名单
    let listed = h.get("/api/v1/skills").await.json();
    assert_eq!(listed["items"][0]["whitelist"]["domains"], json!(["api.intra", "kb.intra"]), "{listed}");

    // 清空白名单是合法操作
    let cleared = h.request("PUT", &uri, Some(&h.admin), Some(json!({"domains": [], "paths": []}))).await;
    assert_eq!(cleared.status, StatusCode::OK, "{}", cleared.text);
    assert_eq!(cleared.json()["whitelist"]["domains"], json!([]));

    let missing = h
        .request(
            "PUT",
            &format!("/api/v1/skills/{}/whitelist", agf_core::ids::Id::new()),
            Some(&h.admin),
            Some(json!({"domains": [], "paths": []})),
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn console_finding_status_alias_delegates_to_state_handler() {
    let h = setup().await;
    let (finding_id, _) = seed_console_finding_and_alert(&h).await;
    let uri = format!("/api/v1/findings/{finding_id}/status");
    assert_unauthorized(&h, "POST", &uri, Some(json!({"status": "verified"}))).await;

    let resp = h.post(&uri, json!({"status": "verified", "evidence_level": "confirmed"})).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let finding = resp.json();
    // 控制台声明 Finding | undefined（裸对象），必须拆掉既有处理器的 {"finding": …} 包裹
    assert!(finding.get("finding").is_none(), "别名必须返回裸对象: {finding}");
    assert_eq!(finding["id"], finding_id.as_str());
    assert_eq!(finding["state"], "verified", "状态流转必须与既有 /state 同源: {finding}");
    assert_eq!(finding["evidence_level"], "confirmed");

    // 与既有 /findings/{id}/state 同处理器：同一份数据读回来一致
    let detail = h.get(&format!("/api/v1/findings/{finding_id}")).await.json();
    assert_eq!(detail["finding"]["state"], "verified", "{detail}");

    let bad = h.post(&uri, json!({"status": "not-a-state"})).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.text);
    let missing =
        h.post(&format!("/api/v1/findings/{}/status", agf_core::ids::Id::new()), json!({"status": "verified"})).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn console_alert_status_alias_maps_frontend_statuses() {
    let h = setup().await;
    let (_, alert_id) = seed_console_finding_and_alert(&h).await;
    let uri = format!("/api/v1/alerts/{alert_id}/status");
    assert_unauthorized(&h, "POST", &uri, Some(json!({"status": "open"}))).await;

    // 前端词表独有值：in-progress → acknowledged、resolved → closed
    let ack = h.post(&uri, json!({"status": "in-progress"})).await;
    assert_eq!(ack.status, StatusCode::OK, "{}", ack.text);
    let alert = ack.json();
    assert!(alert.get("alert").is_none(), "别名必须返回裸对象: {alert}");
    assert_eq!(alert["id"], alert_id.as_str());
    assert_eq!(alert["state"], "acknowledged", "in-progress 必须映射到既有态: {alert}");

    let resolved = h.post(&uri, json!({"status": "resolved"})).await;
    assert_eq!(resolved.status, StatusCode::OK, "{}", resolved.text);
    assert_eq!(resolved.json()["state"], "closed", "resolved 必须映射到终态: {}", resolved.text);

    // 共有值直通
    let reopened = h.post(&uri, json!({"status": "open"})).await;
    assert_eq!(reopened.status, StatusCode::OK, "{}", reopened.text);
    assert_eq!(reopened.json()["state"], "open");

    let bad = h.post(&uri, json!({"status": "nope"})).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.text);
    let missing =
        h.post(&format!("/api/v1/alerts/{}/status", agf_core::ids::Id::new()), json!({"status": "open"})).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn console_escalation_routes_project_sla_ladder() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/alerts/escalation-routes", None).await;
    let resp = h.get("/api/v1/alerts/escalation-routes").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let routes = body.as_array().expect("client.ts 声明 EscalationRoute[]，必须是裸数组");
    assert_eq!(routes.len(), 5, "五个严重等级各一条: {body}");
    let severities: Vec<&str> = routes.iter().filter_map(|r| r["minSeverity"].as_str()).collect();
    assert_eq!(severities, vec!["critical", "high", "medium", "low", "info"]);
    let critical = &routes[0];
    assert_eq!(critical["id"], "sla-critical");
    assert_eq!(critical["enabled"], false, "automatic delivery requires an explicit configuration");
    assert_eq!(critical["afterMinutes"], 15, "critical 首次响应 900s → 15 分钟: {critical}");
    let tiers = critical["tiers"].as_array().expect("tiers 缺失");
    assert_eq!(tiers.len(), 2, "critical 阶梯两级: {critical}");
    assert_eq!(tiers[0]["tier"], 1);
    assert_eq!(tiers[0]["afterMinutes"], 15);
    assert_eq!(tiers[0]["targets"], json!(["on-call"]));
    assert_eq!(tiers[0]["channels"], json!([]), "SLA 阶梯不含渠道，必须留空而不是编造: {}", tiers[0]);
    assert_eq!(tiers[1]["tier"], 2);
    assert_eq!(tiers[1]["targets"], json!(["incident-commander"]));
    assert_eq!(routes[4]["tiers"], json!([]), "info 级没有升级阶梯: {}", routes[4]);
}

#[tokio::test]
async fn console_case_soar_runs_is_empty_array_for_existing_case() {
    let h = setup().await;
    let case = h.post("/api/v1/cases", json!({"title": "SOAR 轨迹", "severity": "high"})).await;
    assert_eq!(case.status, StatusCode::CREATED, "{}", case.text);
    let case_id = case.json()["case"]["id"].as_str().unwrap().to_string();
    let uri = format!("/api/v1/cases/{case_id}/soar-runs");
    assert_unauthorized(&h, "GET", &uri, None).await;

    let resp = h.get(&uri).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert!(body.is_array(), "client.ts 声明 SoarRun[]，必须是裸数组: {body}");
    assert_eq!(body.as_array().map(Vec::len), Some(0), "剧本执行未实现，无轨迹时必须是空数组: {body}");

    let missing = h.get(&format!("/api/v1/cases/{}/soar-runs", agf_core::ids::Id::new())).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let malformed = h.get("/api/v1/cases/not-a-uuid/soar-runs").await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn console_mcp_tools_project_attribute_tool_list() {
    let h = setup().await;
    // 台账是工具清单的唯一来源：发现侧把工具写进 attributes.tools（这里直接落到内存台账）
    let mut asset = agf_core::asset::Asset::new(
        h.tenant,
        agf_core::enums::AssetKind::McpServer,
        "控制台工具 MCP",
        "fp-console-tools",
    );
    asset.attributes.insert(
        "tools".to_string(),
        json!([
            {
                "name": "read_file",
                "description": "读取本地文件",
                "invocations_24h": 12,
                "sensitive_params": ["path"],
                "datasources": ["fs"]
            },
            "shell_exec"
        ]),
    );
    let server_id = h.state.store.asset_upsert(&asset).expect("写入资产失败");
    let uri = format!("/api/v1/mcp-servers/{server_id}/tools");
    assert_unauthorized(&h, "GET", &uri, None).await;

    let resp = h.get(&uri).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let tools = body.as_array().expect("client.ts 声明 McpTool[]，必须是裸数组");
    assert_eq!(tools.len(), 2, "{body}");
    let read_file = &tools[0];
    assert_eq!(read_file["serverId"], server_id.to_string().as_str());
    assert_eq!(read_file["name"], "read_file");
    assert_eq!(read_file["invocations24h"], 12);
    assert_eq!(read_file["sensitiveParams"], json!(["path"]));
    assert_eq!(read_file["datasources"], json!(["fs"]));
    assert!(read_file["capabilities"].as_array().is_some_and(|c| !c.is_empty()), "{read_file}");
    assert!(["info", "low", "medium", "high", "critical"].contains(&read_file["riskLevel"].as_str().unwrap_or("")));
    // 只有名字的工具：风险等级由 agf_core::mcp::ToolTraits::infer 推断（shell → high）
    assert_eq!(tools[1]["name"], "shell_exec");
    assert!(tools[1]["invocations24h"].is_null());
    assert_eq!(tools[1]["riskLevel"], "high", "{}", tools[1]);
    assert_eq!(tools[1]["capabilities"], json!(["execute"]));

    // 非 MCP 资产 / 不存在的 id / 非法 id
    let mut skill =
        agf_core::asset::Asset::new(h.tenant, agf_core::enums::AssetKind::Skill, "不是 MCP", "fp-console-not-mcp");
    skill.attributes.insert("tools".to_string(), json!(["x"]));
    let skill_id = h.state.store.asset_upsert(&skill).expect("写入资产失败");
    assert_eq!(h.get(&format!("/api/v1/mcp-servers/{skill_id}/tools")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        h.get(&format!("/api/v1/mcp-servers/{}/tools", agf_core::ids::Id::new())).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.get("/api/v1/mcp-servers/not-a-uuid/tools").await.status, StatusCode::BAD_REQUEST);
}
