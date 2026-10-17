//! 控制台补齐端点（routes::console_ops）第二批：别名、集成适配器、阿里云与端点清单一致性。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

#[tokio::test]
async fn console_campaign_results_are_bare_array() {
    let h = setup().await;
    let cases = h.get("/api/v1/redteam/cases?page_size=3").await.json();
    if cases["total"].as_u64().unwrap_or(0) == 0 {
        // 用例目录缺失时无法发起战役：只校验路由与形状（空数组是合法响应）
        let empty = h.get(&format!("/api/v1/redteam/campaigns/{}/results", agf_core::ids::Id::new())).await;
        assert_eq!(empty.status, StatusCode::NOT_FOUND);
        return;
    }
    let key = cases["items"][0]["key"].as_str().unwrap().to_string();
    let launched = h
        .post("/api/v1/redteam/campaigns", json!({"name": "控制台战役", "case_keys": [key], "guard_strength": 20}))
        .await;
    assert_eq!(launched.status, StatusCode::ACCEPTED, "{}", launched.text);
    let campaign_id = launched.json()["campaign"]["id"].as_str().unwrap().to_string();
    wait_campaign(&h, &campaign_id).await;
    let uri = format!("/api/v1/redteam/campaigns/{campaign_id}/results");
    assert_unauthorized(&h, "GET", &uri, None).await;

    let resp = h.get(&uri).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let results = body.as_array().expect("client.ts 声明 CampaignResult[]，必须是裸数组");
    assert!(!results.is_empty(), "刚跑完的战役必须有逐用例结果: {body}");
    let first = &results[0];
    assert_eq!(first["campaignId"], campaign_id.as_str());
    assert!(first["id"].is_string() && first["caseId"].is_string() && first["target"].is_string());
    assert!(["succeeded", "blocked", "bypassed"].contains(&first["outcome"].as_str().unwrap_or("")));
    assert!(["info", "low", "medium", "high", "critical"].contains(&first["severity"].as_str().unwrap_or("")));
    assert!(
        [
            "direct-injection",
            "indirect-injection",
            "rag-poisoning",
            "multi-turn-social",
            "credential-theft",
            "privilege-escalation",
            "lateral-movement",
            "resource-exhaustion",
            "prompt-injection",
            "jailbreak",
            "tool-abuse",
            "data-exfiltration",
            "credential-leak",
            "mcp-shadow",
            "model-dos",
            "supply-chain"
        ]
        .contains(&first["category"].as_str().unwrap_or(""))
    );
    assert!(first["bypassPath"].is_array() && first["ranAt"].as_str().is_some_and(|t| t.ends_with('Z')));

    let missing = h.get(&format!("/api/v1/redteam/campaigns/{}/results", agf_core::ids::Id::new())).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn console_rule_detail_alias_is_served_by_same_handler() {
    let h = setup().await;
    // 别名 /rules/{id} 与既有 /rules/{key} 同形路由：未认证同样必须 401
    assert_unauthorized(&h, "GET", &format!("/api/v1/rules/{}", agf_core::ids::Id::new()), None).await;
    let rules = h.get("/api/v1/rules?page_size=1").await.json();
    if rules["total"].as_u64().unwrap_or(0) == 0 {
        let missing = h.get(&format!("/api/v1/rules/{}", agf_core::ids::Id::new())).await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        return;
    }
    let key = rules["items"][0]["key"].as_str().unwrap().to_string();
    // 既有 /rules/{key} 与 /rules/{id} 同形：一条路由同时覆盖两个路径名
    let detail = h.get(&format!("/api/v1/rules/{key}")).await;
    assert_eq!(detail.status, StatusCode::OK, "{}", detail.text);
    assert_eq!(detail.json()["rule"]["key"], key.as_str());
    let missing = h.get(&format!("/api/v1/rules/{}", agf_core::ids::Id::new())).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn console_rule_test_returns_result_object_even_when_samples_fail() {
    let h = setup().await;
    let rules = h.get("/api/v1/rules?page_size=1").await.json();
    if rules["total"].as_u64().unwrap_or(0) == 0 {
        let uri = format!("/api/v1/rules/{}/test", agf_core::ids::Id::new());
        assert_unauthorized(&h, "POST", &uri, None).await;
        assert_eq!(h.post(&uri, json!({})).await.status, StatusCode::NOT_FOUND);
        return;
    }
    let key = rules["items"][0]["key"].as_str().unwrap().to_string();
    let uri = format!("/api/v1/rules/{key}/test");
    assert_unauthorized(&h, "POST", &uri, None).await;

    let resp = h.post(&uri, json!({})).await;
    assert_eq!(resp.status, StatusCode::OK, "样本不通过也必须是 200 + 结果对象: {}", resp.text);
    let body = resp.json();
    assert_eq!(body["ruleId"], key.as_str());
    assert!(body["ranAt"].as_str().is_some_and(|t| t.ends_with('Z')));
    for field in ["truePositive", "falseNegative", "trueNegative", "falsePositive"] {
        assert!(body[field].is_number(), "{field} 必须是数字: {body}");
    }
    let samples = body["samples"].as_array().expect("samples 必须是数组");
    assert!(!samples.is_empty(), "规则自带正负样本: {body}");
    let total = body["truePositive"].as_u64().unwrap_or(0) + body["falseNegative"].as_u64().unwrap_or(0);
    let positives = samples.iter().filter(|s| s["label"] == "positive").count();
    assert_eq!(Some(total), u64::try_from(positives).ok(), "正样本总数必须等于 TP+FN: {body}");
    for sample in samples {
        assert!(sample["id"].is_string() && sample["ruleId"] == key.as_str() && sample["payload"].is_string());
        assert!(sample["matched"].is_boolean());
        assert!(sample["latencyMs"].is_number());
        assert!(["positive", "negative"].contains(&sample["label"].as_str().unwrap_or("")));
    }
    let missing = h.post(&format!("/api/v1/rules/{}/test", agf_core::ids::Id::new()), json!({})).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

// ------------------------------------------------------------ C. 生态与别名

#[tokio::test]
async fn console_ingest_sources_alias_matches_sources() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/ingest/sources", None).await;
    let alias = h.get("/api/v1/ingest/sources").await;
    assert_eq!(alias.status, StatusCode::OK, "{}", alias.text);
    let canonical = h.get("/api/v1/sources").await;
    assert_eq!(canonical.status, StatusCode::OK, "{}", canonical.text);
    let alias_body = alias.json();
    let canonical_body = canonical.json();
    assert_eq!(alias_body["total"], canonical_body["total"], "别名必须与 /sources 同一份数据");
    // 控制台 IngestPage 按 data?.data?.items 消费（分页信封）
    assert!(alias_body["items"].is_array(), "{alias_body}");
    assert_eq!(alias_body["total"], 0, "日志源只展示已保存配置");
}

#[tokio::test]
async fn console_ingest_parsers_alias_matches_parsers() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/ingest/parsers", None).await;
    let alias = h.get("/api/v1/ingest/parsers").await;
    assert_eq!(alias.status, StatusCode::OK, "{}", alias.text);
    let canonical = h.get("/api/v1/parsers").await;
    assert_eq!(canonical.status, StatusCode::OK, "{}", canonical.text);
    let alias_body = alias.json();
    assert_eq!(alias_body["total"], canonical.json()["total"], "别名必须与 /parsers 同一份数据");
    assert!(alias_body["items"].is_array(), "{alias_body}");
    assert!(alias_body["items"][0]["engine"].is_string(), "{alias_body}");
}

#[tokio::test]
async fn console_integration_adapters_are_bare_array() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/integrations/adapters", None).await;
    let resp = h.get("/api/v1/integrations/adapters").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let adapters = body.as_array().expect("client.ts 声明 Adapter[]，必须是裸数组");
    assert_eq!(adapters.len(), 12, "agf-adapters 内置 12 个适配器: {body}");
    let categories = ["llm-provider", "edr", "siem", "soar", "iam", "cloud", "dlp", "notify", "storage"];
    for adapter in adapters {
        assert!(adapter["id"].is_string() && adapter["name"].is_string() && adapter["vendor"].is_string());
        assert!(
            categories.contains(&adapter["category"].as_str().unwrap_or("")),
            "category 必须是前端词表内的取值: {adapter}"
        );
        assert!(["healthy", "degraded", "unhealthy", "unknown"].contains(&adapter["health"].as_str().unwrap_or("")));
        assert!(adapter["mock"].is_boolean() && adapter["configured"].is_boolean());
        assert!(adapter["capabilities"].is_array());
        assert!(adapter["version"].is_string());
        assert!(adapter["lastSyncAt"].is_null(), "注册表不保存同步时间，不得编造: {adapter}");
        assert!(adapter["config"].is_object());
        assert!(adapter["degradedBehavior"].as_str().is_some_and(|d| !d.is_empty()), "降级行为必填: {adapter}");
    }
    let by_id = |id: &str| adapters.iter().find(|a| a["id"] == id).cloned().unwrap_or(Value::Null);
    assert_eq!(by_id("feishu")["category"], "notify");
    assert_eq!(by_id("jira")["category"], "soar");
    assert_eq!(by_id("syslog-forwarder")["category"], "siem");
    assert_eq!(by_id("edr-isolation")["category"], "edr");
    assert_eq!(by_id("iam-scim")["category"], "iam");
    assert_eq!(by_id("feishu")["health"], "degraded", "Mock 态是降级而不是失败");
    assert_eq!(by_id("feishu")["mock"], true);
}

#[tokio::test]
async fn console_integration_adapter_detail_and_not_found() {
    let h = setup().await;
    let uri = "/api/v1/integrations/adapters/feishu";
    assert_unauthorized(&h, "GET", uri, None).await;
    let resp = h.get(uri).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let adapter = resp.json();
    assert_eq!(adapter["id"], "feishu");
    assert!(adapter.get("items").is_none(), "详情是单个 Adapter 对象: {adapter}");
    let missing = h.get("/api/v1/integrations/adapters/nope").await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn console_alicloud_self_check_alias_projects_items() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/alicloud/self-check", None).await;
    let resp = h.get("/api/v1/alicloud/self-check").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let items = body.as_array().expect("client.ts 声明 SelfCheckItem[]，必须是裸数组");
    assert!(items.len() >= 6, "六个云适配器各至少一条连通性检查: {body}");
    let categories = ["connectivity", "least-privilege", "quota"];
    for item in items {
        assert!(item["id"].is_string() && item["name"].is_string() && item["detail"].is_string());
        assert!(categories.contains(&item["category"].as_str().unwrap_or("")));
        assert!(["pass", "warn", "fail"].contains(&item["result"].as_str().unwrap_or("")));
        assert!(item["requirement"].is_string() && item["value"].is_string());
        assert!(item["checkedAt"].is_null(), "尚无真实检查记录时不得编造检查时间: {item}");
    }
    assert_eq!(
        items.iter().filter(|i| i["category"] == "connectivity").count(),
        6,
        "每个云适配器一条连通性检查: {body}"
    );
    // 旧客户端使用 POST；读取记录的兼容入口也必须可用。
    let posted = h.post("/api/v1/alicloud/self-check", json!({})).await;
    assert_eq!(posted.status, StatusCode::OK, "{}", posted.text);
    assert_eq!(posted.json().as_array().map(Vec::len), Some(items.len()));

    let saved = h
        .request(
            "PUT",
            "/api/v1/alicloud/connections/alicloud-cms",
            Some(&h.admin),
            Some(json!({"enabled":true,"mock":true,"settings":{},"expected_version":0})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let probe = h.post("/api/v1/alicloud/connections/alicloud-cms/probe", json!({"configuration_version":1})).await;
    assert_eq!(probe.status, StatusCode::OK, "{}", probe.text);
    let checked = h.get("/api/v1/alicloud/self-check").await.json();
    let cms = checked.as_array().unwrap();
    assert!(cms.iter().any(|item| item["id"] == "alicloud-cms-connectivity"
        && item["checkedAt"].as_str().is_some_and(|time| time.ends_with('Z'))));
    assert!(
        cms.iter().any(|item| item["id"] == "alicloud-cms-quota" && item["checkedAt"].is_null()),
        "只读连通性检查不能伪装成配额检查"
    );
    assert!(
        cms.iter().any(|item| item["id"] == "alicloud-cms-least-privilege"
            && item["result"] == "warn"
            && item["checkedAt"].is_null()),
        "只读接口成功不能证明当前云身份遵循最小权限"
    );
}

#[tokio::test]
async fn console_alicloud_agentteams_are_bare_array() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/alicloud/agentteams", None).await;
    let resp = h.get("/api/v1/alicloud/agentteams").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let teams = body.as_array().expect("client.ts 声明 AgentTeam[]，必须是裸数组");
    assert_eq!(teams.len(), 3, "Mock fixtures 三个团队: {body}");
    let roles = ["orchestrator", "worker", "critic", "retriever", "tool-agent"];
    let statuses = ["active", "idle", "offline"];
    for team in teams {
        assert!(team["id"].is_string() && team["name"].is_string() && team["workspaceId"].is_string());
        assert_eq!(team["region"], "cn-hangzhou");
        assert_eq!(team["memberCount"], 2);
        let members = team["members"].as_array().expect("members 缺失");
        assert_eq!(members.len(), 2);
        for member in members {
            assert!(member["id"].is_string() && member["name"].is_string() && member["model"].is_string());
            assert!(roles.contains(&member["role"].as_str().unwrap_or("")), "{member}");
            assert!(statuses.contains(&member["status"].as_str().unwrap_or("")), "{member}");
            assert_eq!(member["invocations24h"], 0, "云侧 fixtures 无调用计数，不得编造: {member}");
        }
        let dag = team["dag"].as_array().expect("dag 缺失");
        assert_eq!(dag.len(), 2);
        assert!(dag[0]["dependsOn"].is_array() && dag[0]["label"].is_string());
        assert!(team["riskScore"].is_number() && team["createdAt"].as_str().is_some_and(|t| t.ends_with('Z')));
    }
    // 角色映射与风险分（未纳管占比）是可解释推导：team-risk 全纳管 → 0，team-ops 全未纳管 → 100
    assert_eq!(teams[0]["riskScore"], 0, "{}", teams[0]);
    assert_eq!(teams[1]["riskScore"], 50, "{}", teams[1]);
    assert_eq!(teams[2]["riskScore"], 100, "{}", teams[2]);
    assert_eq!(teams[0]["members"][0]["role"], "critic", "分析员 → critic");
    assert_eq!(teams[0]["members"][1]["role"], "retriever", "检索员 → retriever");
    assert_eq!(teams[0]["crossTeamCalls24h"], 2, "{}", teams[0]);
}

#[tokio::test]
async fn console_alicloud_cross_team_calls_are_bare_array() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/alicloud/cross-team-calls", None).await;
    let resp = h.get("/api/v1/alicloud/cross-team-calls").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let calls = body.as_array().expect("client.ts 声明 CrossTeamCall[]，必须是裸数组");
    assert_eq!(calls.len(), 3, "fixtures 三条互不重复的调用链: {body}");
    for call in calls {
        assert!(call["id"].is_string() && call["callerTeam"].is_string() && call["calleeTeam"].is_string());
        assert!(call["calleeAgent"].is_string());
        assert!(call["count24h"].as_u64().unwrap_or(0) >= 1);
        assert!(call["authorized"].is_boolean() && call["sensitiveData"].is_boolean());
    }
    let blocked = calls.iter().find(|c| c["authorized"] == false).expect("fixtures 应含一条被阻断的调用");
    assert_eq!(blocked["sensitiveData"], true, "跨账号调用应标记为敏感数据边界: {blocked}");
    assert_eq!(blocked["callerTeam"], "team-research");
    assert_eq!(blocked["calleeTeam"], "team-ops");
}

#[tokio::test]
async fn console_alicloud_service_bindings_are_bare_array() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/alicloud/service-bindings", None).await;
    let resp = h.get("/api/v1/alicloud/service-bindings").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    let bindings = body.as_array().expect("client.ts 声明 ServiceBinding[]，必须是裸数组");
    assert_eq!(bindings.len(), 5, "前端 AliCloudService 词表只覆盖五服务（不含 agentteams）: {body}");
    let services = ["cms", "apig", "mse", "privatelink", "schedulerx3"];
    for binding in bindings {
        assert!(services.contains(&binding["service"].as_str().unwrap_or("")), "{binding}");
        assert!(binding["displayName"].as_str().is_some_and(|n| !n.is_empty()));
        assert!(binding["bound"].is_boolean());
        assert!(binding["region"].is_string());
        assert!(["healthy", "degraded", "unhealthy", "unknown"].contains(&binding["health"].as_str().unwrap_or("")));
        assert!(binding["note"].is_string());
    }
    // 无云凭据环境：全部 Mock、未绑定、无资源 id（不得编造资源）
    assert!(bindings.iter().all(|b| b["bound"] == false), "{body}");
    assert!(bindings.iter().all(|b| b["resourceId"].is_null()), "{body}");
    assert!(bindings.iter().all(|b| b["region"] == "cn-hangzhou"), "{body}");
    assert!(bindings.iter().all(|b| b["health"] == "unknown"), "未配置的云连接状态不可推测: {body}");
}

#[tokio::test]
async fn console_ops_endpoint_specs_match_registered_routes() {
    use agf_api::routes::console_ops;
    let specs = console_ops::endpoint_specs();
    assert_eq!(specs.len(), 23, "控制台补齐端点清单应为 23 条（含用量投影状态查询）");
    assert!(
        specs.iter().any(|spec| spec.path == "/api/v1/models/usage/projection-status"
            && spec.method == utoipa::openapi::path::HttpMethod::Get),
        "用量投影状态查询必须出现在控制台端点清单中"
    );
    let integrity_path = "/api/v1/runtime/events/{id}/integrity";
    assert!(
        agf_api::routes::platform::endpoint_specs()
            .iter()
            .any(|spec| { spec.path == integrity_path && spec.method == utoipa::openapi::path::HttpMethod::Get }),
        "运行记录完整性查询必须出现在所属的全局端点清单中"
    );
    let not_implemented: Vec<&str> = specs.iter().filter(|s| !s.implemented).map(|s| s.path).collect();
    assert!(not_implemented.is_empty(), "23 条控制台补齐端点全部已实现（路由策略保存已接线）: {not_implemented:?}");
    for spec in &specs {
        assert!(spec.path.starts_with("/api/v1/"), "清单路径必须是完整路径: {}", spec.path);
        assert!(!spec.path.ends_with('/'), "路径不应以斜杠结尾: {}", spec.path);
        assert!(!spec.id.is_empty() && !spec.summary.is_empty() && !spec.tag.is_empty(), "{}", spec.path);
    }

    // 清单里每条路径都必须真的有路由：按声明方法请求后，响应**不能**是路由层 fallback 的 404。
    // （axum 的 `Router::fallback` 同时接管"方法不允许"，所以 405 不能当"路由存在"探针用；
    //  未注册路径的 404 里 `detail` 一定含**完整路径**（fallback 用 `uri.path()` 当 id），
    //  处理器自己的 404 只带实体 id，二者可区分。）
    let h = setup().await;
    for spec in &specs {
        // 清单路径不带前缀（父模块统一加），请求时补上 `/api/v1`
        let uri = spec.path.replace("{id}", &agf_core::ids::Id::new().to_string());
        let method = match spec.method {
            utoipa::openapi::path::HttpMethod::Get => "GET",
            utoipa::openapi::path::HttpMethod::Post => "POST",
            utoipa::openapi::path::HttpMethod::Put => "PUT",
            _ => panic!("清单出现未预期的方法"),
        };
        let resp = h.request(method, &uri, Some(&h.admin), None).await;
        let detail = resp.json()["detail"].as_str().unwrap_or_default().to_string();
        let route_missing = resp.status == StatusCode::NOT_FOUND && detail.contains(&uri);
        assert!(!route_missing, "{method} {uri}（{}）未注册路由: {}", spec.path, resp.text);
        if method == "GET" && !spec.path.contains('{') {
            assert_eq!(resp.status, StatusCode::OK, "GET {uri} 期望 200: {}", resp.text);
        }
    }
    let response = h.get(&integrity_path.replace("{id}", &agf_core::ids::Id::new().to_string())).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["summary_matches"], false);
    assert_eq!(response.json()["checkpoint_verified"], false);
}

async fn wait_campaign(h: &Harness, id: &str) -> Value {
    for _ in 0..100 {
        let body = h.get(&format!("/api/v1/redteam/campaigns/{id}")).await.json();
        if body["campaign"]["state"] == "completed" {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("Campaign did not complete");
}
