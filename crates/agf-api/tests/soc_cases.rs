//! SOC 案件闭环：SLA 里程碑、剧本执行与审批门、通知去重、报表计划与案件状态流转。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

#[tokio::test]
async fn case_sla_derives_milestones_from_timeline_and_writes_back() {
    let h = setup().await;
    let case_id = create_case_for_soc(&h, "案件 SLA 用例", "high").await;
    let uri = format!("/api/v1/cases/{case_id}/sla");
    assert_unauthorized(&h, "GET", &uri, None).await;

    // 时间线：一次人工评论（首次响应）+ 一次隔离处置（遏制）
    let comment =
        h.post(&format!("/api/v1/cases/{case_id}/timeline"), json!({"kind": "comment", "note": "分析师已受理"})).await;
    assert_eq!(comment.status, StatusCode::OK, "{}", comment.text);
    let isolate = h
        .post(&format!("/api/v1/cases/{case_id}/timeline"), json!({"kind": "isolation", "note": "已隔离 Agent"}))
        .await;
    assert_eq!(isolate.status, StatusCode::OK, "{}", isolate.text);

    let resp = h.get(&uri).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert_eq!(body["case_id"], case_id.as_str());
    assert_eq!(body["severity"], "high");
    assert_eq!(body["timeline_events"], 3, "created + comment + isolation: {body}");
    assert_eq!(body["written_back"], true);
    let targets = body["targets"].as_array().expect("targets 必须是数组");
    assert_eq!(targets.len(), 3);
    assert_eq!(targets[0]["target"], "first-response");
    assert_eq!(targets[0]["target_secs"], 3600);
    assert_eq!(targets[0]["status"], "met", "已有人工受理 → 首次响应达成: {body}");
    assert_eq!(targets[1]["target"], "containment");
    assert_eq!(targets[1]["status"], "met", "已隔离 → 遏制达成: {body}");
    assert_eq!(targets[2]["target"], "resolution");
    assert_eq!(targets[2]["status"], "pending", "未解决: {body}");
    assert_eq!(body["overall"], "pending", "最坏结论口径: {body}");
    assert_eq!(body["breached"], false);
    assert!(body["due_at"].as_str().is_some_and(|t| t.ends_with('Z')), "{body}");
    assert_eq!(body["next_due"]["target"], "resolution", "{body}");
    assert_eq!(body["policy"]["name"], "sla-high");
    let milestones = body["milestones"].as_array().expect("milestones 必须是数组");
    let names: Vec<&str> = milestones.iter().filter_map(|m| m["target"].as_str()).collect();
    assert!(names.contains(&"first-response") && names.contains(&"containment"), "{body}");
    assert!(body["ignored_milestones"].as_array().is_some_and(Vec::is_empty), "{body}");
    // 写回落库
    let stored = h
        .state
        .store
        .case_get(h.tenant, agf_core::ids::Id::parse(&case_id).expect("id"))
        .expect("读取失败")
        .expect("案件应存在");
    assert!(stored.sla_due_at.is_some());
    assert!(!stored.sla_breached);

    // 边界：id 非法 → 400；案件不存在 → 404；viewer 有 cases:read → 200
    let bad_id = h.get("/api/v1/cases/not-a-uuid/sla").await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST, "{}", bad_id.text);
    let missing = h.get(&format!("/api/v1/cases/{}/sla", agf_core::ids::Id::new())).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND, "{}", missing.text);
    let viewer = h.request("GET", &uri, Some(&h.viewer), None).await;
    assert_eq!(viewer.status, StatusCode::OK, "只读角色应可读 SLA: {}", viewer.text);
}

/// 演示剧本 YAML（3 步：条件 + 动作 + 通知；无审批步骤 ⇒ 不需要审批门放行）。
const TEST_PLAYBOOK_YAML: &str = r"
key: test-contain
name: 测试-遏制与通知
description: 集成测试剧本
trigger:
  min_severity: high
steps:
  - name: 确认高危等级
    params:
      condition: 'input.severity_weight >= 8'
  - name: 隔离 Agent
    action: isolate-agent
  - name: 通知责任人
    notify_channel: in-app
";

/// 演示剧本 YAML（含审批步骤 ⇒ 默认拒绝执行）。
const TEST_PLAYBOOK_APPROVAL_YAML: &str = r"
key: test-approval
name: 测试-需审批
description: 集成测试剧本（审批门）
trigger:
  min_severity: high
steps:
  - name: 吊销凭据需审批
    params:
      require_approval: true
";

#[tokio::test]
async fn case_playbook_executes_engine_and_records_trace() {
    let h = setup().await;
    seed_ai_assets(&h).await;
    let agent = asset_id_of(&h, agf_core::enums::AssetKind::Agent);
    let created =
        h.post("/api/v1/cases", json!({"title":"剧本执行用例","severity":"critical","asset_ids":[agent]})).await;
    let case_id = created.json()["case"]["id"].as_str().unwrap().to_owned();
    let channel =
        h.request("PUT", "/api/v1/settings/notifications/in-app", Some(&h.admin), Some(json!({"enabled":true}))).await;
    assert_eq!(channel.status, StatusCode::OK, "{}", channel.text);
    let uri = format!("/api/v1/cases/{case_id}/playbook");
    assert_unauthorized(&h, "POST", &uri, Some(json!({"yaml": TEST_PLAYBOOK_YAML}))).await;

    // 正例：真实执行（隔离控制 + 持久化站内通知），轨迹落 soar_runs
    let resp = h.post(&uri, json!({"yaml": TEST_PLAYBOOK_YAML, "approve": true})).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert_eq!(body["playbook"], "test-contain");
    assert_eq!(body["outcome"], "completed", "{body}");
    assert_eq!(body["step_count"], 3);
    assert_eq!(body["has_failure"], false);
    assert_eq!(body["dry_run"], false);
    let steps = body["steps"].as_array().expect("steps 必须是数组");
    assert_eq!(steps[0]["kind"], "condition");
    assert_eq!(steps[0]["outcome"], "succeeded");
    assert!(steps[0]["note"].as_str().is_some_and(|n| n.contains("条件成立")), "{steps:?}");
    assert_eq!(steps[1]["kind"], "action");
    assert!(steps[1]["note"].as_str().is_some_and(|n| n.contains("isolate-agent")), "{steps:?}");
    assert_eq!(steps[2]["kind"], "notify");
    assert!(steps[2]["note"].as_str().is_some_and(|n| n.contains("in-app")), "{steps:?}");
    assert_eq!(body["executed_actions"], json!(["隔离 Agent"]));
    assert!(body["report"].as_str().is_some_and(|r| r.contains("剧本 test-contain v1")), "{body}");
    assert!(body["run_id"].is_string());

    // 读路径闭环：/cases/{id}/soar-runs 里能读到刚执行的轨迹
    let runs = h.get(&format!("/api/v1/cases/{case_id}/soar-runs")).await;
    assert_eq!(runs.status, StatusCode::OK, "{}", runs.text);
    let runs = runs.json();
    assert_eq!(runs.as_array().map(Vec::len), Some(1), "{runs}");
    assert_eq!(runs[0]["playbook"], "test-contain");
    assert_eq!(runs[0]["status"], "succeeded");
    assert_eq!(runs[0]["steps"].as_array().map(Vec::len), Some(3));

    // 审批门：含审批步骤的剧本默认被拒（未在请求中声明 approve），绝不自动放行
    let denied = h.post(&uri, json!({"yaml": TEST_PLAYBOOK_APPROVAL_YAML})).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.text);
    let denied = denied.json();
    assert_eq!(denied["outcome"], "not-started", "{denied}");
    assert!(denied["reason"].as_str().is_some_and(|r| r.contains("审批")), "{denied}");
    // 明确批准后才执行
    let approved = h.post(&uri, json!({"yaml": TEST_PLAYBOOK_APPROVAL_YAML, "approve": true})).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text);
    assert_eq!(approved.json()["outcome"], "completed", "{}", approved.text);

    // dry_run：动作与通知都不触达执行器
    let dry = h.post(&uri, json!({"yaml": TEST_PLAYBOOK_YAML, "dry_run": true})).await;
    assert_eq!(dry.status, StatusCode::OK, "{}", dry.text);
    let dry = dry.json();
    assert_eq!(dry["dry_run"], true);
    assert!(dry["steps"][1]["note"].as_str().is_some_and(|n| n.contains("dry-run")), "{dry}");

    // 边界：缺剧本 / YAML 非法 / id 非法 / 案件不存在 → 400、400、400、404
    let no_book = h.post(&uri, json!({})).await;
    assert_eq!(no_book.status, StatusCode::BAD_REQUEST, "{}", no_book.text);
    let bad_yaml = h.post(&uri, json!({"yaml": "key: broken\nsteps: []"})).await;
    assert_eq!(bad_yaml.status, StatusCode::BAD_REQUEST, "{}", bad_yaml.text);
    let bad_id = h.post("/api/v1/cases/not-a-uuid/playbook", json!({"yaml": TEST_PLAYBOOK_YAML})).await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST, "{}", bad_id.text);
    let missing = h
        .post(&format!("/api/v1/cases/{}/playbook", agf_core::ids::Id::new()), json!({"yaml": TEST_PLAYBOOK_YAML}))
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND, "{}", missing.text);
    // 边界：多剧本 + key 选择
    let multi =
        format!("playbooks:\n{}", TEST_PLAYBOOK_YAML.lines().map(|l| format!("  {l}")).collect::<Vec<_>>().join("\n"));
    let picked = h.post(&uri, json!({"yaml": multi, "key": "nope"})).await;
    assert_eq!(picked.status, StatusCode::BAD_REQUEST, "key 不存在必须 400: {}", picked.text);
}

#[tokio::test]
async fn notify_send_dispatches_then_deduplicates_per_channel() {
    let h = setup().await;
    assert_unauthorized(&h, "POST", "/api/v1/notifications/send", Some(json!({}))).await;
    let alert_id = create_alert_for_soc(&h, "通知派发用例", "high", "notify-1").await;

    // 正例：两个渠道各派发一次（Mock 渠道，回执 mock-N）
    let payload = json!({
        "subject_kind": "alert",
        "subject_id": alert_id,
        "body": "请立即处置",
        "channels": [{"kind": "email", "targets": ["soc@corp.example"]}, {"kind": "in-app"}]
    });
    let resp = h.post("/api/v1/notifications/send", payload.clone()).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert_eq!(body["subject_kind"], "alert");
    assert_eq!(body["subject_id"], alert_id.as_str());
    assert_eq!(body["channel_count"], 2);
    assert_eq!(body["delivered_count"], 2, "{body}");
    assert_eq!(body["any_delivered"], true);
    assert_eq!(body["fully_suppressed"], false);
    let deliveries = body["deliveries"].as_array().expect("deliveries 必须是数组");
    assert!(deliveries.iter().all(|d| d["outcome"] == "delivered"), "{deliveries:?}");
    assert!(
        deliveries.iter().all(|d| d["receipt"].as_str().is_some_and(|r| r.contains("mock-"))),
        "渠道为 Mock，回执必须自证: {deliveries:?}"
    );
    assert_eq!(body["audit"].as_array().map(Vec::len), Some(2), "派发器必须留审计: {body}");

    // 同一对象同一渠道第二次：引擎去重（跨请求生效，因为派发器是进程单例）
    let again = h.post("/api/v1/notifications/send", payload).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text);
    let again = again.json();
    assert_eq!(again["delivered_count"], 0, "{again}");
    assert_eq!(again["fully_suppressed"], true);
    assert!(
        again["deliveries"].as_array().is_some_and(|list| list.iter().all(|d| d["suppressed_by"] == "dedup")),
        "{again}"
    );

    // 换关联对象 → 允许再发（去重键含对象 id）
    let other = create_alert_for_soc(&h, "通知派发用例 2", "high", "notify-2").await;
    let other_resp = h
        .post(
            "/api/v1/notifications/send",
            json!({"subject_kind": "alert", "subject_id": other, "channels": [{"kind": "email"}]}),
        )
        .await;
    assert_eq!(other_resp.status, StatusCode::OK, "{}", other_resp.text);
    assert_eq!(other_resp.json()["delivered_count"], 1);

    // 正例：等级不足 ⇒ unroutable（渠道声明 min_severity=critical）
    let blocked = h
        .post(
            "/api/v1/notifications/send",
            json!({
                "subject_kind": "alert",
                "subject_id": other,
                "channels": [{"kind": "sms", "min_severity": "critical"}]
            }),
        )
        .await;
    assert_eq!(blocked.status, StatusCode::OK, "{}", blocked.text);
    assert_eq!(blocked.json()["deliveries"][0]["suppressed_by"], "unroutable", "{}", blocked.text);

    // 正例：custom 通知（不依赖台账对象）
    let custom = h
        .post(
            "/api/v1/notifications/send",
            json!({"subject_kind": "custom", "title": "演练通知", "severity": "low", "channels": [{"kind": "in-app"}]}),
        )
        .await;
    assert_eq!(custom.status, StatusCode::OK, "{}", custom.text);
    assert_eq!(custom.json()["delivered_count"], 1);

    // 边界：缺 subject_id / 对象不存在 / 类型非法 / 渠道非法 / 等级非法 → 400、404、400、400、400
    let no_subject = h.post("/api/v1/notifications/send", json!({"subject_kind": "case"})).await;
    assert_eq!(no_subject.status, StatusCode::BAD_REQUEST, "{}", no_subject.text);
    let missing = h
        .post(
            "/api/v1/notifications/send",
            json!({"subject_kind": "case", "subject_id": agf_core::ids::Id::new(), "channels": [{"kind": "email"}]}),
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND, "{}", missing.text);
    let bad_kind = h.post("/api/v1/notifications/send", json!({"subject_kind": "ghost", "subject_id": alert_id})).await;
    assert_eq!(bad_kind.status, StatusCode::BAD_REQUEST, "{}", bad_kind.text);
    let bad_channel = h
        .post(
            "/api/v1/notifications/send",
            json!({"subject_kind": "alert", "subject_id": alert_id, "channels": [{"kind": "carrier-pigeon"}]}),
        )
        .await;
    assert_eq!(bad_channel.status, StatusCode::BAD_REQUEST, "{}", bad_channel.text);
    let bad_severity = h
        .post(
            "/api/v1/notifications/send",
            json!({"subject_kind": "custom", "title": "x", "severity": "nope", "channels": [{"kind": "email"}]}),
        )
        .await;
    assert_eq!(bad_severity.status, StatusCode::BAD_REQUEST, "{}", bad_severity.text);
    let custom_missing_severity =
        h.post("/api/v1/notifications/send", json!({"subject_kind": "custom", "title": "x"})).await;
    assert_eq!(custom_missing_severity.status, StatusCode::BAD_REQUEST, "{}", custom_missing_severity.text);
}

#[tokio::test]
async fn report_schedules_lists_real_entries_and_creates_new_ones() {
    let h = setup().await;
    assert_unauthorized(&h, "GET", "/api/v1/reports/schedules", None).await;

    let first = h.get("/api/v1/reports/schedules").await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.json()["total"], 0, "不能在真实租户内自动创建演示计划");
    assert_eq!(first.json()["scheduler"], "server");
    // 正例：POST 创建真实条目
    let created = h
        .post(
            "/api/v1/reports/schedules",
            json!({"name": "每小时发现报表", "kind": "findings", "format": "csv", "cron": "0 * * * *", "window_secs": 3600,
                   "recipients": []}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let created = created.json();
    assert_eq!(created["schedule"]["name"], "每小时发现报表");
    assert_eq!(created["schedule"]["kind"], "findings");
    assert_eq!(created["schedule"]["format"], "csv");
    assert_eq!(created["schedule"]["window_secs"], 3600);
    let schedule_id = created["schedule"]["id"].as_str().expect("id 缺失").to_string();
    let listed = h.get("/api/v1/reports/schedules?kind=findings").await.json();
    let ids: Vec<&str> = listed["items"]
        .as_array()
        .map(|items| items.iter().filter_map(|i| i["id"].as_str()).collect())
        .unwrap_or_default();
    assert!(ids.contains(&schedule_id.as_str()), "过滤条件必须生效: {listed}");
    assert_eq!(listed["total"], 1);

    // 边界：缺 name / cron 段数不足 / window_secs<=0 / 类型非法 / 渠道 id 非法 → 400
    let no_name = h.post("/api/v1/reports/schedules", json!({"cron": "0 8 * * *"})).await;
    assert_eq!(no_name.status, StatusCode::BAD_REQUEST, "{}", no_name.text);
    let bad_cron = h.post("/api/v1/reports/schedules", json!({"name": "x", "cron": "0 8 * *"})).await;
    assert_eq!(bad_cron.status, StatusCode::BAD_REQUEST, "{}", bad_cron.text);
    let bad_window =
        h.post("/api/v1/reports/schedules", json!({"name": "x", "cron": "0 8 * * *", "window_secs": 0})).await;
    assert_eq!(bad_window.status, StatusCode::BAD_REQUEST, "{}", bad_window.text);
    let bad_kind = h.post("/api/v1/reports/schedules", json!({"name": "x", "cron": "0 8 * * *", "kind": "nope"})).await;
    assert_eq!(bad_kind.status, StatusCode::BAD_REQUEST, "{}", bad_kind.text);
    let bad_channel = h
        .post("/api/v1/reports/schedules", json!({"name": "x", "cron": "0 8 * * *", "channel_ids": ["not-a-uuid"]}))
        .await;
    assert_eq!(bad_channel.status, StatusCode::BAD_REQUEST, "{}", bad_channel.text);
    // 权限：viewer 有 reports:read（GET 200）但没有 reports:write（POST 403）
    assert_eq!(h.request("GET", "/api/v1/reports/schedules", Some(&h.viewer), None).await.status, StatusCode::OK);
    let viewer_post = h
        .request("POST", "/api/v1/reports/schedules", Some(&h.viewer), Some(json!({"name": "x", "cron": "0 8 * * *"})))
        .await;
    assert_eq!(viewer_post.status, StatusCode::FORBIDDEN, "{}", viewer_post.text);
}

#[tokio::test]
async fn case_create_state_and_timeline() {
    let h = setup().await;
    let created = h
        .post("/api/v1/cases", json!({"title": "影子 MCP 排查", "summary": "发现未登记 MCP", "severity": "high"}))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let case_id = created.json()["case"]["id"].as_str().unwrap().to_string();
    assert!(created.json()["case"]["code"].as_str().unwrap().starts_with("CASE-"));

    let timeline = h.get(&format!("/api/v1/cases/{case_id}/timeline")).await.json();
    assert_eq!(timeline["events"].as_array().map(Vec::len), Some(1), "创建事件应入时间线");

    let appended =
        h.post(&format!("/api/v1/cases/{case_id}/timeline"), json!({"note": "已联系负责人", "kind": "comment"})).await;
    assert_eq!(appended.status, StatusCode::OK, "{}", appended.text);

    let moved = h.post(&format!("/api/v1/cases/{case_id}/state"), json!({"state": "investigating"})).await;
    assert_eq!(moved.status, StatusCode::OK, "{}", moved.text);
    assert_eq!(moved.json()["case"]["state"], "investigating");

    let illegal = h.post(&format!("/api/v1/cases/{case_id}/state"), json!({"state": "closed"})).await;
    assert_eq!(illegal.status, StatusCode::CONFLICT, "{}", illegal.text);
}
