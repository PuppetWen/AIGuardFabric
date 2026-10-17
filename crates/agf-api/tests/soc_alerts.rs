//! SOC 告警闭环：聚合聚类、SLA 三档刷新、升级阶梯与通知派发，以及告警状态流转。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

// ===========================================================================
// 8. SOC 闭环端点（真实引擎；曾经的 501 已接线）
// ===========================================================================
//
// 覆盖口径：每条端点 = **未认证 401** + **正例（200 + 关键字段/形状）** + **边界（400/404）**。
// 数据都是通过 HTTP 写进台账的真实数据；断言只认可复现的计算结果（簇数/条数/到期时间/轨迹/派发结论）。

#[tokio::test]
async fn alerts_aggregate_clusters_ledger_alerts_and_rejects_bad_config() {
    let h = setup().await;
    assert_unauthorized(&h, "POST", "/api/v1/alerts/aggregate", Some(json!({}))).await;

    // 边界：台账没有告警 → 200 + 空簇（不伪造簇）
    let empty = h.post("/api/v1/alerts/aggregate", json!({})).await;
    assert_eq!(empty.status, StatusCode::OK, "{}", empty.text);
    assert_eq!(empty.json()["source_alerts"], 0);
    assert_eq!(empty.json()["clusters"].as_array().map(Vec::len), Some(0));
    assert_eq!(empty.json()["raw_alerts"], 0);

    // 正例：相似标题同窗合并、无关标题独立成簇
    let _ = create_alert_for_soc(&h, "检测到提示词注入尝试 A", "high", "agg-a").await;
    let _ = create_alert_for_soc(&h, "检测到提示词注入尝试 B", "high", "agg-b").await;
    let _ = create_alert_for_soc(&h, "磁盘只读告警", "medium", "agg-c").await;
    let resp = h.post("/api/v1/alerts/aggregate", json!({})).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert_eq!(body["source_alerts"], 3, "{body}");
    assert_eq!(body["raw_alerts"], 3, "原始告警条数来自台账: {body}");
    assert_eq!(body["clusters"].as_array().map(Vec::len), Some(2), "相似标题应合并: {body}");
    assert_eq!(body["deduped_alerts"], 2);
    assert!(
        body["noise_reduction_ratio"].as_f64().is_some_and(|ratio| ratio > 0.0 && ratio < 1.0),
        "降噪率必须是引擎算出的真实比例: {body}"
    );
    assert_eq!(body["config"]["window_secs"], 300);
    assert_eq!(body["config"]["similarity"], "jaccard");
    assert_eq!(body["max_severity"], "high");
    let first = &body["clusters"][0];
    assert_eq!(first["occurrences"], 2, "相似标题的两条告警都应计入该簇: {first}");
    assert_eq!(first["dedup_count"], 2, "标题不同 ⇒ 两个去重键: {first}");
    assert!(first["dedup_keys"][0].as_str().is_some_and(|key| key.contains("检测到提示词注入尝试")), "{first}");

    // 正例：抑制规则真实生效（父"已隔离"压制子"外传"，同实体）
    let _ = create_alert_for_soc(&h, "主机已隔离完成", "high", "agg-parent").await;
    let _ = create_alert_for_soc(&h, "检测到数据外传尝试", "medium", "agg-child").await;
    let suppressed = h
        .post(
            "/api/v1/alerts/aggregate",
            json!({
                "suppression_rules": [{
                    "key": "SUP-ISOLATED",
                    "reason": "主机已隔离，后续外传尝试降噪",
                    "parent_title_contains": ["已隔离"],
                    "child_title_contains": ["外传"]
                }]
            }),
        )
        .await;
    assert_eq!(suppressed.status, StatusCode::OK, "{}", suppressed.text);
    let suppressed = suppressed.json();
    assert_eq!(suppressed["suppression_rule_count"], 1);
    assert_eq!(suppressed["suppressed_clusters"], 1, "子告警应被抑制: {suppressed}");
    let child = suppressed["clusters"]
        .as_array()
        .and_then(|clusters| clusters.iter().find(|cluster| cluster["suppressed"] == true))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(child["suppress_rule"], "SUP-ISOLATED", "{suppressed}");
    assert!(child["suppressed_by"].is_string(), "必须记录抑制来源簇: {child}");

    // 边界：非法配置 / 未知策略 / 坏 JSON → 400
    let window = h.post("/api/v1/alerts/aggregate", json!({"window_secs": 0})).await;
    assert_eq!(window.status, StatusCode::BAD_REQUEST, "{}", window.text);
    assert!(window.json()["detail"].as_str().unwrap_or_default().contains("window_secs"), "{}", window.text);
    let similarity = h.post("/api/v1/alerts/aggregate", json!({"similarity": "nope"})).await;
    assert_eq!(similarity.status, StatusCode::BAD_REQUEST, "{}", similarity.text);
    let bad_rule = h.post("/api/v1/alerts/aggregate", json!({"suppression_rules": [{"key": "X", "reason": ""}]})).await;
    assert_eq!(bad_rule.status, StatusCode::BAD_REQUEST, "无理由抑制规则必须被拒: {}", bad_rule.text);
    let malformed = h.request("POST", "/api/v1/alerts/aggregate", Some(&h.admin), Some(json!([1, 2]))).await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST, "{}", malformed.text);
}

#[tokio::test]
async fn alert_sla_refresh_computes_three_tiers_and_writes_back() {
    let h = setup().await;
    assert_unauthorized(&h, "POST", "/api/v1/alerts/sla-refresh", Some(json!({}))).await;
    let alert_id = create_alert_for_soc(&h, "SLA 刷新用例", "high", "sla-refresh-1").await;

    let resp = h.post("/api/v1/alerts/sla-refresh", json!({})).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert_eq!(body["checked"], 1, "{body}");
    assert_eq!(body["updated"], 1, "结论要写回台账: {body}");
    assert_eq!(body["written_back"], true);
    assert_eq!(body["policies"].as_array().map(Vec::len), Some(5), "五个等级各一条策略: {body}");
    let row = &body["alerts"][0];
    assert_eq!(row["alert_id"], alert_id.as_str());
    assert_eq!(row["severity"], "high");
    // 刚建的告警：首次响应目标 3600s、有效耗时≈0 → pending，且三档判定齐全
    let targets = row["targets"].as_array().expect("targets 必须是数组");
    assert_eq!(targets.len(), 3);
    let names: Vec<&str> = targets.iter().filter_map(|t| t["target"].as_str()).collect();
    assert_eq!(names, vec!["first-response", "containment", "resolution"], "{row}");
    assert_eq!(targets[0]["target_secs"], 3600, "high 的首次响应目标来自 SlaPolicy::for_severity: {targets:?}");
    assert_eq!(targets[0]["status"], "pending");
    assert_eq!(row["overall"], "pending");
    assert_eq!(row["breached"], false);
    assert!(row["due_at"].as_str().is_some_and(|t| t.ends_with('Z')), "{row}");
    assert!(row["next_escalation"]["target"].is_string(), "未逾期也要给出下一档: {row}");
    // 写回前是 agf-core 单值口径、写回后是引擎三档口径的最近截止
    assert!(row["stored_before"]["sla_due_at"].is_string(), "{row}");
    assert_eq!(row["stored_after"]["sla_due_at"], row["due_at"], "{row}");
    // 落库校验：直接读内存台账
    let stored = h
        .state
        .store
        .alert_get(h.tenant, agf_core::ids::Id::parse(&alert_id).expect("id"))
        .expect("读取失败")
        .expect("告警应存在");
    assert!(!stored.sla_breached);
    assert!(stored.sla_due_at.is_some(), "SLA 截止必须写回台账");
    assert_eq!(stored.escalation_level, 0);

    // 边界：body 类型不符 → 400；active_only=false 也可用
    let bad = h.post("/api/v1/alerts/sla-refresh", json!({"active_only": "yes"})).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.text);
    let all = h.post("/api/v1/alerts/sla-refresh", json!({"active_only": false})).await;
    assert_eq!(all.status, StatusCode::OK, "{}", all.text);
    assert_eq!(all.json()["active_only"], false);
}

#[tokio::test]
async fn alert_escalate_judges_ladder_and_dispatches_notification() {
    let h = setup().await;
    let alert_id = create_alert_for_soc(&h, "升级链路用例", "critical", "escalate-1").await;
    let uri = format!("/api/v1/alerts/{alert_id}/escalate");
    assert_unauthorized(&h, "POST", &uri, Some(json!({}))).await;
    // 案件引用该告警（`case_create` 会双向写入 `Alert.case_id`）→ 升级必须落到案件时间线
    let case = h
        .post("/api/v1/cases", json!({"title": "升级链路案件", "severity": "critical", "alert_ids": [alert_id]}))
        .await;
    assert_eq!(case.status, StatusCode::CREATED, "{}", case.text);
    let case_id = case.json()["case"]["id"].as_str().expect("case id 缺失").to_string();
    let linked = h
        .state
        .store
        .alert_get(h.tenant, agf_core::ids::Id::parse(&alert_id).expect("id"))
        .expect("读取失败")
        .expect("告警应存在");
    assert_eq!(
        linked.case_id.map(|id| id.to_string()),
        Some(case_id.clone()),
        "案件引用告警后，告警的 case_id 必须回指该案件"
    );

    // 边界：id 非法 → 400；告警不存在 → 404
    let bad_id = h.request("POST", "/api/v1/alerts/not-a-uuid/escalate", Some(&h.admin), Some(json!({}))).await;
    assert_eq!(bad_id.status, StatusCode::BAD_REQUEST, "{}", bad_id.text);
    let missing = h
        .request(
            "POST",
            &format!("/api/v1/alerts/{}/escalate", agf_core::ids::Id::new()),
            Some(&h.admin),
            Some(json!({})),
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND, "{}", missing.text);

    // 未逾期：如实回答"没到升级档位"，绝不假装已升级
    let fresh = h.post(&uri, json!({})).await;
    assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.text);
    let fresh = fresh.json();
    assert_eq!(fresh["escalated"], false, "{fresh}");
    assert!(fresh["reason"].as_str().is_some_and(|r| r.contains("未逾期")), "{fresh}");
    assert!(fresh["next_escalation"]["target"].is_string(), "{fresh}");
    assert_eq!(fresh["targets"].as_array().map(Vec::len), Some(3));

    // 正例：以"首见 + 2 小时"为判定时刻（演练/补偿判定）→ critical 逾 L2（L1@900s、L2@3600s）
    let judged_at = agf_core::time::Timestamp::now().offset_secs(7_200).to_rfc3339();
    let escalated = h.post(&uri, json!({"judged_at": judged_at.clone(), "channel_kind": "in-app"})).await;
    assert_eq!(escalated.status, StatusCode::OK, "{}", escalated.text);
    let escalated = escalated.json();
    assert_eq!(escalated["escalated"], true, "{escalated}");
    assert_eq!(escalated["level"], 2, "critical 逾 7200s 应到 L2: {escalated}");
    assert_eq!(escalated["target"], "incident-commander");
    assert!(escalated["overdue_secs"].as_i64().is_some_and(|secs| secs >= 3_600), "{escalated}");
    // 通知真的过了一遍派发器（Mock 渠道，回执形如「已受理：mock-N」）
    assert_eq!(escalated["notification"]["outcome"], "delivered", "{escalated}");
    assert_eq!(escalated["notification"]["kind"], "in-app");
    assert!(
        escalated["notification"]["receipt"].as_str().is_some_and(|r| r.contains("mock-")),
        "必须说明是 Mock 渠道: {escalated}"
    );
    // 真实落库：状态流转 + 升级层级 + 指派升级目标
    assert_eq!(escalated["alert"]["state"], "escalated");
    assert_eq!(escalated["alert"]["escalation_level"], 2);
    assert!(escalated["alert"]["assignee"].is_null(), "role labels are not real user assignments");
    let stored = h
        .state
        .store
        .alert_get(h.tenant, agf_core::ids::Id::parse(&alert_id).expect("id"))
        .expect("读取失败")
        .expect("告警应存在");
    assert_eq!(stored.state.as_str(), "escalated");
    assert_eq!(stored.escalation_level, 2);
    assert!(stored.sla_breached, "逾期必须置位");
    // 升级必须落到关联案件的时间线（双向关系已由 `case_create` 建立）
    let event = &escalated["case_event"];
    assert_eq!(event["case_id"], case_id.as_str(), "{escalated}");
    assert_eq!(event["kind"], "escalated", "{escalated}");
    assert!(event["note"].as_str().is_some_and(|note| note.contains("incident-commander")), "{escalated}");
    let timeline = h.get(&format!("/api/v1/cases/{case_id}/timeline")).await.json();
    assert!(
        timeline["events"].as_array().is_some_and(|events| events.iter().any(|item| item["kind"] == "escalated")),
        "案件时间线里应能读到升级事件: {timeline}"
    );
    // 同一告警第二次升级：同一去重键 → 引擎判 dedup（既定语义，不是失败）
    let again = h.post(&uri, json!({"judged_at": judged_at})).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text);
    assert_eq!(again.json()["notification"]["suppressed_by"], "dedup", "{}", again.text);

    // 边界：判定时刻早于告警首见时间 → 400
    let too_early = h.post(&uri, json!({"judged_at": "2000-01-01T00:00:00Z"})).await;
    assert_eq!(too_early.status, StatusCode::BAD_REQUEST, "{}", too_early.text);
    // 边界：未知渠道 → 400
    let bad_channel = h.post(&uri, json!({"channel_kind": "carrier-pigeon"})).await;
    assert_eq!(bad_channel.status, StatusCode::BAD_REQUEST, "{}", bad_channel.text);
}

#[tokio::test]
async fn alert_create_list_and_state_flow() {
    let h = setup().await;
    let created = h
        .post(
            "/api/v1/alerts",
            json!({"title": "MCP 影子资产外联", "severity": "high", "domain": "tool-abuse", "dedup_key": "alert-1"}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    assert_eq!(created.json()["created"], true);
    let alert_id = created.json()["alert_id"].as_str().unwrap().to_string();
    assert!(created.json()["alert"]["sla_due_at"].is_string());

    let merged = h
        .post("/api/v1/alerts", json!({"title": "MCP 影子资产外联", "severity": "critical", "dedup_key": "alert-1"}))
        .await;
    assert_eq!(merged.json()["created"], false, "同 dedup_key 应合并");
    assert_eq!(merged.json()["alert"]["dedup_count"], 2);

    let listed = h.get("/api/v1/alerts?active=true").await.json();
    assert_eq!(listed["total"], 1);
    let detail = h.get(&format!("/api/v1/alerts/{alert_id}")).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert_eq!(detail.json()["active"], true);

    let moved =
        h.post(&format!("/api/v1/alerts/{alert_id}/state"), json!({"state": "acknowledged", "assignee": "soc"})).await;
    assert_eq!(moved.status, StatusCode::OK, "{}", moved.text);
    assert_eq!(moved.json()["alert"]["state"], "acknowledged");
    assert_eq!(moved.json()["alert"]["assignee"], "soc");
}

#[tokio::test]
async fn alert_invalid_state_is_400() {
    let h = setup().await;
    let created = h.post("/api/v1/alerts", json!({"title": "x"})).await.json();
    let id = created["alert_id"].as_str().unwrap().to_string();
    let resp = h.post(&format!("/api/v1/alerts/{id}/state"), json!({"state": "bogus"})).await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
}
