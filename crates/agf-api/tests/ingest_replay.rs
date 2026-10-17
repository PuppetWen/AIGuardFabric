//! 日志回放：未解析原始日志经内置 / 自研模板回放后的事件与差异。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

#[tokio::test]
async fn ingest_replay_parses_unparsed_raws_and_reports_diffs() {
    let h = setup_console().await;
    let tenant = h.tenant;

    // 边界：缺 source_id / limit 非正 / limit 非数字 → 400
    let missing = h.get("/api/v1/ingest/replay").await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST, "{}", missing.text);
    assert!(missing.json()["detail"].as_str().is_some_and(|d| d.contains("source_id")), "{}", missing.text);
    let bad_limit = h.get("/api/v1/ingest/replay?sourceId=x&limit=0").await;
    assert_eq!(bad_limit.status, StatusCode::BAD_REQUEST, "{}", bad_limit.text);
    let nan_limit = h.get("/api/v1/ingest/replay?sourceId=x&limit=abc").await;
    assert_eq!(nan_limit.status, StatusCode::BAD_REQUEST, "{}", nan_limit.text);
    // 边界：源不存在（没有任何未解析原始日志）→ 200 + 0 条（不伪造）
    let unknown = h.get("/api/v1/ingest/replay?sourceId=nope").await;
    assert_eq!(unknown.status, StatusCode::OK, "{}", unknown.text);
    let unknown = unknown.json();
    assert_eq!(unknown["preview_only"], true);
    assert_eq!(unknown["replayed"], 0);
    assert_eq!(unknown["newly_parsed"], 0);
    assert_eq!(unknown["matched_by"], "none", "{unknown}");
    assert!(unknown["notes"].as_array().is_some_and(|notes| !notes.is_empty()), "{unknown}");

    // 正例：两条未解析原始日志 + 一条既有事件（用于差分）
    let payload = r#"{"zzz_client":"203.0.113.42","zzz_level":"high","zzz_detail":"异常登录","zzz_action":"block"}"#;
    let source_id = agf_core::ids::Id::new();
    let protocol = agf_core::enums::IngestProtocol::Webhook;
    let existing = {
        let mut event = agf_core::event::Event::new(tenant, source_id, protocol);
        event.message = payload.to_string();
        event.raw_hash = agf_core::secret::content_hash(payload);
        h.state.ingest_sink.put_event(&event).await.expect("写既有事件失败");
        event
    };
    let first = replay_raw_log(tenant, "it-src-webhook", source_id, protocol, payload, Some(existing.id));
    let second = replay_raw_log(
        tenant,
        "it-src-webhook",
        source_id,
        protocol,
        r#"{"zzz_client":"203.0.113.43","zzz_level":"low","zzz_detail":"正常读取","zzz_action":"allow"}"#,
        None,
    );
    h.state.ingest_sink.put_raw(&first).await.expect("写原始日志失败");
    h.state.ingest_sink.put_raw(&second).await.expect("写原始日志失败");
    // 注册自研模板（回放注册表是可变的，与 /parsers 读路径独立）
    {
        let mut registry = h.state.replay_parsers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.register(replay_custom_template(), 5_000).expect("注册模板失败");
    }

    let preview = h.get("/api/v1/ingest/replay?sourceId=it-src-webhook").await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text);
    let preview = preview.json();
    assert_eq!(preview["preview_only"], true);
    assert_eq!(preview["replayed"], 0);
    assert_eq!(preview["unparsed_total_for_source"], 2);
    assert_eq!(preview["raw_logs"].as_array().map(Vec::len), Some(2));
    assert_eq!(preview["raw_logs"][0]["payload"], payload);
    assert_eq!(h.state.ingest_sink.event_count(tenant).await.ok(), Some(1), "GET 不能生成事件");
    assert_eq!(h.state.ingest_sink.unparsed_raw(tenant, 100).await.unwrap().len(), 2, "GET 不能标记原文");
    assert!(
        h.state.store.audit_chain(tenant, 0, 100).unwrap().iter().all(|entry| entry.actor.name != "ingest-replay"),
        "GET 不能记执行审计"
    );

    let resp = h.post("/api/v1/ingest/replay", json!({"sourceId":"it-src-webhook"})).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert!(body["preview_only"].is_null());
    assert_eq!(body["source_id"], "it-src-webhook");
    assert_eq!(body["matched_by"], "origin");
    assert_eq!(body["replayed"], 2, "{body}");
    assert_eq!(body["newly_parsed"], 2, "{body}");
    assert_eq!(body["failed"], 0, "{body}");
    assert_eq!(body["is_noop"], false);
    assert_eq!(body["unparsed_total_for_source"], 2);
    assert_eq!(body["parser_used"]["it-replay-webhook"], 2, "{body}");
    let raws = body["raw_logs"].as_array().expect("raw_logs 必须是数组");
    assert_eq!(raws.len(), 2);
    assert_eq!(raws[0]["payload"], payload, "必须返回回放出的原文: {raws:?}");
    assert_eq!(raws[0]["origin"], "it-src-webhook");
    assert!(raws[0]["bytes"].as_u64().unwrap_or(0) > 0);
    let diffs = body["diffs"].as_array().expect("diffs 必须是数组");
    assert_eq!(diffs.len(), 1, "已有事件的原始日志必须产出差分: {body}");
    let paths: Vec<&str> = diffs[0]["changes"]
        .as_array()
        .map(|changes| changes.iter().filter_map(|c| c["path"].as_str()).collect())
        .unwrap_or_default();
    assert!(paths.contains(&"event.severity"), "等级应从 info 变为 high: {paths:?}");
    assert_eq!(diffs[0]["previous_event"], existing.id.to_string().as_str());
    assert!(diffs[0]["new_event"].is_string());
    assert!(body["elapsed_micros"].as_u64().is_some(), "引擎必须给出耗时: {body}");

    // 回放后：原始日志被标记已解析、事件表 +2
    let left = h.state.ingest_sink.unparsed_raw(tenant, 100).await.expect("读取失败");
    assert!(left.is_empty(), "回放成功后原始日志必须标记为已解析: {left:?}");
    assert_eq!(h.state.ingest_sink.event_count(tenant).await.ok(), Some(3), "既有 1 + 回放 2");

    // 已回放过的原始日志不会再被重复执行。
    let posted = h.post("/api/v1/ingest/replay", json!({"sourceId": "it-src-webhook"})).await;
    assert_eq!(posted.status, StatusCode::OK, "{}", posted.text);
    assert_eq!(posted.json()["replayed"], 0, "已解析过的原始日志不会被反复回放: {}", posted.text);

    // 权限：viewer 无 sources:write → 403
    let viewer = h.request("GET", "/api/v1/ingest/replay?sourceId=it-src-webhook", Some(&h.viewer), None).await;
    assert_eq!(viewer.status, StatusCode::FORBIDDEN, "{}", viewer.text);
}

#[tokio::test]
async fn ingest_replay_demo_payloads_match_builtin_templates() {
    let h = setup().await;
    // 与 state.rs 的 DEMO_RAW_LOGS 同形（Wazuh alerts.json）：AGF_SEED_FIXTURES=1 灌入的就是它，
    // 必须能被**内置**模板解析，否则实跑时 /ingest/replay 只会返回 newly_parsed=0。
    let payload = r#"{"timestamp":"2026-03-02T10:00:00.000Z","rule":{"level":10,"description":"sshd: authentication failed","id":"5710"},"agent":{"name":"web-01","ip":"10.0.0.21"},"data":{"srcip":"203.0.113.9","srcuser":"root","protocol":"ssh"},"location":"/var/log/auth.log","full_log":"Failed password for root from 203.0.113.9 port 51234 ssh2"}"#;
    let raw = replay_raw_log(
        h.tenant,
        "demo-src-wazuh-json",
        agf_core::ids::Id::new(),
        agf_core::enums::IngestProtocol::Webhook,
        payload,
        None,
    );
    h.state.ingest_sink.put_raw(&raw).await.expect("写演示原始日志失败");
    let resp = h.post("/api/v1/ingest/replay", json!({"sourceId":"demo-src-wazuh-json"})).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert_eq!(body["replayed"], 1, "{body}");
    assert_eq!(body["newly_parsed"], 1, "演示原始日志必须能被内置模板解析: {body}");
    assert_eq!(body["failed"], 0, "{body}");
    assert_eq!(body["parser_used"]["wazuh-alert-json"], 1, "{body}");
}
