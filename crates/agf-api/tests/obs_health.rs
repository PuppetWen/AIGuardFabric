//! 状态与可观测：healthz / readyz / metrics / openapi 契约。
//! 只读探针语义：就绪降级说明、指标序列、规范与真实端点的一致性。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

// ===========================================================================
// 1. 状态与可观测
// ===========================================================================

#[tokio::test]
async fn healthz_is_liveness_only() {
    let h = setup().await;
    let resp = h.request("GET", "/healthz", None, None).await;
    assert_eq!(resp.status, StatusCode::OK);
    let body = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["mode"], "offline");
    assert!(body["uptime_secs"].is_number());
}

#[tokio::test]
async fn readyz_offline_returns_ready_and_degraded() {
    let h = setup().await;
    let resp = h.request("GET", "/readyz", None, None).await;
    assert_eq!(resp.status, StatusCode::OK);
    let body = resp.json();
    assert_eq!(body["status"], "ready");
    assert_eq!(body["degraded"], true);
    assert_eq!(body["checks"]["database"]["status"], "offline");
    assert!(body["notes"].as_array().is_some_and(|n| !n.is_empty()));
}

#[tokio::test]
async fn readyz_reports_redteam_cases_and_parser_templates() {
    let h = setup().await;
    let body = h.request("GET", "/readyz", None, None).await.json();

    // 解析器：内置模板恒在，外部目录存在时必须真的被加载（PV-025 的回归断言）
    let parsers = &body["checks"]["parsers"];
    let builtin = parsers["builtin"].as_u64().unwrap_or(0);
    let loaded = parsers["loaded"].as_u64().unwrap_or(0);
    let total = parsers["total"].as_u64().unwrap_or(0);
    assert!(builtin >= 18, "内置解析模板不应少于 18 个: {parsers}");
    assert!(total >= builtin, "模板总数不得少于内置模板数: {parsers}");
    let parsers_dir = agf_api::state::resolve_dir("AGF_PARSERS_DIR", ".", &["parsers"]);
    if parsers_dir.is_dir() {
        assert!(loaded > 0, "解析模板目录 {} 存在却一个模板都没加载: {parsers}", parsers_dir.display());
        assert!(total > builtin, "外部模板必须真的并入注册表（不是只统计）: {parsers}");
        assert_eq!(parsers["status"], "ok", "{parsers}");
    }

    // 红队用例库：目录存在时必须加载（缺失时只降级、不得 500）
    let redteam = &body["checks"]["redteam"];
    let redteam_dir = agf_api::state::resolve_dir("AGF_REDTEAM_DIR", ".", &["redteam"]);
    if redteam_dir.is_dir() {
        assert!(
            redteam["cases"].as_u64().unwrap_or(0) > 0,
            "红队用例目录 {} 存在却一个用例都没加载: {redteam}",
            redteam_dir.display()
        );
        assert_eq!(redteam["status"], "ok", "{redteam}");
    }
    // 未加载时必须是明确的降级说明，而不是静默为 0
    if redteam["cases"].as_u64().unwrap_or(0) == 0 {
        assert_eq!(redteam["status"], "degraded");
        assert!(redteam["note"].as_str().is_some_and(|n| !n.is_empty()));
    }
}

/// `/readyz` 的写后持久化段是**实时**计数；阿里云 TLS 放松提示按需出现（默认无噪音）。
#[tokio::test]
async fn readyz_reports_live_persistence_and_no_tls_noise_by_default() {
    let h = setup().await;
    let body = h.request("GET", "/readyz", None, None).await.json();

    // 写后持久化：离线模式无桥，如实标注 memory-only（不是启动期快照里的旧字面量）
    let persistence = &body["checks"]["persistence"];
    assert_eq!(persistence["status"], "offline", "{persistence}");
    assert_eq!(persistence["mode"], "memory-only", "{persistence}");
    assert!(persistence["note"].as_str().is_some_and(|n| !n.is_empty()), "{persistence}");
    assert!(persistence.get("dropped").is_none(), "离线模式没有写队列计数: {persistence}");

    // 默认（trust anchor = verify-chain）不得出现 TLS 放松 note
    let notes = body["notes"].as_array().cloned().unwrap_or_default();
    let text = notes.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n");
    assert!(!text.contains("已放松 TLS 校验"), "默认不得产生阿里云 TLS 放松噪音: {text}");
}

#[tokio::test]
async fn metrics_exposes_requests_latency_and_interceptions() {
    let h = setup().await;
    let _ = h.get("/api/v1/assets").await;
    let resp = h.request("GET", "/metrics", None, None).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.content_type().starts_with("text/plain"));
    for needle in [
        "agf_http_requests_total",
        "agf_http_request_duration_seconds_bucket",
        "agf_interceptions_total",
        "agf_rate_limited_total",
        "agf_ready",
    ] {
        assert!(resp.text.contains(needle), "缺少指标 {needle}");
    }
}

#[tokio::test]
async fn dedicated_metrics_router_serves_scrapes_without_console_routes() {
    let h = setup().await;
    let _ = h.get("/api/v1/assets").await;
    let app = agf_api::build_metrics_router(h.state);
    let response = app.clone().oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("agf_http_requests_total"));

    let response = app.oneshot(Request::builder().uri("/api/v1/assets").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn openapi_spec_is_valid_and_lists_endpoints() {
    let h = setup().await;
    let resp = h.request("GET", "/api/v1/openapi.json", None, None).await;
    assert_eq!(resp.status, StatusCode::OK);
    let doc = resp.json();
    assert!(doc["openapi"].as_str().unwrap_or_default().starts_with("3."));
    assert_eq!(doc["info"]["title"], "AIGuardFabric API");
    let paths = doc["paths"].as_object().expect("paths 缺失");
    assert!(paths.contains_key("/api/v1/assets"));
    assert!(paths.contains_key("/api/v1/auth/login"));
    // 本轮接线后，原先声明 501 的 SOC/报表端点必须声明 200（规范与真实行为一致）
    for (path, method) in [
        ("/api/v1/alerts/aggregate", "post"),
        ("/api/v1/alerts/sla-refresh", "post"),
        ("/api/v1/alerts/{id}/escalate", "post"),
        ("/api/v1/cases/{id}/sla", "get"),
        ("/api/v1/cases/{id}/playbook", "post"),
        ("/api/v1/notifications/send", "post"),
        ("/api/v1/reports/schedules", "get"),
        ("/api/v1/soar/automations", "get"),
        ("/api/v1/soar/automations", "post"),
        ("/api/v1/notifications/history", "get"),
        ("/api/v1/settings/notifications", "get"),
        ("/api/v1/settings/notifications/{kind}", "put"),
        ("/api/v1/alicloud/connections", "get"),
        ("/api/v1/alicloud/connections/{name}", "put"),
        ("/api/v1/alicloud/agentteams/sync", "post"),
        ("/api/v1/settings/tenant", "put"),
        ("/api/v1/settings/quotas", "put"),
        ("/api/v1/chat/completions", "post"),
    ] {
        assert!(
            paths[path][method]["responses"]["200"].is_object(),
            "{method} {path} 必须声明 200（已接线）: {:?}",
            paths.get(path)
        );
    }
    // 仍未实现的端点才允许声明 501：本轮接线后应无 501 端点
    let mut still_501: Vec<String> = Vec::new();
    for (path, item) in paths {
        if let Some(object) = item.as_object() {
            for (method, op) in object {
                if op["responses"]["501"].is_object() {
                    still_501.push(format!("{method} {path}"));
                }
            }
        }
    }
    assert!(still_501.is_empty(), "unexpected 501 endpoints remain: {still_501:?}");
}
