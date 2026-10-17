//! 采集器上行端点（`POST /api/v1/ingest/agent`）集成测试：认证、幂等、非法载荷、
//! 事件真的进 Sink、资产台账归并、OpenAPI 收录。
//!
//! 全部通过 `tower::ServiceExt::oneshot` 驱动路由器：**不监听端口、不联网、不需要 PostgreSQL**。
//! mTLS 证书身份（头部解析 / 主体映射 / 门禁）在 `tests/ingest_agent_mtls.rs`；
//! 完整的"证书 → 200"真机链路见 `tools/simulators/run_agent_mtls_e2e.ps1`。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
// 端点的接入流水线是**进程级单例**（按租户一份），本文件刻意用一个静态 `Mutex` 把用例串行化：
// 否则并发用例会互相看到对方的 Sink 计数。guard 因此必然跨 await 持有——这是设计意图。
#![allow(clippy::await_holding_lock)]

mod common;

use common::*;

/// 端点路径。
const PATH: &str = "/api/v1/ingest/agent";

/// 串行锁：端点的接入流水线是**进程级单例**（按租户一份），并发测试会互相看到对方的计数，
/// 因此所有会读 Sink 计数的用例都必须串行（同 `mod` 内 _还是_ 跨文件都是同一进程）。
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 装配测试夹具（**持锁**）：返回值里的 `_guard` 必须活到用例结束，否则锁会被提前释放。
async fn setup_locked() -> (Harness, std::sync::MutexGuard<'static, ()>) {
    let guard = serial();
    (setup().await, guard)
}

/// 一次原始日志（明文载荷，走 `text` 字段）。
fn log_item(text: &str, protocol: &str) -> Value {
    json!({ "text": text, "origin": "it-agent", "protocol": protocol })
}

/// 一条最简 AgentReport（`agf_core::agent::AgentReport`）。
fn agent_report(collector: &str, host: &str) -> Value {
    json!({
        "collector_id": collector,
        "collected_at": "2026-01-02T03:04:05Z",
        "hostname": host,
        "os": "windows/x86_64",
        "os_user": "alice",
        "agents": [{
            "flavor": "cursor",
            "version": "1.0.0",
            "binary_path": null,
            "config_dir": "~/.cursor",
            "config_hash": null
        }],
        "mcp_configs": [],
        "credential_hits": [],
        "scan_scope": ["/home/alice"],
        "agent_version": "0.1.0"
    })
}

// ---------------------------------------------------------------------------
// ① 认证
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_credentials_is_401_problem_json() {
    let (h, _guard) = setup_locked().await;
    let resp = h.request("POST", PATH, None, Some(json!({"logs": [log_item("hi", "webhook")]}))).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{}", resp.text);
    assert_eq!(resp.content_type(), "application/problem+json; charset=utf-8", "{}", resp.text);
    assert_eq!(resp.code(), "unauthenticated", "{}", resp.text);
    assert!(
        resp.json()["detail"].as_str().is_some_and(|d| d.contains("证书") || d.contains("Bearer")),
        "{}",
        resp.text
    );
}

#[tokio::test]
async fn bearer_without_sources_write_is_403() {
    let (h, _guard) = setup_locked().await;
    // viewer 是只读角色（无 sources:write）→ 必须 403 而不是放行
    let resp = h.request("POST", PATH, Some(&h.viewer), Some(json!({"logs": [log_item("hi", "webhook")]}))).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.text);
}

#[tokio::test]
async fn api_key_without_sources_scope_is_403_and_with_scope_is_200() {
    let (h, _guard) = setup_locked().await;
    // 夹具里的 API Key 只有 assets:* ⇒ 403
    let denied = h
        .request_with(
            "POST",
            PATH,
            &[("x-agf-key", h.api_key.as_str())],
            Some(json!({"logs": [log_item("hi", "webhook")]})),
        )
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{}", denied.text);

    // 换一把带 sources:write 的 Key ⇒ 200
    let issued = h.state.api_keys.issue(agf_auth::api_key::ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("sources:write")],
        ..agf_auth::api_key::ApiKeyIssueRequest::named(h.tenant, "agent-uplink", Timestamp::now())
    });
    h.state.store.api_key_insert(issued.record.clone()).expect("write api key");
    let ok = h
        .request_with(
            "POST",
            PATH,
            &[("x-agf-key", issued.plaintext.as_str())],
            Some(json!({"logs": [log_item("hello from api key", "webhook")]})),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text);
    let body = ok.json();
    assert_eq!(body["auth_mode"], "bearer", "{body}");
    assert!(body["total"].as_u64().unwrap_or(0) >= 1, "{body}");
}

#[tokio::test]
async fn bearer_admin_ingests_and_returns_webhook_shaped_summary() {
    let (h, _guard) = setup_locked().await;
    let resp = h
        .post(
            PATH,
            json!({
                "collector_id": "it-collector-1",
                "hostname": "host-1",
                "raw_logs": [log_item("agent uplink payload", "webhook")],
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    // 响应形状与 webhook **同口径**
    for key in ["accepted", "total", "matched", "unmatched", "parsers", "deduped", "event_ids"] {
        assert!(body.get(key).is_some(), "缺少 webhook 同口径字段 {key}: {body}");
    }
    assert_eq!(body["total"], 1, "{body}");
    assert_eq!(body["accepted"], 1, "载荷必须真的落进 Sink: {body}");
    assert_eq!(body["auth_mode"], "bearer", "{body}");
    assert_eq!(body["tenant"], h.tenant.to_string(), "{body}");
    assert_eq!(body["sink"]["backend"], "memory", "{body}");
    // Sink 是**进程级单例**（按租户一份），别的用例也会往里写；这里只断言"本请求写进去了"
    assert!(body["sink"]["events_total"].as_u64().unwrap_or(0) >= 1, "事件必须真的进 Sink: {body}");
    let event_ids = body["event_ids"].as_array().cloned().unwrap_or_default();
    assert_eq!(event_ids.len(), 1, "一条载荷必须对应一个事件 id: {body}");
    let audit = h.get("/api/v1/audit?q=collector-uplink").await;
    assert_eq!(audit.status, StatusCode::OK, "{}", audit.text);
    let items = audit.json()["items"].as_array().cloned().unwrap_or_default();
    assert!(!items.is_empty(), "审计必须记录采集器上行: {}", audit.text);
}

// ---------------------------------------------------------------------------
// ② 非法载荷
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_payload_is_400() {
    let (h, _guard) = setup_locked().await;
    // ① 空体
    let empty = h.request("POST", PATH, Some(&h.admin), Some(json!({}))).await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST, "{}", empty.text);
    // ② 载荷项既没有 payload_b64 也没有 text
    let no_payload = h.post(PATH, json!({"logs": [{"origin": "x"}]})).await;
    assert_eq!(no_payload.status, StatusCode::BAD_REQUEST, "{}", no_payload.text);
    assert!(no_payload.json()["detail"].as_str().is_some_and(|d| d.contains("payload_b64")), "{}", no_payload.text);
    // ③ base64 非法
    let bad_b64 = h.post(PATH, json!({"logs": [{"payload_b64": "!!!not-base64!!!"}]})).await;
    assert_eq!(bad_b64.status, StatusCode::BAD_REQUEST, "{}", bad_b64.text);
    // ④ report 不是合法 AgentReport
    let bad_report = h.post(PATH, json!({"report": {"nope": 1}})).await;
    assert_eq!(bad_report.status, StatusCode::BAD_REQUEST, "{}", bad_report.text);
    // ⑤ 不是 JSON 的请求体（Content-Type 归一为 400）
    let bad_ct = h
        .request_with(
            "POST",
            PATH,
            &[("authorization", format!("Bearer {}", h.admin).as_str()), ("content-type", "text/plain")],
            None,
        )
        .await;
    assert_eq!(bad_ct.status, StatusCode::BAD_REQUEST, "{}", bad_ct.text);
}

// ---------------------------------------------------------------------------
// ③ 幂等（复用既有 `Idempotency-Key` 中间件）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn idempotency_key_replays_the_first_response() {
    let (h, _guard) = setup_locked().await;
    let key = "it-agent-uplink-idem-1";
    let body = json!({"collector_id": "it-idem", "raw_logs": [log_item("idempotent payload", "webhook")]});

    let first = h
        .request_with(
            "POST",
            PATH,
            &[("authorization", format!("Bearer {}", h.admin).as_str()), ("idempotency-key", key)],
            Some(body.clone()),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let first_body = first.json();
    assert_eq!(first_body["total"], 1, "{first_body}");
    assert_eq!(first.header("idempotency-replayed"), "", "首次不得标记重放");

    let second = h
        .request_with(
            "POST",
            PATH,
            &[("authorization", format!("Bearer {}", h.admin).as_str()), ("idempotency-key", key)],
            Some(body.clone()),
        )
        .await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text);
    assert_eq!(second.header("idempotency-replayed"), "true", "重放必须打标");
    assert_eq!(second.json(), first_body, "重放必须复用首次响应体（含 event_ids）");

    // 幂等重放**没有产生第二个事件**（去重在中间件层：请求根本没进处理器）
    let before = agf_api::routes::ingest::pipeline_event_count(&h.state, h.tenant).await.unwrap();
    let third = h
        .request(
            "POST",
            PATH,
            Some(&h.admin),
            Some(json!({"collector_id": "it-idem", "raw_logs": [log_item("idempotent payload", "webhook")]})),
        )
        .await;
    assert_eq!(third.status, StatusCode::OK, "{}", third.text);
    // 不带幂等键 → 真的走了一次流水线（新增 1 条），说明上一步的"复用首次响应"不是碰巧
    let after = agf_api::routes::ingest::pipeline_event_count(&h.state, h.tenant).await.unwrap();
    assert_eq!(after, before + 1, "无幂等键的请求必须真的再入一次（{before} → {after}）");
}

// ---------------------------------------------------------------------------
// ④ 事件真的进 Sink（可观测面断言）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn events_really_land_in_the_sink_and_are_observable() {
    let (h, _guard) = setup_locked().await;
    let before = agf_api::routes::ingest::pipeline_event_count(&h.state, h.tenant).await.unwrap();
    let resp = h
        .post(
            PATH,
            json!({
                "collector_id": "it-sink",
                "hostname": "sink-host",
                "raw_logs": [
                    log_item("first observable payload", "webhook"),
                    log_item("second observable payload", "webhook"),
                ],
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert_eq!(body["total"], 2, "{body}");
    assert_eq!(body["accepted"], 2, "{body}");
    // 端点自报的 Sink 计数必须与之相符
    assert_eq!(body["sink"]["events_total"], before + 2, "{body}");
    let after = agf_api::routes::ingest::pipeline_event_count(&h.state, h.tenant).await.unwrap();
    assert_eq!(after, before + 2, "端点必须真的把事件写进 Sink（{before} → {after}）");
    assert_eq!(body["sink"]["raw_total"], body["sink"]["events_total"], "原始日志与事件一一对应: {body}");
}

#[tokio::test]
async fn agent_report_flows_into_the_asset_ledger() {
    let (h, _guard) = setup_locked().await;
    let fingerprint_probe = h.get("/api/v1/assets?q=cursor").await;
    let before = fingerprint_probe.json()["total"].as_u64().unwrap_or(0);

    let resp = h
        .post(
            PATH,
            json!({
                "collector_id": "it-assets",
                "hostname": "asset-host",
                "report": agent_report("it-assets", "asset-host"),
            }),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    // report 同时进流水线（1 条载荷）与资产台账（既有发现归并）
    assert_eq!(body["total"], 1, "{body}");
    assert!(body.get("assets_created").is_some(), "必须返回资产侧统计: {body}");
    assert_eq!(body["assets_created"], 1, "Agent 资产必须真的落台账: {body}");

    let after = h.get("/api/v1/assets?q=cursor").await;
    assert!(after.json()["total"].as_u64().unwrap_or(0) > before, "资产台账必须可观测到新 Agent: {}", after.text);
    let agents = h.get("/api/v1/agents?q=asset-host").await;
    assert_eq!(agents.status, StatusCode::OK, "{}", agents.text);
    assert!(agents.json()["total"].as_u64().unwrap_or(0) >= 1, "AI 资产视图必须能看到该 Agent: {}", agents.text);
}

// ---------------------------------------------------------------------------
// ⑤ OpenAPI 收录
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_report_never_partially_ingests_its_logs() {
    let (h, _guard) = setup_locked().await;
    let before = agf_api::routes::ingest::pipeline_event_count(&h.state, h.tenant).await.unwrap();
    let response =
        h.post(PATH, json!({"report":{"invalid":true},"logs":[log_item("must not persist","webhook")]})).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
    let after = agf_api::routes::ingest::pipeline_event_count(&h.state, h.tenant).await.unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
async fn openapi_declares_the_agent_uplink_path() {
    let (h, _guard) = setup_locked().await;
    let doc = h.get("/api/v1/openapi.json").await.json();
    let paths = doc["paths"].as_object().expect("OpenAPI paths 缺失");
    assert!(paths.contains_key(PATH), "OpenAPI 必须声明 {PATH}");
    assert!(paths[PATH].get("post").is_some(), "必须是 POST: {}", paths[PATH]);
    let spec_count = agf_api::routes::platform::endpoint_specs().len();
    // 端点清单的条数由多个模块共同贡献（console / console_ops / ingest 各自导出），因此这里
    // 只断言"本端点确实被计入"，不写死总数——写死会因别的模块加端点而假失败。
    assert!(spec_count >= 121, "端点清单至少应包含既有 120 条 + 本端点，实际 {spec_count}");
    let uplink: Vec<_> =
        agf_api::routes::ingest::endpoint_specs().into_iter().filter(|spec| spec.path == PATH).collect();
    assert_eq!(uplink.len(), 1);
    assert_eq!(uplink[0].path, PATH);
    assert!(uplink[0].implemented, "已实现端点不得标成 501");
}
