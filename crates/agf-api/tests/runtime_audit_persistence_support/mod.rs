//! 两个独立测试入口共享真实认证、公开请求和已提交事实查询。
// 每个入口使用其中不同子集；仅此测试辅助模块允许未使用项。
#![allow(dead_code)]
use crate::common::*;
use agf_core::audit::AuditLog;
use agf_runtime::audit::InterceptionRecord;
use axum::extract::FromRequestParts;
use sha2::{Digest, Sha256};

pub(crate) async fn check(h: &Harness, session: &str) -> Resp {
    h.post(
        "/api/v1/runtime/mcp/check",
        json!({"session_id":session,
        "frame":{"jsonrpc":"2.0","id":1,"method":"tools/list",
            "params":{"marker":"owned-private-MCP-marker"}}}),
    )
    .await
}
pub(crate) async fn actor(h: &Harness) -> agf_api::Principal {
    let request = Request::builder()
        .uri("/api/v1/runtime/mcp/check")
        .header("Authorization", format!("Bearer {}", h.admin))
        .header("X-AGF-Tenant", h.tenant.to_string())
        .body(Body::empty())
        .unwrap();
    let (mut parts, _) = request.into_parts();
    agf_api::Principal::from_request_parts(&mut parts, &h.state).await.unwrap()
}
pub(crate) async fn records(h: &Harness) -> Vec<InterceptionRecord> {
    h.state.configurations.list(h.tenant, "runtime-interception").await.unwrap()
}
pub(crate) async fn facts(h: &Harness) -> Vec<AuditLog> {
    h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.target.kind == "runtime-interception-fact")
        .collect()
}
pub(crate) async fn snapshot(h: &Harness) -> Value {
    let mut values: Vec<Value> = h.state.configurations.list(h.tenant, "runtime-interception").await.unwrap();
    values.sort_by_key(Value::to_string);
    json!({"records":values,"audit":facts(h).await})
}

pub(crate) fn record_hash(record: &InterceptionRecord) -> String {
    // 当前固定记录模型只含标量及字符串数组；按键排序独立验证 JSONB 往返摘要。
    let fields: BTreeMap<String, Value> = serde_json::from_value(serde_json::to_value(record).unwrap()).unwrap();
    hex::encode(Sha256::digest(serde_json::to_vec(&fields).unwrap()))
}
pub(crate) async fn integrity(h: &Harness, record: &InterceptionRecord) -> Resp {
    h.get(&format!("/api/v1/runtime/events/{}/integrity", record.id)).await
}
pub(crate) fn call(session: &str) -> Value {
    json!({"session_id":session,"frame":{"jsonrpc":"2.0","id":19,"method":"tools/call",
        "params":{"name":"owned-query","arguments":{"query":"owned-private-MCP-marker"}}}})
}
pub(crate) fn answer(session: &str, lease: Value) -> Value {
    json!({"session_id":session,"lease_id":lease,"response":true,
        "frame":{"jsonrpc":"2.0","id":19,"result":{"content":[{"type":"text","text":"owned-safe-response"}]}}})
}
