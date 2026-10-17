//! Opt-in Node SDK → real loopback API → SQL acceptance; no production endpoints or provider writes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod agentteams_sdk_database_support;
mod common;
mod configuration_audit_support;

use agentteams_sdk_database_support::{EVENTS, Fixture, Scratch, Server, issue_key, sql_router};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
use futures::FutureExt;
use std::{collections::BTreeMap, panic::AssertUnwindSafe};

fn input(f: &Fixture, server: &Server, action: &str, key: &str) -> Value {
    json!({"action":action,"platform_url":server.origin,"source_id":f.source,
        "binding_id":f.binding.binding_id,"scope_id":f.binding.scope_id,
        "expected_mocked":true,"collector_key":key})
}

fn assert_private_omitted(text: &str, key: &str) {
    for forbidden in [key, "owned-sdk-user@example.invalid", "13800138000"] {
        assert!(!text.contains(forbidden), "Credentials and original business PII must not enter SDK evidence");
    }
}

async fn assert_sql(f: &Fixture) {
    let rows = f.ledger().await;
    assert_eq!(rows.len(), 7, "Retry must not duplicate SQL audit identities");
    let mut kinds = BTreeMap::new();
    for row in &rows {
        *kinds.entry(row["kind"].as_str().unwrap()).or_insert(0) += 1;
        assert_eq!(row["tenant_id"], json!(f.h.tenant));
        assert_eq!(row["scope_id"], json!(f.binding.scope_id));
        assert_eq!(row["source_id"], json!(f.source));
        assert_eq!(row["binding_id"], json!(f.binding.binding_id));
        assert_eq!(row["mocked"], true, "The fixture is observed Mock evidence only");
        assert_eq!(row["message_preview"], "", "Default SDK capture omits content");
        assert_private_omitted(&row.to_string(), &f.key.plaintext);
    }
    assert_eq!(kinds, BTreeMap::from([("call", 1), ("heartbeat", 1), ("message", 1), ("task", 4)]));
    let root = rows
        .iter()
        .find(|row| row["kind"] == "task" && row["task_id"] == "sdk-root-task" && row["parent_span_id"].is_null())
        .unwrap();
    let call = rows.iter().find(|row| row["kind"] == "call").unwrap();
    let child = rows
        .iter()
        .find(|row| row["kind"] == "task" && row["from_worker"] == "sdk-receiver" && row["task_id"] == "sdk-root-task")
        .unwrap();
    let message = rows.iter().find(|row| row["kind"] == "message").unwrap();
    for row in [call, child, message] {
        assert_eq!(row["trace_id"], root["trace_id"]);
    }
    assert_eq!(call["parent_span_id"], root["span_id"]);
    assert_eq!(child["parent_span_id"], call["span_id"], "Explicit injected carrier must preserve the caller span");
    assert_eq!(message["parent_span_id"], root["span_id"]);
    assert_eq!(call["from_worker"], "worker-demo");
    assert_eq!(call["to_worker"], "sdk-receiver");
    assert_eq!(call["from_asset"], json!(f.binding.members["worker-demo"].asset_id));
    assert_eq!(call["to_asset"], json!(f.binding.members["sdk-receiver"].asset_id));
    assert!(rows.iter().any(|row| row["task_id"] == "sdk-error-task" && row["status"] == "error"));
    assert!(rows.iter().any(|row| row["task_id"] == "sdk-timeout-task" && row["status"] == "unknown"));
    let heartbeat = rows.iter().find(|row| row["kind"] == "heartbeat").unwrap();
    assert!(heartbeat["from_worker"].is_null() && heartbeat["task_id"].is_null());
    assert_eq!(heartbeat["status"], "unknown");
    let (raw, events, outbox) = f.evidence().await;
    assert_eq!((raw.len(), events.len(), outbox), (7, 7, 7));
    for payload in raw {
        let decoded = STANDARD.decode(payload).unwrap();
        let text = std::str::from_utf8(&decoded).unwrap();
        assert_private_omitted(text, &f.key.plaintext);
        let event: Value = serde_json::from_str(text).unwrap();
        assert!(event["message"].is_null());
        assert!(event.get("authorized").is_none() && event.get("tenant").is_none());
    }
    for event in events {
        assert_private_omitted(&event.to_string(), &f.key.plaintext);
        assert_eq!(event["extra"]["scope_id"], json!(f.binding.scope_id));
        assert_eq!(event["ai"]["mocked"], true);
    }
}

async fn assert_fresh_instance(f: &Fixture) {
    let second = sql_router(f.case.second_instance().await, f.case.pool.clone());
    let mut server = Server::start(second.app.clone()).await;
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("{}{EVENTS}", server.origin))
        .bearer_auth(&second.admin)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Fresh process-local state must read durable SDK audit");
    let body: Value = response.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 7);
    for row in items {
        assert_eq!(row["authorizationStatus"], "unknown");
        assert!(row["authorized"].is_null());
        assert_eq!(row["mocked"], true);
        assert_eq!(row["sourceId"], json!(f.source));
        assert!(row.get("raw").is_none() && row.get("headers").is_none());
        assert_private_omitted(&row.to_string(), &f.key.plaintext);
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned AGF_TEST_DATABASE_URL/AGF_SDK_DATABASE_OWNER, fixed AGF_SDK_TEST_DIR and AGF_SDK_NODE"]
async fn node_sdk_roundtrip_is_durable_deduplicated_private_and_revocation_safe() {
    let scratch = Scratch::new();
    let f = Fixture::open().await;
    let mut server = Server::start(f.h.app.clone()).await;
    let outcome = AssertUnwindSafe(async {
        let report = scratch.node(input(&f, &server, "business", &f.key.plaintext)).await;
        assert_eq!(report["events"], 7);
        assert_eq!(report["durable"], true);
        assert_eq!(report["deduped"], 7);
        for flag in ["business_once", "return_identity", "exception_identity", "private_omitted"] {
            assert_eq!(report[flag], true, "Business and privacy invariant: {flag}");
        }
        assert_sql(&f).await;
        assert_fresh_instance(&f).await;
        f.revoke().await;
        let rejected = scratch.node(input(&f, &server, "revoked", &f.key.plaintext)).await;
        assert_eq!(rejected["paused"], "http_401");
        assert_eq!((rejected["pending"].as_u64(), rejected["quarantined"].as_u64()), (Some(2), Some(0)));
        assert_eq!(rejected["retained_after_reopen"], true);
        assert_eq!(rejected["business_once"], true);
        assert_sql(&f).await;
        let replacement = issue_key(&f.h).await;
        f.disable_binding().await;
        let stale = scratch.node(input(&f, &server, "disabled", &replacement.plaintext)).await;
        assert_eq!(stale["paused"], "http_409");
        assert_eq!((stale["pending"].as_u64(), stale["quarantined"].as_u64()), (Some(0), Some(2)));
        assert_eq!(stale["retained_after_reopen"], true);
        assert_eq!(stale["business_once"], true);
        assert_eq!(stale["private_omitted"], true);
        assert_sql(&f).await;
    })
    .catch_unwind()
    .await;
    // Owned child processes have finished; clean only their verified case path, even on assertions.
    server.stop().await;
    scratch.clean_node().await;
    f.case.pool.close().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
