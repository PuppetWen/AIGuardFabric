//! 独占数据库上的真实路由、原子失败、跨实例并发及读取证明；不访问真实 MCP 上游。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod runtime_audit_authority_database_support;
mod runtime_audit_persistence_support;
// 同一独占围栏供多个测试二进制复用；只对未使用的 fixture 辅助限定允许 dead_code。
#[allow(dead_code)]
#[path = "audit_anchor_database_support/mod.rs"]
mod audit_anchor_database_support;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use audit_anchor_database_support::Owned;
use common::*;
use runtime_audit_authority_database_support::*;
use runtime_audit_persistence_support::*;

async fn replace(owned: &Owned, id: Id, value: &Value) -> DomainResult<()> {
    owned.verify().await?;
    let changed = sqlx::query(
        "UPDATE console_configurations SET payload=$1 WHERE tenant_id=$2 AND kind='runtime-interception' AND id=$3",
    )
    .bind(value)
    .bind(owned.case.h.tenant.as_uuid())
    .bind(id.as_uuid())
    .execute(&owned.case.pool)
    .await
    .map_err(|error| agf_storage::map_sqlx_err("owned_runtime_fact_tamper", &error))?;
    assert_eq!(changed.rows_affected(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn runtime_fact_atomic_commit_restart_and_read_integrity_detect_configuration_tamper() -> DomainResult<()> {
    let owned = Owned::open("runtime-fact-read").await?;
    // 既有 SQL 业务库 + 同步内存身份模式仍可使用，不能静默改从 SQL 查另一个身份。
    let hybrid = memory_identity(owned.case.h.clone()).await?;
    assert_eq!(check(&hybrid, "sql-hybrid-memory-identity").await.status, StatusCode::OK);
    let sql_h = sql_identity(owned.case.h.clone()).await?;
    let h = &sql_h;
    let response = check(h, "sql-fact-read").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let mut record = records(h).await.remove(0);
    assert_eq!(facts(h).await.len(), records(h).await.len());
    assert!(!serde_json::to_string(&facts(h).await)?.contains("owned-private-MCP-marker"));
    one_connection(&owned, h).await?;
    let before = snapshot(h).await;
    let fresh = sql_identity(owned.fresh().await?).await?;
    assert_eq!(snapshot(&fresh).await, before);
    let verified = integrity(&fresh, &record).await;
    assert_eq!(verified.status, StatusCode::OK, "{}", verified.text);
    assert_eq!(verified.json()["summary_matches"], true);
    assert_eq!(verified.json()["checkpoint_verified"], false);
    assert_eq!(verified.json()["record_sha256"], record_hash(&record));
    owned.checkpoint().await?;
    assert_eq!(fresh.get("/api/v1/audit/verify").await.json()["anchoring"]["fully_anchored"], true);
    let mut raw: Value = h.state.configurations.get(h.tenant, "runtime-interception", record.id).await?.unwrap();
    record.reason.push_str("owned database rewrite");
    record.seal();
    let mut changed = serde_json::to_value(&record)?;
    changed["_agf_management_audit_v1"] = raw["_agf_management_audit_v1"].clone();
    replace(&owned, record.id, &changed).await?;
    assert_eq!(integrity(&fresh, &record).await.json()["summary_matches"], false);
    // 攻击者重算普通 record hash 和 proof SHA，仍不匹配已提交的管理审计摘要。
    changed["_agf_management_audit_v1"]["record_sha256"] = json!(record_hash(&record));
    replace(&owned, record.id, &changed).await?;
    assert_eq!(integrity(&fresh, &record).await.json()["summary_matches"], false);
    changed.as_object_mut().unwrap().remove("_agf_management_audit_v1");
    replace(&owned, record.id, &changed).await?;
    assert_eq!(integrity(&fresh, &record).await.json()["status"], "missing-proof");
    assert_eq!(
        fresh.get("/api/v1/audit/verify").await.json()["anchoring"]["fully_anchored"],
        true,
        "管理链仍有效，不代表单独被改写的配置事实完整"
    );
    assert!(fresh.get("/api/v1/runtime/events").await.json().is_array());
    raw["unexpected-field"] = json!(true);
    replace(&owned, record.id, &raw).await?;
    assert_eq!(integrity(&fresh, &record).await.json()["summary_matches"], false);
    owned.verify().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn runtime_audit_failure_returns_no_allow_and_closes_only_original_response_usage() -> DomainResult<()> {
    let owned = Owned::open("runtime-fact-fault").await?;
    let sql_h = sql_identity(owned.case.h.clone()).await?;
    let h = &sql_h;
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"owned-fact-concurrency","scope":"tenant",
        "dimension":"concurrency","window":"total","limit":2}),
        )
        .await;
    assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
    let quota_id: Id = serde_json::from_value(quota.json()["quota"]["id"].clone())?;
    assert_eq!(check(h, "sql-warm").await.status, StatusCode::OK);
    let before = snapshot(h).await;
    let fault = owned.case.block_audit().await;
    let denied = h.post("/api/v1/runtime/mcp/check", call("sql-before-lease")).await;
    owned.case.unblock_audit(&fault).await;
    assert!(denied.status.is_server_error(), "{}", denied.text);
    assert_ne!(denied.json()["allowed"], true);
    assert_eq!(snapshot(h).await, before);
    assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await?[&quota_id], 0);
    assert_eq!(h.get("/api/v1/runtime/mcp/usage").await.json()["items"], json!([]));
    let admitted = h.post("/api/v1/runtime/mcp/check", call("sql-after-lease")).await;
    assert_eq!(admitted.status, StatusCode::OK, "{}", admitted.text);
    let lease = admitted.json()["lease_id"].clone();
    assert!(lease.is_string());
    assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await?[&quota_id], 1);
    let other = h.post("/api/v1/runtime/mcp/check", call("sql-unrelated-lease")).await;
    assert_eq!(other.status, StatusCode::OK, "{}", other.text);
    assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await?[&quota_id], 2);
    let saved = snapshot(h).await;
    let fault = owned.case.block_audit().await;
    let failed = h.post("/api/v1/runtime/mcp/check", answer("sql-after-lease", lease)).await;
    owned.case.unblock_audit(&fault).await;
    assert!(failed.status.is_server_error(), "{}", failed.text);
    assert_ne!(failed.json()["allowed"], true);
    let fresh = sql_identity(owned.fresh().await?).await?;
    assert_eq!(snapshot(&fresh).await, saved);
    assert_eq!(agf_api::runtime_quota::usage(&fresh.state, fresh.tenant).await?[&quota_id], 1);
    let usage = fresh.get("/api/v1/runtime/mcp/usage").await.json();
    let row = usage["items"].as_array().unwrap().iter().find(|row| row["name"] == "owned-query").unwrap();
    assert_eq!(row["attempts"], 2);
    assert_eq!(row["failed"], 1);
    assert_eq!(row["succeeded"], 0);
    assert_eq!(row["inflight"], 1, "别的会话租约不得被本次失败关闭");
    let completed =
        fresh.post("/api/v1/runtime/mcp/check", answer("sql-unrelated-lease", other.json()["lease_id"].clone())).await;
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text);
    assert_eq!(agf_api::runtime_quota::usage(&fresh.state, fresh.tenant).await?[&quota_id], 0);
    let retry = fresh.post("/api/v1/runtime/mcp/check", call("sql-after-lease")).await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.text);
    let finish = fresh
        .post(
            "/api/v1/runtime/mcp/check",
            json!({"session_id":"sql-after-lease",
        "lease_id":retry.json()["lease_id"],"finished":true,"frame":{}}),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.text);
    revoked_during_audit_wait(&owned, &fresh).await?;
    owned.verify().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn runtime_fact_concurrent_exact_retry_is_once_and_conflicting_bytes_never_overwrite() -> DomainResult<()> {
    let owned = Owned::open("runtime-fact-race").await?;
    let sql_h = sql_identity(owned.case.h.clone()).await?;
    let h = &sql_h;
    assert_eq!(check(h, "sql-race").await.status, StatusCode::OK);
    let fresh = sql_identity(owned.fresh().await?).await?;
    let first = actor(h).await;
    let second = actor(&fresh).await;
    let mut record = records(h).await.remove(0);
    record.id = Id::new();
    record.seal();
    let count = facts(h).await.len();
    let (a, b) = tokio::join!(
        agf_api::runtime_audit::persist(&h.state, &first, &record),
        agf_api::runtime_audit::persist(&fresh.state, &second, &record)
    );
    a?;
    b?;
    assert_eq!(facts(h).await.len(), count + 1);
    assert_eq!(integrity(&fresh, &record).await.json()["summary_matches"], true);
    let before = snapshot(h).await;
    let mut changed = record.clone();
    changed.reason.push_str("different bytes");
    changed.seal();
    assert!(matches!(
        agf_api::runtime_audit::persist(&fresh.state, &second, &changed).await,
        Err(DomainError::Conflict(_))
    ));
    assert_eq!(snapshot(h).await, before);
    record.id = Id::new();
    record.seal();
    changed = record.clone();
    changed.reason.push_str("racing alternative");
    changed.seal();
    let (a, b) = tokio::join!(
        agf_api::runtime_audit::persist(&h.state, &first, &record),
        agf_api::runtime_audit::persist(&fresh.state, &second, &changed)
    );
    assert!(matches!((&a, &b), (Ok(()), Err(DomainError::Conflict(_))) | (Err(DomainError::Conflict(_)), Ok(()))));
    let winner = if a.is_ok() { &record } else { &changed };
    let saved: agf_runtime::audit::InterceptionRecord =
        h.state.configurations.get(h.tenant, "runtime-interception", record.id).await?.unwrap();
    assert_eq!(serde_json::to_value(saved)?, serde_json::to_value(winner)?);
    assert_eq!(facts(h).await.len(), count + 2);
    let before = snapshot(h).await;
    agf_api::runtime_audit::persist(&fresh.state, &second, winner).await?;
    assert_eq!(snapshot(&fresh).await, before);
    owned.verify().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn runtime_integrity_is_tenant_scoped_and_missing_proof_cannot_be_adopted() -> DomainResult<()> {
    let owned = Owned::open("runtime-fact-tenant").await?;
    let sql_h = sql_identity(owned.case.h.clone()).await?;
    let h = &sql_h;
    assert_eq!(check(h, "sql-tenant").await.status, StatusCode::OK);
    let foreign = sql_identity(owned.case.foreign_instance().await).await?;
    let record = records(h).await.remove(0);
    let before = snapshot(h).await;
    let foreign_before = snapshot(&foreign).await;
    let response = integrity(&foreign, &record).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["summary_matches"], false);
    assert_eq!(response.json()["status"], "missing-record");
    assert!(response.json()["audit_id"].is_null());
    let other = actor(&foreign).await;
    assert!(agf_api::runtime_audit::persist(&foreign.state, &other, &record).await.is_err());
    assert_eq!(snapshot(&foreign).await, foreign_before);
    assert_eq!(snapshot(h).await, before);
    let mut legacy = record.clone();
    legacy.id = Id::new();
    legacy.seal();
    h.state.configurations.put(h.tenant, "runtime-interception", legacy.id, &legacy).await?;
    let before = snapshot(h).await;
    let principal = actor(h).await;
    assert!(matches!(
        agf_api::runtime_audit::persist(&h.state, &principal, &legacy).await,
        Err(DomainError::Conflict(_))
    ));
    assert_eq!(integrity(h, &legacy).await.json()["status"], "missing-proof");
    assert_eq!(snapshot(h).await, before);
    owned.verify().await
}
