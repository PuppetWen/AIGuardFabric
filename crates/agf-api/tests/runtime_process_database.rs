//! 真实 SQL 原子发布、重启随机标识和原 Key 撤销；不启动宿主进程。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
// 复用同一迁移前 owner/COMMENT/OID/数据目录围栏；跨二进制未用的 checkpoint 辅助仅此模块允许。
#[allow(dead_code)]
#[path = "audit_anchor_database_support/mod.rs"]
mod audit_anchor_database_support;
use agf_core::{
    enums::AssetKind,
    error::{DomainError, DomainResult},
    ids::Id,
    process_hook::{ProcessMode, ProcessRequest, ProcessSource},
};
use audit_anchor_database_support::Owned;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::*;
use std::time::Duration;

fn invalid() -> DomainError {
    DomainError::Internal("独占进程准入 SQL 回归未达到预期边界".into())
}
fn sql(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("runtime_process_owned_test", &error)
}
async fn fixture() -> DomainResult<(Owned, Id, String, Id)> {
    let owned = Owned::open("process-admission-owned").await?;
    let h = &owned.case.h;
    assert_eq!(seed_ai_assets(h).await.status, StatusCode::OK);
    let agent = asset_id_of(h, AssetKind::Agent);
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned-process-sql-key","scopes":["policies:read"],"bound_agent_id":agent}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    let token = response.json()["plaintext"].as_str().ok_or_else(invalid)?.to_owned();
    let key = serde_json::from_value(response.json()["api_key"]["id"].clone())?;
    let warm = h.get("/api/v1/runtime/events").await;
    assert_eq!(warm.status, StatusCode::OK);
    Ok((owned, agent, token, key))
}
fn body(agent: Id) -> ProcessRequest {
    ProcessRequest {
        request_id: Id::new(),
        agent_id: agent,
        mode: ProcessMode::Launch,
        source: ProcessSource::ManagedLauncher,
        executable_b64: STANDARD.encode(b"/owned/process/sql-private-path"),
        arguments: vec!["--token=sql-private-argument".into()],
        executable_sha256: Some("a".repeat(64)),
        pid: None,
        uid: None,
        monotonic_ns: None,
        truncated: false,
        lost: 0,
    }
}
async fn send(h: &Harness, token: &str, request: &ProcessRequest) -> Resp {
    h.request_with(
        "POST",
        "/api/v1/runtime/process/check",
        &[("X-AGF-Key", token)],
        Some(serde_json::to_value(request).unwrap()),
    )
    .await
}
async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut rows = BTreeMap::new();
    for kind in ["runtime-process-admission", "runtime-interception"] {
        let mut values: Vec<Value> = h.state.configurations.list(h.tenant, kind).await?;
        values.sort_by_key(Value::to_string);
        rows.insert(kind, values);
    }
    let audits = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?;
    Ok(json!({"rows":rows,"audits":audits}))
}
fn assert_private(value: &Value, request: &ProcessRequest, token: &str) {
    let text = value.to_string();
    for secret in ["/owned/process/sql-private-path", "sql-private-argument", request.executable_b64.as_str(), token] {
        assert!(!text.contains(secret));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn process_receipt_interception_and_management_audit_survive_fresh_state_and_nonce_never_authorizes_twice()
-> DomainResult<()> {
    let (owned, agent, token, _) = fixture().await?;
    let h = &owned.case.h;
    let request = body(agent);
    let before = h.state.store.audit_stats_durable(h.tenant).await?;
    let committed = send(h, &token, &request).await;
    assert_eq!(committed.status, StatusCode::OK, "{}", committed.text);
    assert_eq!(committed.json()["audit_committed"], true);
    assert_eq!(committed.json()["launch_allowed"], true);
    assert_eq!(committed.json()["enforced"], false);
    assert_eq!(committed.json()["request_sha256"], request.digest()?);
    let saved = snapshot(h).await?;
    assert_eq!(saved["rows"]["runtime-process-admission"].as_array().unwrap().len(), 1);
    assert_eq!(saved["rows"]["runtime-interception"].as_array().unwrap().len(), 1);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?.0, before.0 + 1);
    let process_audit = saved["audits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["target"]["kind"] == "process-admission")
        .ok_or_else(invalid)?;
    assert_eq!(process_audit["target"]["id"], request.request_id.to_string());
    assert_private(&saved, &request, &token);
    let fresh = owned.fresh().await?;
    assert_eq!(snapshot(&fresh).await?, saved);
    assert_eq!(send(&fresh, &token, &request).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&fresh).await?, saved);
    assert!(fresh.state.store.audit_verify_durable(fresh.tenant).await?.passed);
    owned.verify().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn process_audit_failure_rolls_back_receipt_interception_and_nonce_then_same_request_can_commit()
-> DomainResult<()> {
    let (owned, agent, token, _) = fixture().await?;
    let h = &owned.case.h;
    let request = body(agent);
    let before = snapshot(h).await?;
    let fault = owned.case.block_audit().await;
    let rejected = send(h, &token, &request).await;
    // 先解除本例精确约束，再检查断言；失败时仍由 runner 负责精确独占库清理。
    owned.case.unblock_audit(&fault).await;
    assert!(rejected.status.is_server_error(), "{}", rejected.text);
    assert_eq!(snapshot(h).await?, before);
    let fresh = owned.fresh().await?;
    assert_eq!(snapshot(&fresh).await?, before);
    let retry = send(&fresh, &token, &request).await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.text);
    assert_eq!(retry.json()["audit_committed"], true);
    let saved = snapshot(&fresh).await?;
    assert_eq!(saved["rows"]["runtime-process-admission"].as_array().unwrap().len(), 1);
    assert_eq!(saved["rows"]["runtime-interception"].as_array().unwrap().len(), 1);
    assert_private(&saved, &request, &token);
    owned.verify().await
}

struct Pending(tokio::task::JoinHandle<Resp>);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.abort();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn process_original_key_revoked_during_exact_audit_lock_wait_cannot_publish_or_admit_launch() -> DomainResult<()>
{
    let (owned, agent, token, key) = fixture().await?;
    let h = &owned.case.h;
    let request = body(agent);
    let before = snapshot(h).await?;
    owned.verify().await?;
    let mut holder = owned.case.pool.begin().await.map_err(sql)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{}:audit-chain", h.tenant))
        .execute(&mut *holder)
        .await
        .map_err(sql)?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *holder).await.map_err(sql)?;
    let request_h = (*h).clone();
    let pending_token = token.clone();
    let pending_request = request.clone();
    let mut pending = Pending(tokio::spawn(async move { send(&request_h, &pending_token, &pending_request).await }));
    tokio::time::timeout(Duration::from_millis(1500),async{
        loop{
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%pg_advisory_xact_lock%')")
                .bind(pid).fetch_one(&owned.case.pool).await.map_err(sql)?;
            if waiting{return Ok::<_,DomainError>(());}
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_|invalid())??;
    // 维持原三秒产品预算；撤销必须在解除精确审计锁之前提交，不伪造 Principal。
    let changed = sqlx::query("UPDATE api_keys SET revoked=true WHERE tenant_id=$1 AND id=$2 AND NOT revoked")
        .bind(h.tenant.as_uuid())
        .bind(key.as_uuid())
        .execute(&mut *holder)
        .await
        .map_err(sql)?;
    assert_eq!(changed.rows_affected(), 1);
    holder.commit().await.map_err(sql)?;
    let response = tokio::time::timeout(Duration::from_secs(3), &mut pending.0)
        .await
        .map_err(|_| invalid())?
        .map_err(|_| invalid())?;
    assert_eq!(response.status, StatusCode::FORBIDDEN, "{}", response.text);
    assert_eq!(snapshot(h).await?, before);
    let fresh = owned.fresh().await?;
    assert_eq!(snapshot(&fresh).await?, before);
    assert_eq!(send(&fresh, &token, &request).await.status, StatusCode::UNAUTHORIZED);
    owned.verify().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn independent_process_instances_commit_one_original_nonce_and_one_management_audit() -> DomainResult<()> {
    let (owned, agent, token, _) = fixture().await?;
    let h = &owned.case.h;
    let fresh = owned.fresh().await?;
    let request = body(agent);
    let before = h.state.store.audit_stats_durable(h.tenant).await?;
    let (a, b) = tokio::join!(send(h, &token, &request), send(&fresh, &token, &request));
    let statuses = [a.status, b.status];
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let saved = snapshot(h).await?;
    assert_eq!(saved["rows"]["runtime-process-admission"].as_array().unwrap().len(), 1);
    assert_eq!(saved["rows"]["runtime-interception"].as_array().unwrap().len(), 1);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?.0, before.0 + 1);
    assert_eq!(snapshot(&owned.fresh().await?).await?, saved);
    assert_private(&saved, &request, &token);
    owned.verify().await
}
