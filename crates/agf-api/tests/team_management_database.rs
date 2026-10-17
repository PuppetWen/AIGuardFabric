//! SQL preview/run claims, restart recovery and rollback use a dedicated owned database.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod team_management_helpers;
mod team_management_sql_helpers;
use agf_core::ids::Id;
use common::*;
use team_management_helpers::*;
use team_management_sql_helpers::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn two_processes_cannot_overwrite_global_request_indexes_from_different_team_records() {
    let sql = fixture().await;
    let other = instance(sql.db.clone(), sql.f.h.tenant, &sql.key).await;
    let request = Id::new();
    let mut a = preview_body(create("sql-preview-a", json!([])), 0, false);
    a["request_id"] = json!(request);
    let mut b = a.clone();
    b["change"]["team_name"] = json!("sql-preview-b");
    let uri = format!("{BASE}/previews");
    let (left, right) = tokio::join!(sql.f.h.post(&uri, a), other.h.post(&uri, b));
    assert_eq!(
        [left.status, right.status].iter().filter(|status| status.is_success()).count(),
        1,
        "{} / {}",
        left.text,
        right.text
    );
    assert_eq!([left.status, right.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    assert_eq!(sql.f.h.state.configurations.list::<Value>(sql.f.h.tenant, PREVIEW_KIND).await.unwrap().len(), 1);
    let a = result(sql.f.preview(create("sql-operation-a", json!([]))).await);
    let b = result(other.preview(create("sql-operation-b", json!([]))).await);
    let request = Id::new();
    let (left, right) = tokio::join!(sql.f.apply(&a, request), other.apply(&b, request));
    assert_eq!(
        [left.status, right.status].iter().filter(|status| status.is_success()).count(),
        1,
        "{} / {}",
        left.text,
        right.text
    );
    assert_eq!([left.status, right.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let saved = if left.status.is_success() { left.json() } else { right.json() };
    verified(&saved);
    let indexed = sql.f.h.state.configurations.list::<Value>(sql.f.h.tenant, RUN_KIND).await.unwrap();
    assert_eq!(indexed.len(), 1);
    assert_eq!(indexed[0]["id"], saved["id"]);
    let restarted = instance(sql.db.clone(), sql.f.h.tenant, &sql.key).await;
    let read = result(restarted.h.get(&format!("{BASE}?request_id={request}")).await);
    assert_eq!(read["operations"].as_array().unwrap().len(), 1);
    assert_eq!(read["operations"][0]["id"], saved["id"]);
    assert_eq!(restarted.writes("CreateTeam").await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn independent_instances_claim_one_preview_and_restart_restores_the_original_receipt() {
    let sql = fixture().await;
    let f = &sql.f;
    let second = instance(sql.db.clone(), f.h.tenant, &sql.key).await;
    let preview = result(f.preview(update(TEAM, "Persisted across API restart")).await);
    let left = Id::new();
    let right = Id::new();
    let (a, b) = tokio::join!(f.apply(&preview, left), second.apply(&preview, right));
    assert_eq!([a.status, b.status].iter().filter(|status| status.is_success()).count(), 1, "{} / {}", a.text, b.text);
    assert_eq!([a.status, b.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let (winner, request) = if a.status.is_success() { (a.json(), left) } else { (b.json(), right) };
    verified(&winner);
    let restarted = instance(sql.db.clone(), f.h.tenant, &sql.key).await;
    assert_eq!(restarted.cloud_team(TEAM).await["Description"], "Persisted across API restart");
    let read = result(restarted.h.get(&format!("{BASE}/operations/{}", winner["id"].as_str().unwrap())).await);
    assert_eq!(read, winner);
    assert_eq!(result(restarted.apply(&preview, request).await), winner);
    assert_eq!(
        restarted.writes("UpdateTeam").await,
        1,
        "Mock writes and idempotency receipts must survive a new instance"
    );
    let observed = result(restarted.recover(&winner, "observe").await);
    assert_eq!(observed["readback"]["status"], "matched");
    assert_eq!(restarted.writes("UpdateTeam").await, 1);
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn run_index_and_audit_faults_roll_back_the_entire_preview_claim_before_any_cloud_write() {
    let sql = fixture().await;
    let preview = result(sql.f.preview(update(TEAM, "Claim must be atomic")).await);
    let before = record(&sql.f).await;
    let chain = audits(&sql).await;
    for (table, predicate) in [
        ("console_configurations", format!("tenant_id='{}'::uuid AND kind='{RUN_KIND}'", sql.f.h.tenant)),
        ("audit_logs", format!("tenant_id='{}'::uuid AND target->>'kind'='{STATE_KIND}'", sql.f.h.tenant)),
    ] {
        let request = Id::new();
        fault(&sql, table, predicate, async {
            let rejected = sql.f.apply(&preview, request).await;
            assert!(!rejected.status.is_success(), "{}", rejected.text);
            assert_eq!(record(&sql.f).await, before, "preview, active lease and run must remain one atomic record");
            assert!(sql.f.h.state.configurations.list::<Value>(sql.f.h.tenant, RUN_KIND).await.unwrap().is_empty());
            assert_eq!(audits(&sql).await, chain, "no success audit may escape the failed claim");
            assert_eq!(sql.f.writes("UpdateTeam").await, 0);
        })
        .await;
    }
    verified(&result(sql.f.apply(&preview, Id::new()).await));
    assert_eq!(sql.f.writes("UpdateTeam").await, 1, "a rolled-back claim leaves the original preview usable");
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn inventory_publication_failure_retains_snapshot_and_retry_publishes_without_resending_update() {
    let sql = fixture().await;
    let preview = result(sql.f.preview(update(TEAM, "Write accepted; publication recoverable")).await);
    let before = snapshot(&sql.f.h).await;
    let predicate = format!("tenant_id='{}'::uuid AND kind='cloud-inventory'", sql.f.h.tenant);
    let operation = Arc::new(tokio::sync::Mutex::new(Value::Null));
    let captured = operation.clone();
    fault(&sql, "console_configurations", predicate, async {
        let applied = result(sql.f.apply(&preview, Id::new()).await);
        assert_eq!(applied["cloudWrite"]["status"], "accepted");
        assert_eq!(applied["readback"]["status"], "matched");
        assert_eq!(applied["inventoryPublish"]["status"], "failed");
        assert_eq!(applied["status"], "uncertain");
        assert_eq!(snapshot(&sql.f.h).await, before);
        assert_eq!(sql.f.writes("UpdateTeam").await, 1);
        *captured.lock().await = applied;
    })
    .await;
    let restarted = instance(sql.db.clone(), sql.f.h.tenant, &sql.key).await;
    let recovered = result(restarted.recover(&operation.lock().await.clone(), "publish").await);
    verified(&recovered);
    assert_eq!(restarted.cloud_team(TEAM).await["Description"], "Write accepted; publication recoverable");
    assert_eq!(restarted.writes("UpdateTeam").await, 1);
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn expired_started_delete_survives_restart_and_new_requests_cannot_replay_it() {
    let sql = fixture().await;
    let preview = result(sql.f.preview(delete(TEAM)).await);
    let operation = result(sql.f.apply(&preview, Id::new()).await);
    assert_eq!(operation["status"], "deleting");
    let operation_id = operation["id"].as_str().unwrap();
    let mut record = record(&sql.f).await;
    let record_id = Id::parse(record["id"].as_str().unwrap()).unwrap();
    let expired = Timestamp::now().offset_secs(-1);
    record["operations"][operation_id]["status"] = json!("started");
    record["operations"][operation_id]["lease_expires_at"] = json!(expired);
    record["active"] = json!({"run":operation_id,"claim":operation["requestId"],
        "authorized_at":operation["startedAt"],"expires_at":expired});
    sql.f.h.state.configurations.put(sql.f.h.tenant, STATE_KIND, record_id, &record).await.unwrap();
    let restarted = instance(sql.db.clone(), sql.f.h.tenant, &sql.key).await;
    let recovered = result(restarted.h.get(&format!("{BASE}/operations/{operation_id}")).await);
    assert_eq!(recovered["status"], "uncertain");
    assert_eq!(recovered["busy"], false);
    assert!(recovered["allowedActions"].as_array().unwrap().contains(&json!("observe")));
    for change in [create(TEAM, json!([])), update(TEAM, "A new ID cannot revive a delete"), delete(TEAM)] {
        assert_eq!(restarted.preview(change).await.status, StatusCode::PRECONDITION_FAILED);
    }
    assert_eq!(restarted.apply(&preview, Id::new()).await.status, StatusCode::CONFLICT);
    let absent = result(restarted.recover(&recovered, "observe").await);
    assert_eq!(absent["readback"]["resourceState"], "absent");
    let published = result(restarted.recover(&absent, "publish").await);
    assert_eq!(published["status"], "verified");
    assert_eq!(restarted.writes("DeleteTeam").await, 1);
    let fresh = instance(sql.db.clone(), sql.f.h.tenant, &sql.key).await;
    let list = fresh.list().await;
    assert!(
        !list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|team| team["teamName"] == TEAM && team["currentAvailable"] == true),
        "a new Mock instance must not resurrect deleted fixed fixtures"
    );
}
