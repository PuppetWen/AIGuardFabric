//! Real PostgreSQL snapshots/cursors. All SQL rows live in owned isolated test tenants.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod agentteams_trace_support;
mod common;
mod configuration_audit_support;
use agentteams_trace_support::*;
use agf_core::ids::Id;
use common::*;
use std::collections::BTreeSet;

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn full_sql_total_bounded_records_and_cursor_pages_share_one_observed_snapshot() {
    let f = Fixture::open("trace-bounded").await;
    let records: Vec<_> = (0..2001).map(|index| f.record(index)).collect();
    f.seed(&records).await;
    let snapshot = f.h.state.ingest_sink.agentteams_trace_snapshot(&f.query(2000)).await.unwrap();
    assert_eq!(snapshot.total, 2001);
    assert_eq!(snapshot.records.len(), 2000);
    assert!(snapshot.records.windows(2).all(|pair| pair[0].id > pair[1].id));
    let first = f.page(None, 200).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let first = first.json();
    assert_eq!(first["totalEvents"], 2001);
    assert_eq!(first["nodeLimit"], 2000);
    assert_eq!(first["truncated"], true);
    assert_eq!(first["complete"], false);
    assert_eq!(first["coverage"], "observed_only");
    assert_eq!(first["consistency"], "statement");
    assert_eq!(first["timePrecision"], "microsecond");
    assert_eq!(first["graph"]["nodes"].as_array().unwrap().len(), 2000);
    assert_eq!(first["graph"]["status"], "unknown");
    let mut ids = BTreeSet::new();
    let mut page = first.clone();
    loop {
        assert_eq!(page["totalEvents"], 2001);
        assert_eq!(page["asOfReceivedAt"], first["asOfReceivedAt"]);
        assert_eq!(page["windowFrom"], first["windowFrom"]);
        assert_eq!(page["windowTo"], first["windowTo"]);
        for item in page["items"].as_array().unwrap() {
            assert!(ids.insert(item["id"].as_str().unwrap().to_owned()), "page overlap");
        }
        let Some(next) = page["nextCursor"].as_str() else { break };
        assert!(next.len() <= 4096);
        assert!(!next.contains(TRACE));
        let next = f.page(Some(next), 200).await;
        assert_eq!(next.status, StatusCode::OK, "{}", next.text);
        page = next.json();
    }
    assert_eq!(ids.len(), 2000);
    let expected: BTreeSet<_> = snapshot.records.iter().map(|record| record.id.to_string()).collect();
    assert_eq!(ids, expected);
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn concurrent_atomic_commits_cannot_mix_sql_count_and_bounded_record_versions() {
    let f = Fixture::open("trace-mvcc").await;
    f.seed(&(0..2001).map(|index| f.record(index)).collect::<Vec<_>>()).await;
    let mut marker = f.record(3000);
    marker.event_time = f.clock;
    let store = f.h.state.ingest_sink.database().unwrap();
    let writer_store = store.clone();
    let writer_marker = marker.clone();
    let writer = tokio::spawn(async move {
        for index in 0..100 {
            let mut tx = writer_store.db().begin_tenant(writer_marker.tenant_id).await.unwrap();
            sqlx::query("DELETE FROM agentteams_audit WHERE tenant_id=$1 AND id=$2")
                .bind(writer_marker.tenant_id.as_uuid())
                .bind(writer_marker.id.as_uuid())
                .execute(&mut *tx)
                .await
                .unwrap();
            if index % 2 == 0 {
                insert(&mut tx, std::slice::from_ref(&writer_marker)).await;
            }
            tx.commit().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    });
    for _ in 0..100 {
        let snapshot = f.h.state.ingest_sink.agentteams_trace_snapshot(&f.query(7)).await.unwrap();
        assert_eq!(snapshot.records.len(), 7);
        let contains_marker = snapshot.records[0].id == marker.id;
        assert_eq!(
            snapshot.total,
            if contains_marker { 2002 } else { 2001 },
            "count and the newest record must belong to one statement snapshot"
        );
    }
    writer.await.unwrap();
    let snapshot = f.h.state.ingest_sink.agentteams_trace_snapshot(&f.query(7)).await.unwrap();
    assert_eq!(snapshot.total, 2001);
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn sql_filters_tenant_current_scope_trace_occurrence_window_and_receive_watermark() {
    let f = Fixture::open("trace-filters").await;
    let foreign = sql_router(f.case.foreign_instance().await, f.case.pool.clone());
    let mut records: Vec<_> = (0..8).map(|index| f.record(index)).collect();
    let watermark = f.clock.offset_secs(-1);
    records[0].received_at = watermark;
    records[0].event_time = f.from; // Inclusive occurrence lower bound.
    records[1].received_at = watermark; // Inclusive receive watermark.
    records[2].event_time = f.from.offset_secs(-1);
    records[3].event_time = f.until; // Exclusive occurrence upper bound.
    records[4].received_at = f.clock;
    records[5].scope_id = Id::new();
    records[6].trace_id = Some("foreign-trace".into());
    records[7].binding_id = Id::new(); // Same-scope historical binding is retained.
    records[7].received_at = watermark;
    f.seed(&records).await;
    let mut foreign_record = f.record(100);
    foreign_record.tenant_id = foreign.tenant;
    let store = foreign.state.ingest_sink.database().unwrap();
    let mut tx = store.db().begin_tenant(foreign.tenant).await.unwrap();
    insert(&mut tx, &[foreign_record]).await;
    tx.commit().await.unwrap();
    let mut query = f.query(2000);
    query.received_until = watermark;
    let snapshot = f.h.state.ingest_sink.agentteams_trace_snapshot(&query).await.unwrap();
    assert_eq!(snapshot.total, 3);
    assert_eq!(
        snapshot.records.iter().map(|record| record.id).collect::<BTreeSet<_>>(),
        [records[0].id, records[1].id, records[7].id].into_iter().collect()
    );
    let page = f.page(None, 200).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert_eq!(page.json()["totalEvents"], 4); // Later receive-time is visible on a fresh HTTP query.
    for limit in [0, 2001] {
        assert!(f.h.state.ingest_sink.agentteams_trace_snapshot(&f.query(limit)).await.is_err());
    }
    query.until = query.from.offset_secs(30 * 86_400 + 1);
    assert!(f.h.state.ingest_sink.agentteams_trace_snapshot(&query).await.is_err());
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn genuine_http_ingest_cursor_survives_equivalent_refresh_and_a_second_api_instance() {
    let f = Fixture::open("trace-refresh").await;
    f.ingest(2).await;
    let first = f.page(None, 1).await;
    let next = cursor(&first);
    let before = agf_api::cloud_inventory::load(&f.h.state, f.h.tenant).await.unwrap().unwrap();
    let refreshed =
        f.h.post(SYNC, json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false})).await;
    assert_eq!(refreshed.status, StatusCode::OK, "{}", refreshed.text);
    assert_eq!(refreshed.json()["bindingsRefreshed"], 1);
    let after = agf_api::cloud_inventory::load(&f.h.state, f.h.tenant).await.unwrap().unwrap();
    assert_ne!(after.checked_at, before.checked_at);
    let second = sql_router(f.case.second_instance().await, f.case.pool.clone());
    let page = second.get(&f.uri(TRACE, Some(&next), 1)).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert_eq!(page.json()["totalEvents"], 2);
    assert_eq!(page.json()["asOfReceivedAt"], first.json()["asOfReceivedAt"]);
    assert_ne!(page.json()["items"][0]["id"], first.json()["items"][0]["id"]);
    assert!(page.json()["nextCursor"].is_null());
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn opaque_cursors_reject_tampering_foreign_tenant_trace_window_and_changed_cloud_scope() {
    let f = Fixture::open("trace-cursor").await;
    f.ingest(2).await;
    let first = f.page(None, 1).await;
    let next = cursor(&first);
    let bad = f.page(Some(&format!("{next}!")), 1).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.text);
    let expired = f.page(Some(&expired_cursor(&f, &next)), 1).await;
    assert_eq!(expired.status, StatusCode::BAD_REQUEST, "{}", expired.text);
    let other_trace = f.h.get(&f.uri("other-trace", Some(&next), 1)).await;
    assert_eq!(other_trace.status, StatusCode::BAD_REQUEST, "{}", other_trace.text);
    let foreign = sql_router(f.case.foreign_instance().await, f.case.pool.clone());
    configure(&foreign).await;
    let cross_tenant = foreign.get(&f.uri(TRACE, Some(&next), 1)).await;
    assert_eq!(cross_tenant.status, StatusCode::BAD_REQUEST, "{}", cross_tenant.text);
    let changed_from = trace_uri(TRACE, Some(&next), 1, f.from.offset_secs(-1), f.until);
    let changed = f.h.get(&changed_from).await;
    assert_eq!(changed.status, StatusCode::BAD_REQUEST, "{}", changed.text);
    let changed =
        f.h.request(
            "PUT",
            CLOUD,
            Some(&f.h.admin),
            Some(json!({"expected_version":1,"enabled":true,
        "mock":true,"settings":{"instance_id":format!("new-scope-{}",Id::new()),"account_id":"trace-owned-mock"}})),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    let unavailable = f.page(Some(&next), 1).await;
    assert_eq!(unavailable.status, StatusCode::CONFLICT, "{}", unavailable.text);
    let synced = f.h.post(SYNC, json!({"request_id":Id::new(),"configuration_version":2,"confirm_live":false})).await;
    assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
    let old_scope = f.page(Some(&next), 1).await;
    assert_eq!(old_scope.status, StatusCode::CONFLICT, "{}", old_scope.text);
    let fresh = f.page(None, 1).await;
    assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.text);
    assert_eq!(fresh.json()["totalEvents"], 0);
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn late_commit_invalidates_cursor_but_after_watermark_arrival_does_not_change_old_pages() {
    let f = Fixture::open("trace-late-commit").await;
    f.ingest(2).await;
    let mut late = f.record(100);
    let store = f.h.state.ingest_sink.database().unwrap();
    let mut tx = store.db().begin_tenant(f.h.tenant).await.unwrap();
    insert(&mut tx, std::slice::from_ref(&late)).await;
    let first = f.page(None, 1).await;
    assert_eq!(first.json()["totalEvents"], 2);
    let next = cursor(&first);
    tx.commit().await.unwrap();
    let changed = f.page(Some(&next), 1).await;
    assert_eq!(changed.status, StatusCode::CONFLICT, "{}", changed.text);
    let refreshed = f.page(None, 1).await;
    assert_eq!(refreshed.json()["totalEvents"], 3);
    let next = cursor(&refreshed);
    let received: Timestamp = serde_json::from_value(refreshed.json()["asOfReceivedAt"].clone()).unwrap();
    late.id = Id::new();
    late.external_event_id = "after-watermark".into();
    late.received_at = received.offset_secs(1);
    f.seed(&[late]).await;
    let continued = f.page(Some(&next), 1).await;
    assert_eq!(continued.status, StatusCode::OK, "{}", continued.text);
    assert_eq!(continued.json()["totalEvents"], 3);
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn deletion_or_changed_record_requires_refresh_instead_of_merging_snapshot_pages() {
    for remove in [false, true] {
        let f = Fixture::open("trace-revision").await;
        let records: Vec<_> = (0..3).map(|index| f.record(index)).collect();
        f.seed(&records).await;
        let first = f.page(None, 1).await;
        let next = cursor(&first);
        let store = f.h.state.ingest_sink.database().unwrap();
        let mut tx = store.db().begin_tenant(f.h.tenant).await.unwrap();
        let statement = if remove {
            "DELETE FROM agentteams_audit WHERE tenant_id=$1 AND id=$2"
        } else {
            "UPDATE agentteams_audit SET payload=jsonb_set(payload,'{status}','\"error\"'::jsonb) WHERE tenant_id=$1 AND id=$2"
        };
        sqlx::query(statement)
            .bind(f.h.tenant.as_uuid())
            .bind(records[0].id.as_uuid())
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let changed = f.page(Some(&next), 1).await;
        assert_eq!(changed.status, StatusCode::CONFLICT, "{}", changed.text);
        assert!(f.page(None, 1).await.status.is_success());
    }
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn durable_unknown_graph_and_inventory_absence_are_not_complete_or_zero_evidence() {
    let f = Fixture::open("trace-evidence").await;
    let empty = f.page(None, 50).await;
    assert_eq!(empty.status, StatusCode::OK, "{}", empty.text);
    assert_eq!(empty.json()["inventoryAvailable"], true);
    assert_eq!(empty.json()["totalEvents"], 0);
    assert_eq!(empty.json()["graph"]["status"], "unobserved");
    let mut records: Vec<_> = (0..7).map(|index| f.record(index)).collect();
    records[0].span_id = Some("duplicate".into());
    records[1].span_id = Some("duplicate".into());
    records[2].parent_span_id = Some("duplicate".into());
    records[3].parent_span_id = records[4].span_id.clone();
    records[4].parent_span_id = records[3].span_id.clone();
    records[5].parent_span_id = Some("unseen-parent".into());
    records[6].span_id = None;
    f.seed(&records).await;
    let page = f.page(None, 1).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    let graph = &page.json()["graph"];
    assert_eq!(graph["status"], "conflict");
    assert_eq!(graph["nodes"].as_array().unwrap().len(), 7);
    assert!(graph["edges"].as_array().unwrap().is_empty());
    let kinds: BTreeSet<_> =
        graph["issues"].as_array().unwrap().iter().map(|issue| issue["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        BTreeSet::from(["duplicate_span", "ambiguous_parent", "cycle", "missing_parent", "missing_span"])
    );
    assert!(
        graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|node| node["authorized"].is_null() && node["authorizationStatus"] == "unknown")
    );
    let disabled =
        f.h.request(
            "PUT",
            CLOUD,
            Some(&f.h.admin),
            Some(json!({"expected_version":1,"enabled":false,
        "mock":true,"settings":{"instance_id":"unused-disabled"}})),
        )
        .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text);
    let absent = f.page(None, 50).await;
    assert_eq!(absent.status, StatusCode::OK, "{}", absent.text);
    assert_eq!(absent.json()["inventoryAvailable"], false);
    assert!(absent.json()["totalEvents"].is_null());
    assert!(absent.json()["items"].as_array().unwrap().is_empty());
    assert_eq!(absent.json()["graph"]["status"], "unavailable");
}
