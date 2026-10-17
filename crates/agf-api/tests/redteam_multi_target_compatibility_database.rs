#![cfg(feature = "test-loopback-transport")]
mod common;
mod redteam_multi_target_database_support;
use agf_core::{error::DomainResult, ids::Id};
use common::*;
use redteam_multi_target_database_support::{BASE, Fixture, Pending, key_call, owned, private_free};
fn managed(id: Id) -> String {
    format!("{BASE}/profiles/mcp-http/{id}/transport")
}
fn approval(f: &Fixture, version: u64, enabled: bool) -> Value {
    json!({"expected_version":version,"profile_version":1,"url":f.wires[1].url(),"enabled":enabled,
        "mcp_protocol_revision":"2026-07-28","private_network":null})
}
#[tokio::test]
#[ignore = "requires exact owned multi-target SQL database and default-off literal127 capability"]
async fn explicit_legacy_profile_runs_real_handshake_and_original_replay_never_reinitializes() -> DomainResult<()> {
    let f = Fixture::new_with_legacy("compat-legacy", true, false, true).await?;
    let mut input = approval(&f, 0, true);
    input["mcp_protocol_revision"] = json!("2025-11-25");
    let saved = f.case.h.request("PUT", &managed(f.ids[1]), Some(&f.case.h.admin), Some(input)).await;
    assert_eq!(saved.status, StatusCode::OK);
    let request = Id::new();
    let body = f.body(request).await?;
    let result = f.call("POST", &format!("{BASE}/runs"), Some(body.clone())).await;
    private_free(&result);
    assert!(
        result.status == StatusCode::OK
            && result.json()["status"] == "completed"
            && result.json()["targets"][1]["mcpProtocolRevision"] == "2025-11-25"
            && f.counts()? == [1, 4, 1]
    );
    let rows = f.wires[1].requests()?;
    assert_eq!(
        rows.iter().map(|row| row["method"].as_str()).collect::<Vec<_>>(),
        vec![Some("initialize"), Some("notifications/initialized"), Some("tools/list"), Some("tools/call")]
    );
    let before = f.snapshot().await?;
    let second = f.second().await?;
    assert_eq!(key_call(&second, &f.key, "POST", &format!("{BASE}/runs"), Some(body)).await.json(), result.json());
    assert!(f.snapshot().await? == before && f.counts()? == [1, 4, 1]);
    f.chain().await
}
#[tokio::test]
#[ignore = "requires exact owned multi-target SQL database and default-off literal127 capability"]
async fn owner_recent_reads_are_pure_and_archive_preserves_original_uuid_across_instances() -> DomainResult<()> {
    let f = Fixture::new("compat-archive", true, false).await?;
    let request = Id::new();
    let body = f.body(request).await?;
    let result = f.call("POST", &format!("{BASE}/runs"), Some(body.clone())).await;
    assert!(result.status == StatusCode::OK && result.json()["status"] == "completed");
    let generation = result.json()["generation"].as_u64().ok_or_else(owned::failure)?;
    let before = f.snapshot().await?;
    let list = f.call("GET", &format!("{BASE}/runs?limit=20&offset=0"), None).await;
    assert!(
        list.status == StatusCode::OK
            && list.json()["items"][0]["requestId"] == json!(request)
            && list.json()["total"] == 1
    );
    for query in ["limit=0", "offset=256", "limit=1&limit=2", "tenant=foreign"] {
        assert_eq!(f.call("GET", &format!("{BASE}/runs?{query}"), None).await.status, StatusCode::BAD_REQUEST);
    }
    assert!(f.snapshot().await? == before && f.counts()? == [1, 2, 1]);
    let archive_path = format!("{BASE}/runs/{request}/archive");
    let archived = f.call("POST", &archive_path, Some(json!({"expected_generation":generation}))).await;
    assert!(
        archived.status == StatusCode::OK
            && archived.json()["status"] == "archived"
            && archived.json()["originalStatus"] == "completed"
            && archived.json()["auditId"] == result.json()["auditId"]
            && archived.json()["evidence"] == json!([])
            && archived.json()["archivedEvidenceSha256"].is_string()
            && archived.json()["canRetryDispatch"] == false
    );
    private_free(&archived);
    let retained = f.snapshot().await?;
    let second = f.second().await?;
    let replay = key_call(&second, &f.key, "POST", &format!("{BASE}/runs"), Some(body)).await;
    assert!(replay.status == StatusCode::OK && replay.json() == archived.json());
    assert_eq!(
        key_call(&second, &f.key, "POST", &archive_path, Some(json!({"expected_generation":generation}))).await.json(),
        archived.json()
    );
    assert_eq!(
        f.call("POST", &archive_path, Some(json!({"expected_generation":generation+1}))).await.status,
        StatusCode::CONFLICT
    );
    assert!(
        f.snapshot().await? == retained && f.counts()? == [1, 2, 1] && f.terminal_audits(request, true).await? == 1
    );
    let foreign = f.case.foreign().await?;
    assert_eq!(foreign.get(&format!("{BASE}/runs/{request}")).await.status, StatusCode::NOT_FOUND);
    f.chain().await
}
#[tokio::test]
#[ignore = "requires exact owned multi-target SQL database and default-off literal127 capability"]
async fn explicit_private_http_approval_is_cas_bound_to_registered_url_version_and_sends_nothing() -> DomainResult<()> {
    let f = Fixture::new("compat-private", true, false).await?;
    let id = f.ids[1];
    let saved = f
        .case
        .h
        .post(
            "/api/v1/redteam/mcp-targets",
            json!({"id":id,"expected_version":1,"asset_id":f.assets[1],
        "name":"Owned explicitly private MCP","url":"http://10.2.3.4:8080/mcp","enabled":true,"tool_name":"safe_query",
        "argument_name":"query","bearer_token":"","protected_canary":redteam_multi_target_database_support::CANARY}),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    let mut targets = f.selections.clone();
    targets[1]["expected_version"] = json!(2);
    assert_eq!(
        f.call("POST", &format!("{BASE}/preview"), Some(json!({"targets":targets}))).await.status,
        StatusCode::BAD_REQUEST
    );
    let mut input = json!({"expected_version":0,"profile_version":2,"url":"http://10.2.3.4:8080/mcp","enabled":true,
        "mcp_protocol_revision":"2026-07-28","private_network":{"addresses":["10.2.3.4"],"port":8080,"allow_plain_http":false,"confirm_exact_private_network":true}});
    let before = f.snapshot().await?;
    assert_eq!(
        f.case.h.request("PUT", &managed(id), Some(&f.case.h.admin), Some(input.clone())).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(f.call("PUT", &managed(id), Some(input.clone())).await.status, StatusCode::FORBIDDEN);
    assert_eq!(f.snapshot().await?, before);
    input["private_network"]["allow_plain_http"] = json!(true);
    let accepted = f.case.h.request("PUT", &managed(id), Some(&f.case.h.admin), Some(input.clone())).await;
    assert!(
        accepted.status == StatusCode::OK
            && accepted.json()["version"] == 1
            && accepted.json()["privateNetwork"]["allowPlainHttp"] == true
    );
    private_free(&accepted);
    let preview = f.call("POST", &format!("{BASE}/preview"), Some(json!({"targets":targets}))).await;
    assert!(
        preview.status == StatusCode::OK
            && preview.json()["topology"]["targets"][1]["transportMode"] == "approved-private-http"
    );
    input["expected_version"] = json!(1);
    input["enabled"] = json!(false);
    assert_eq!(
        f.case.h.request("PUT", &managed(id), Some(&f.case.h.admin), Some(input.clone())).await.status,
        StatusCode::OK
    );
    let retained = f.snapshot().await?;
    assert_eq!(
        f.call("POST", &format!("{BASE}/preview"), Some(json!({"targets":targets}))).await.status,
        StatusCode::CONFLICT
    );
    input["expected_version"] = json!(0);
    assert_eq!(
        f.case.h.request("PUT", &managed(id), Some(&f.case.h.admin), Some(input)).await.status,
        StatusCode::CONFLICT
    );
    assert!(f.snapshot().await? == retained && f.counts()? == [0, 0, 0]);
    f.chain().await
}
#[tokio::test]
#[ignore = "requires exact owned multi-target SQL database and default-off literal127 capability"]
async fn current_approval_change_after_actual_first_read_stops_all_follow_on_requests() -> DomainResult<()> {
    let f = Fixture::new("compat-change", true, true).await?;
    let request = Id::new();
    let body = f.body(request).await?;
    let mut pending = Pending::start(f.case.h.clone(), f.key.clone(), body);
    let gate = f.wires[0].gate.as_ref().ok_or_else(owned::failure)?;
    gate.wait().await?;
    let approved =
        f.case.h.request("PUT", &managed(f.ids[1]), Some(&f.case.h.admin), Some(approval(&f, 0, false))).await;
    gate.release();
    assert_eq!(approved.status, StatusCode::OK);
    let result = pending.finish().await?;
    assert!(
        result.status == StatusCode::OK
            && result.json()["completionState"] == "pending_audit"
            && f.counts()? == [1, 0, 0]
    );
    let second = f.second().await?;
    let recovered = key_call(&second, &f.key, "POST", &format!("{BASE}/runs/{request}/recover"), Some(json!({}))).await;
    assert!(
        recovered.status == StatusCode::OK
            && recovered.json()["status"] == "failed"
            && recovered.json()["sourceCurrent"] == false
    );
    assert!(f.counts()? == [1, 0, 0] && f.terminal_audits(request, false).await? == 1);
    f.chain().await
}
#[tokio::test]
#[ignore = "requires exact owned multi-target SQL database and default-off literal127 capability"]
async fn body_capacity_archive_frees_only_body_slot_and_original_ids_never_dispatch_again() -> DomainResult<()> {
    let f = Fixture::new("compat-capacity", true, false).await?;
    let mut bodies = Vec::new();
    let mut generations = Vec::new();
    for _ in 0..128 {
        let id = Id::new();
        let body = f.body(id).await?;
        let response = f.call("POST", &format!("{BASE}/runs"), Some(body.clone())).await;
        assert!(response.status == StatusCode::OK && response.json()["status"] == "completed");
        generations.push(response.json()["generation"].as_u64().ok_or_else(owned::failure)?);
        bodies.push((id, body));
    }
    let candidate = f.body(Id::new()).await?;
    let before = f.snapshot().await?;
    assert_eq!(
        f.call("POST", &format!("{BASE}/runs"), Some(candidate.clone())).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert!(f.snapshot().await? == before && f.counts()? == [128, 256, 128]);
    for (at, (id, _)) in bodies.iter().take(100).enumerate() {
        let response = f
            .call("POST", &format!("{BASE}/runs/{id}/archive"), Some(json!({"expected_generation":generations[at]})))
            .await;
        assert!(response.status == StatusCode::OK && response.json()["status"] == "archived");
    }
    assert_eq!(f.call("POST", &format!("{BASE}/runs"), Some(candidate)).await.json()["status"], "completed");
    let retained = f.snapshot().await?;
    for (_, body) in bodies.iter().take(100) {
        let response = f.call("POST", &format!("{BASE}/runs"), Some(body.clone())).await;
        assert!(response.status == StatusCode::OK && response.json()["status"] == "archived");
    }
    assert!(f.snapshot().await? == retained && f.counts()? == [129, 258, 129]);
    f.chain().await
}
