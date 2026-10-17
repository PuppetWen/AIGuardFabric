//! Expired selection/preview evidence and configuration revisions never authorize a fresh write.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod team_management_helpers;
mod team_management_loopback_helpers;
use agf_core::ids::Id;
use common::*;
use team_management_helpers::*;
use team_management_loopback_helpers::*;

#[tokio::test]
async fn expired_previews_remain_readable_but_cannot_dispatch_or_appear_usable() {
    let f = Fixture::mock().await;
    let preview = result(f.preview(update(TEAM, "Expired preview cannot send")).await);
    let mut row =
        f.h.state
            .configurations
            .list::<Value>(f.h.tenant, STATE_KIND)
            .await
            .unwrap()
            .into_iter()
            .find(|row| row["team_name"] == TEAM)
            .unwrap();
    let id = Id::parse(row["id"].as_str().unwrap()).unwrap();
    row["previews"][preview["id"].as_str().unwrap()]["expires_at"] = json!(Timestamp::now().offset_secs(-1));
    f.h.state.configurations.put(f.h.tenant, STATE_KIND, id, &row).await.unwrap();
    let read = result(f.h.get(&format!("{BASE}/previews/{}", preview["id"].as_str().unwrap())).await);
    assert_eq!(read["previewUsable"], false);
    assert_eq!(read["unusableReason"], "expired");
    assert_eq!(f.apply(&preview, Id::new()).await.status, StatusCode::CONFLICT);
    assert_eq!(f.writes("UpdateTeam").await, 0);
}

#[tokio::test]
async fn selected_users_require_a_current_snapshot_even_when_the_names_were_previously_known() {
    let f = Fixture::mock().await;
    let users = result(f.users(json!({})).await);
    let kind = "agentteams-user-directory";
    let mut directory = f.h.state.configurations.list::<Value>(f.h.tenant, kind).await.unwrap().remove(0);
    directory["latest"]["observedAt"] = json!(Timestamp::now().offset_secs(-301));
    let id = agf_core::ids::deterministic_id("agf.team-management.directory", &f.h.tenant.to_string());
    f.h.state.configurations.put(f.h.tenant, kind, id, &directory).await.unwrap();
    let mut body = preview_body(create("expired-selection", json!(["member-user"])), 0, false);
    body["user_snapshot_id"] = users["snapshotId"].clone();
    let rejected = f.h.post(&format!("{BASE}/previews"), body).await;
    assert_eq!(rejected.status, StatusCode::PRECONDITION_FAILED, "{}", rejected.text);
    assert_eq!(f.writes("CreateTeam").await, 0);
}

#[tokio::test]
async fn confirmation_and_state_versions_are_checked_before_any_real_provider_dispatch() {
    let rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(update(TEAM, "Explicit current confirmation")).await);
    let mut unconfirmed = apply_body(&preview, Id::new(), false);
    assert_eq!(
        rpc.f.h.post(&format!("{BASE}/operations"), unconfirmed.clone()).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    unconfirmed["confirm_live"] = json!(true);
    unconfirmed["confirm_apply"] = json!(false);
    assert_eq!(rpc.f.h.post(&format!("{BASE}/operations"), unconfirmed).await.status, StatusCode::PRECONDITION_FAILED);
    for field in ["expected_state_version", "configuration_version"] {
        let mut stale = apply_body(&preview, Id::new(), true);
        stale[field] = json!(42);
        assert_eq!(rpc.f.h.post(&format!("{BASE}/operations"), stale).await.status, StatusCode::CONFLICT);
    }
    assert_eq!(rpc.write_count("UpdateTeam"), 0);
    assert_eq!(
        result(rpc.f.h.get(&format!("{BASE}/previews/{}", preview["id"].as_str().unwrap())).await)["previewUsable"],
        true
    );
    verified(&result(rpc.f.apply(&preview, Id::new()).await));
    assert_eq!(rpc.write_count("UpdateTeam"), 1);
}

#[tokio::test]
async fn rotating_configuration_and_reinventorying_the_same_target_never_clears_unknown_delete() {
    let rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(delete(TEAM)).await);
    rpc.cloud.lock().unwrap().write_unknown = true;
    let operation = result(rpc.f.apply(&preview, Id::new()).await);
    assert_eq!(operation["status"], "uncertain");
    let saved = rpc
        .f
        .h
        .request(
            "PUT",
            CLOUD,
            Some(&rpc.f.h.admin),
            Some(json!({"expected_version":1,
        "enabled":true,"mock":false,"settings":{"instance_id":INSTANCE,"account_id":"team-test-account",
        "endpoint":rpc.server.uri()},"secrets":{}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    result(rpc.f.h.post(SYNC, json!({"request_id":Id::new(),"configuration_version":2,"confirm_live":true})).await);
    let uri = format!("{BASE}/operations/{}", operation["id"].as_str().unwrap());
    let restored = result(rpc.f.h.get(&uri).await);
    assert_eq!(restored["configurationVersion"], 1, "original write provenance is immutable");
    assert_eq!(restored["scopeId"], operation["scopeId"]);
    assert_eq!(restored["recoveryConfigurationVersion"], 2);
    assert_eq!(restored["recoveryScopeId"], rpc.f.list().await["scopeId"]);
    assert!(restored["allowedActions"].as_array().unwrap().contains(&json!("observe")));
    let version = rpc.f.version(TEAM).await;
    for change in [create(TEAM, json!([])), update(TEAM, "Cannot resurrect a pending delete"), delete(TEAM)] {
        let mut body = preview_body(change, version, true);
        body["configuration_version"] = json!(2);
        assert_eq!(rpc.f.h.post(&format!("{BASE}/previews"), body).await.status, StatusCode::PRECONDITION_FAILED);
    }
    assert_eq!(rpc.write_count("DeleteTeam"), 1);
    rpc.complete_delete(TEAM);
    let uri = format!("{BASE}/operations/{}/observe", operation["id"].as_str().unwrap());
    let read =
        result(rpc.f.h.post(&uri, json!({"request_id":Id::new(),"configuration_version":2,"confirm_live":true})).await);
    assert_eq!(read["readback"]["resourceState"], "absent");
    let uri = format!("{BASE}/operations/{}/publish", operation["id"].as_str().unwrap());
    let published =
        result(rpc.f.h.post(&uri, json!({"request_id":Id::new(),"configuration_version":2,"confirm_live":true})).await);
    assert_eq!(published["status"], "verified");
    assert_eq!(
        rpc.write_count("DeleteTeam"),
        1,
        "configuration revisions cannot authorize retransmission of an ambiguous delete"
    );
}

#[tokio::test]
async fn changed_account_cannot_recover_an_old_operation_using_the_new_inventory() {
    let rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(update(TEAM, "Original account operation")).await);
    let operation = result(rpc.f.apply(&preview, Id::new()).await);
    verified(&operation);
    result(
        rpc.f
            .h
            .request(
                "PUT",
                CLOUD,
                Some(&rpc.f.h.admin),
                Some(json!({
                        "expected_version":1,"enabled":true,"mock":false,
                        "settings":{"instance_id":INSTANCE,"account_id":"another-account","endpoint":rpc.server.uri()},
                "secrets":{"access_key_id":"SECOND-LOOPBACK-ID","access_key_secret":"SECOND-LOOPBACK-SECRET"}
                    })),
            )
            .await,
    );
    result(rpc.f.h.post(SYNC, json!({"request_id":Id::new(),"configuration_version":2,"confirm_live":true})).await);
    let uri = format!("{BASE}/operations/{}", operation["id"].as_str().unwrap());
    let restored = result(rpc.f.h.get(&uri).await);
    assert_eq!(restored["configurationVersion"], 1);
    assert_eq!(restored["status"], "superseded");
    assert_eq!(restored["recoveryConfigurationVersion"], Value::Null);
    assert_eq!(restored["recoveryScopeId"], Value::Null);
    assert_eq!(restored["allowedActions"], json!(["read_receipt"]));
    let recovered = rpc
        .f
        .h
        .post(
            &format!("{uri}/observe"),
            json!({
                "request_id":Id::new(),"configuration_version":2,"confirm_live":true
            }),
        )
        .await;
    assert_eq!(recovered.status, StatusCode::CONFLICT);
    assert_eq!(rpc.write_count("UpdateTeam"), 1);
}
