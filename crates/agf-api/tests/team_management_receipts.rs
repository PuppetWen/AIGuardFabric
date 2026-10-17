//! Receipt recovery cannot revive an old intent or reuse another selection request.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod team_management_helpers;
mod team_management_loopback_helpers;
use agf_core::ids::Id;
use common::*;
use team_management_helpers::*;
use team_management_loopback_helpers::*;

#[tokio::test]
async fn directory_request_ids_restore_the_page_and_reject_another_query() {
    let f = Fixture::mock().await;
    let request = Id::new();
    let first = result(f.users(json!({"request_id":request})).await);
    let replay = result(f.users(json!({"request_id":request})).await);
    assert_eq!(replay, first, "same read restores its recorded page rather than reissuing a query");
    let conflict = f.users(json!({"request_id":request,"name_like":"member"})).await;
    assert_eq!(conflict.status, StatusCode::CONFLICT, "{}", conflict.text);
    let current = f.list().await;
    assert_eq!(current["userDirectory"]["snapshotId"], first["snapshotId"]);
    assert_eq!(current["userDirectory"]["selectionUsable"], true);
}

#[tokio::test]
async fn a_new_team_intent_supersedes_old_recovery_without_losing_its_accepted_receipt() {
    let f = Fixture::mock().await;
    let preview = result(f.preview(update(TEAM, "First confirmed description")).await);
    let first = result(f.apply(&preview, Id::new()).await);
    verified(&first);
    let preview = result(f.preview(update(TEAM, "Second confirmed description")).await);
    let second = result(f.apply(&preview, Id::new()).await);
    verified(&second);
    let path = format!("{BASE}/operations/{}", first["id"].as_str().unwrap());
    let old = result(f.h.get(&path).await);
    assert_eq!(old["status"], "superseded");
    assert_eq!(old["cloudWrite"], first["cloudWrite"], "superseding does not erase the real cloud receipt");
    assert_eq!(old["allowedActions"], json!(["read_receipt"]));
    assert!(old["recoveryScopeId"].is_null());
    assert!(old["recoveryConfigurationVersion"].is_null());
    for phase in ["observe", "publish"] {
        let rejected = f.recover(&first, phase).await;
        assert_eq!(rejected.status, StatusCode::CONFLICT, "{}", rejected.text);
    }
    assert_eq!(f.writes("UpdateTeam").await, 2);
    assert_eq!(f.cloud_team(TEAM).await["Description"], "Second confirmed description");
    let reread = result(f.recover(&second, "observe").await);
    verified(&reread);
    assert_eq!(reread["recoveryConfigurationVersion"], 1);
    assert_eq!(reread["recoveryScopeId"], f.list().await["scopeId"]);
    assert_eq!(f.writes("UpdateTeam").await, 2, "read recovery cannot write an old or current intent");
}

#[tokio::test]
async fn changing_an_unprovided_field_to_explicit_null_invalidates_the_cloud_baseline() {
    let rpc = FixtureRpc::new().await;
    rpc.cloud.lock().unwrap().teams.get_mut(TEAM).unwrap().as_object_mut().unwrap().remove("Description");
    let preview = result(rpc.f.preview(update(TEAM, "Requested description")).await);
    assert!(preview["before"]["description"].is_null());
    rpc.cloud.lock().unwrap().teams.get_mut(TEAM).unwrap()["Description"] = Value::Null;
    let operation = result(rpc.f.apply(&preview, Id::new()).await);
    assert_ne!(operation["status"], "verified");
    assert_eq!(rpc.write_count("UpdateTeam"), 0, "missing/null evidence must not collapse to an equal baseline hash");
    assert_eq!(operation["cloudWrite"]["status"], "rejected");
}
