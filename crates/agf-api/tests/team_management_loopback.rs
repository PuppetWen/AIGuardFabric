//! Actual local HTTP, strict existence evidence and sticky recovery after ambiguous deletion.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod team_management_helpers;
mod team_management_loopback_helpers;
use agf_core::ids::Id;
use common::*;
use team_management_helpers::*;
use team_management_loopback_helpers::*;

#[tokio::test]
async fn only_structured_provider_absence_allows_create_not_denial_html_or_missing_request_id() {
    let mut rpc = FixtureRpc::new().await;
    let before = snapshot(&rpc.f.h).await;
    for failure in [Failure::Forbidden, Failure::Html404, Failure::MissingRequestId404, Failure::MalformedIdentity] {
        rpc.restart_runtime();
        rpc.cloud.lock().unwrap().team_failure = Some(failure);
        let rejected = rpc.f.preview(create("absent-team", json!([]))).await;
        assert!(!rejected.status.is_success(), "{}", rejected.text);
        assert!(!rejected.text.contains("PRIVATE-UPSTREAM-DETAIL"), "upstream raw errors are not safe DTOs");
        assert_eq!(rpc.write_count("CreateTeam"), 0);
        assert_eq!(snapshot(&rpc.f.h).await, before);
    }
    rpc.cloud.lock().unwrap().team_failure = None;
    rpc.restart_runtime();
    let preview = result(rpc.f.preview(create("absent-team", json!([]))).await);
    assert_eq!(preview["baselineComplete"], true);
    assert_eq!(preview["previewUsable"], true);
    assert_eq!(rpc.write_count("CreateTeam"), 0, "reading a preview cannot dispatch the write");
    verified(&result(rpc.f.apply(&preview, Id::new()).await));
    assert_eq!(rpc.write_count("CreateTeam"), 1);
}

#[tokio::test]
async fn unknown_human_baseline_allows_description_keep_but_never_implicit_replacement() {
    let rpc = FixtureRpc::new().await;
    rpc.cloud.lock().unwrap().teams.get_mut(TEAM).unwrap().as_object_mut().unwrap().remove("TeamMembers");
    let replacement = rpc.f.preview(replace(TEAM, json!([]))).await;
    assert_eq!(replacement.status, StatusCode::PRECONDITION_FAILED, "{}", replacement.text);
    let preview = result(rpc.f.preview(update(TEAM, "Safe description only")).await);
    assert_eq!(preview["before"]["memberNamesAvailable"], false);
    assert_eq!(preview["before"]["memberNames"], Value::Null);
    assert_eq!(preview["membersChanged"], false);
    assert!(preview["desired"].get("memberNames").is_none());
    verified(&result(rpc.f.apply(&preview, Id::new()).await));
    let cloud = rpc.cloud.lock().unwrap();
    let (_, parameters) = cloud.writes.iter().find(|(action, _)| action == "UpdateTeam").unwrap();
    assert!(!parameters.contains_key("TeamMembers"));
    assert_eq!(parameters.get("Description").map(String::as_str), Some("Safe description only"));
    assert_eq!(cloud.teams[TEAM]["TeamMembers"], Value::Null);
}

#[tokio::test]
async fn selected_get_user_identity_and_final_provider_administrator_authorization_are_not_invented() {
    let rpc = FixtureRpc::new().await;
    for failure in [Failure::MalformedIdentity, Failure::Forbidden, Failure::MissingRequestId404] {
        rpc.cloud.lock().unwrap().user_failure = Some(failure);
        let mut change = create("user-check-team", json!(["member-user"]));
        change["admin_name"] = json!("admin-user");
        let denied = rpc.f.preview(change).await;
        assert!(!denied.status.is_success(), "{}", denied.text);
        assert!(!denied.text.contains("PRIVATE-UPSTREAM-DETAIL"));
        assert_eq!(rpc.write_count("CreateTeam"), 0);
    }
    rpc.cloud.lock().unwrap().user_failure = None;
    let preview = result(rpc.f.preview(create("user-check-team", json!(["member-user"]))).await);
    assert_eq!(preview["verifiedUsers"][0]["existenceVerified"], true);
    assert_eq!(preview["verifiedUsers"][0]["adminEligibility"], Value::Null);
    let mut change = create("provider-rejected-admin", json!(["member-user"]));
    change["admin_name"] = json!("admin-user");
    let preview = result(rpc.f.preview(change).await);
    let before = snapshot(&rpc.f.h).await;
    rpc.cloud.lock().unwrap().write_denied = true;
    let denied = result(rpc.f.apply(&preview, Id::new()).await);
    assert_eq!(denied["status"], "failed");
    assert_eq!(denied["cloudWrite"]["status"], "rejected");
    assert!(!denied.to_string().contains("PRIVATE-UPSTREAM-DETAIL"));
    assert!(!rpc.cloud.lock().unwrap().teams.contains_key("provider-rejected-admin"));
    assert_eq!(snapshot(&rpc.f.h).await, before);
}

#[tokio::test]
async fn readback_mismatch_preserves_old_snapshot_and_recovery_does_not_repeat_the_write() {
    let rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(update(TEAM, "Actual desired description")).await);
    let before = snapshot(&rpc.f.h).await;
    rpc.cloud.lock().unwrap().leave_old_description = true;
    let operation = result(rpc.f.apply(&preview, Id::new()).await);
    assert_eq!(operation["cloudWrite"]["status"], "accepted");
    assert_eq!(operation["status"], "uncertain");
    assert_eq!(operation["readback"]["status"], "mismatch");
    assert_eq!(snapshot(&rpc.f.h).await, before);
    assert_eq!(rpc.write_count("UpdateTeam"), 1);
    {
        let mut cloud = rpc.cloud.lock().unwrap();
        cloud.teams.get_mut(TEAM).unwrap()["Description"] = json!("Actual desired description");
    }
    let observed = result(rpc.f.recover(&operation, "observe").await);
    assert_eq!(observed["readback"]["status"], "matched");
    let published = result(rpc.f.recover(&observed, "publish").await);
    verified(&published);
    assert_eq!(rpc.write_count("UpdateTeam"), 1);
}

#[tokio::test]
async fn delete_receipt_loss_is_sticky_even_for_fresh_request_ids_and_present_readbacks() {
    let mut rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(delete(TEAM)).await);
    let before = snapshot(&rpc.f.h).await;
    rpc.cloud.lock().unwrap().write_unknown = true;
    let request = Id::new();
    let operation = result(rpc.f.apply(&preview, request).await);
    assert_eq!(operation["status"], "uncertain");
    assert_eq!(operation["cloudWrite"]["status"], "unknown");
    assert_eq!(rpc.write_count("DeleteTeam"), 1);
    assert_eq!(snapshot(&rpc.f.h).await, before);
    assert!(!operation["allowedActions"].as_array().unwrap().contains(&json!("retry_write")));
    result(rpc.f.apply(&preview, request).await);
    assert_eq!(rpc.write_count("DeleteTeam"), 1, "same request restores receipt without a second send");
    assert_eq!(rpc.f.apply(&preview, Id::new()).await.status, StatusCode::CONFLICT);
    for change in [create(TEAM, json!([])), update(TEAM, "New request cannot bypass delete"), delete(TEAM)] {
        assert_eq!(rpc.f.preview(change).await.status, StatusCode::PRECONDITION_FAILED);
    }
    for failure in [Failure::Forbidden, Failure::Html404, Failure::MissingRequestId404] {
        rpc.restart_runtime();
        rpc.cloud.lock().unwrap().team_failure = Some(failure);
        let observed = rpc.f.recover(&operation, "observe").await;
        if observed.status.is_success() {
            assert_ne!(observed.json()["readback"]["resourceState"], "absent");
            assert_ne!(observed.json()["status"], "verified");
        }
        assert_eq!(snapshot(&rpc.f.h).await, before);
        assert_eq!(rpc.write_count("DeleteTeam"), 1);
    }
    rpc.cloud.lock().unwrap().team_failure = None;
    rpc.restart_runtime();
    let deleting = result(rpc.f.recover(&operation, "observe").await);
    assert_eq!(deleting["readback"]["status"], "deleting");
    assert_ne!(deleting["status"], "verified");
    assert_eq!(rpc.write_count("DeleteTeam"), 1);
    rpc.complete_delete(TEAM);
    let absent = result(rpc.f.recover(&operation, "observe").await);
    assert_eq!(absent["readback"]["resourceState"], "absent");
    let published = result(rpc.f.recover(&absent, "publish").await);
    assert_eq!(published["status"], "verified");
    assert_eq!(published["inventoryPublish"]["status"], "published");
    assert_eq!(rpc.write_count("DeleteTeam"), 1);
}

#[tokio::test]
async fn an_absent_team_with_an_unresolved_worker_group_cannot_publish_a_partial_deletion_snapshot() {
    let rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(delete(TEAM)).await);
    let operation = result(rpc.f.apply(&preview, Id::new()).await);
    let before = snapshot(&rpc.f.h).await;
    rpc.cloud.lock().unwrap().teams.remove(TEAM);
    let absent = result(rpc.f.recover(&operation, "observe").await);
    assert_eq!(absent["readback"]["resourceState"], "absent");
    let publish = rpc.f.recover(&absent, "publish").await;
    if publish.status.is_success() {
        assert_eq!(publish.json()["inventoryPublish"]["status"], "failed");
        assert_ne!(publish.json()["status"], "verified");
    }
    assert_eq!(snapshot(&rpc.f.h).await, before, "known Worker.Groups still references the missing Team");
    assert_eq!(rpc.write_count("DeleteTeam"), 1);
    rpc.complete_delete(TEAM);
    let recovered = result(rpc.f.recover(&absent, "publish").await);
    assert_eq!(recovered["status"], "verified");
    assert_eq!(rpc.write_count("DeleteTeam"), 1);
}

#[tokio::test]
async fn drift_detected_in_the_final_preflight_never_sends_the_overwriting_update() {
    let rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(replace(TEAM, json!([]))).await);
    rpc.cloud.lock().unwrap().teams.get_mut(TEAM).unwrap()["TeamMembers"] = json!([{"Name":"admin-user"}]);
    let applied = rpc.f.apply(&preview, Id::new()).await;
    if applied.status.is_success() {
        assert_eq!(applied.json()["status"], "failed");
    } else {
        assert_eq!(applied.status, StatusCode::CONFLICT);
    }
    assert_eq!(rpc.write_count("UpdateTeam"), 0);
    assert_eq!(rpc.cloud.lock().unwrap().teams[TEAM]["TeamMembers"], json!([{"Name":"admin-user"}]));
}

#[tokio::test]
async fn an_administrator_cannot_bypass_preview_claims_using_generic_cloud_team_operations() {
    let rpc = FixtureRpc::new().await;
    let requests = rpc.server.received_requests().await.unwrap().len();
    for action in ["CreateTeam", "UpdateTeam", "DeleteTeam"] {
        let response = rpc
            .f
            .h
            .post(
                &format!("{CLOUD}/operations"),
                json!({"request_id":Id::new(),
            "configuration_version":1,"confirm_live":true,"action":action,
            "parameters":{"Name":TEAM}}),
            )
            .await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED, "{action}: {}", response.text);
        assert_eq!(rpc.write_count(action), 0);
    }
    assert_eq!(
        rpc.server.received_requests().await.unwrap().len(),
        requests,
        "denied raw writes must not even reach provider preflight"
    );
}
