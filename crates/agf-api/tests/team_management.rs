//! Persistent Mock Team changes through authenticated HTTP: explicit preview and confirmation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod team_management_helpers;
use agf_core::ids::Id;
use common::*;
use team_management_helpers::*;

#[tokio::test]
async fn cloud_user_picker_is_safe_and_filtered_empty_does_not_prove_existence() {
    let f = Fixture::mock().await;
    let users = result(f.users(json!({})).await);
    assert_eq!(users["complete"], true);
    assert_eq!(users["directoryComplete"], true);
    assert_eq!(users["selectionUsable"], true);
    for name in ["member-user", "admin-user"] {
        let user = users["items"].as_array().unwrap().iter().find(|user| user["name"] == name).unwrap();
        assert_eq!(user["existenceVerified"], false);
        assert_eq!(user["adminEligibility"], Value::Null);
        for forbidden in ["email", "Email", "AuthMethod", "Note", "password", "raw", "Data"] {
            assert!(user.get(forbidden).is_none(), "unsafe directory field {forbidden}: {user}");
        }
    }
    let filtered = result(f.users(json!({"name_like":"not-a-known-user"})).await);
    assert_eq!(filtered["items"], json!([]));
    assert_eq!(filtered["complete"], true);
    assert_eq!(filtered["directoryComplete"], false, "a filtered query never proves complete instance coverage");
    let mut body = preview_body(create("invalid-member-team", json!(["not-a-known-user"])), 0, false);
    body["user_snapshot_id"] = filtered["snapshotId"].clone();
    let missing = f.h.post(&format!("{BASE}/previews"), body).await;
    assert_eq!(missing.status, StatusCode::PRECONDITION_FAILED, "{}", missing.text);
    assert_eq!(f.writes("CreateTeam").await, 0, "a caller cannot create its own Mock cloud user by naming it");
}

#[tokio::test]
async fn mock_create_update_delete_uses_real_readback_and_requires_explicit_delete_recovery() {
    let f = Fixture::mock().await;
    let mut change = create("managed-team", json!(["member-user"]));
    change["admin_name"] = json!("admin-user");
    let preview = result(f.preview(change).await);
    assert_eq!(preview["action"], "create");
    assert_eq!(preview["previewUsable"], true);
    assert_eq!(preview["desired"]["memberNames"], json!(["member-user"]));
    for user in preview["verifiedUsers"].as_array().unwrap() {
        assert_eq!(user["existenceVerified"], true);
        assert_eq!(user["adminEligibility"], Value::Null, "GetUser Active cannot establish administrator eligibility");
    }
    let operation = result(f.apply(&preview, Id::new()).await);
    verified(&operation);
    let created = f.cloud_team("managed-team").await;
    assert_eq!(created["Name"], "managed-team");
    assert_eq!(created["AdminName"], "admin-user");
    assert_eq!(created["TeamMembers"], json!([{"Name":"member-user"}]));
    assert_eq!(created["WorkerNames"], json!([]));
    let before_assets: std::collections::BTreeSet<_> =
        f.h.state.store.asset_list_all(f.h.tenant).unwrap().into_iter().map(|asset| asset.id).collect();
    let deletion = result(f.preview(delete("managed-team")).await);
    assert_eq!(deletion["deleteImpact"]["humanCount"], 1);
    assert_eq!(deletion["deleteImpact"]["workerCount"], 0);
    assert_eq!(deletion["deleteImpact"]["asyncCleanup"], true);
    let mut deleted = result(f.apply(&deletion, Id::new()).await);
    assert_eq!(deleted["status"], "deleting", "successful Delete receipt is not cleanup completion");
    assert_eq!(deleted["cloudWrite"]["status"], "accepted");
    assert_eq!(deleted["readback"]["resourceState"], "present");
    assert_ne!(deleted["inventoryPublish"]["status"], "published");
    assert!(!deleted["allowedActions"].as_array().unwrap().contains(&json!("retry_write")));
    for _ in 0..3 {
        deleted = result(f.recover(&deleted, "observe").await);
        if deleted["readback"]["resourceState"] == "absent" {
            break;
        }
    }
    assert_eq!(deleted["readback"]["resourceState"], "absent", "Mock tombstone must progress through actual reads");
    let published = result(f.recover(&deleted, "publish").await);
    verified(&published);
    assert_eq!(f.writes("DeleteTeam").await, 1, "observe/publish never dispatch another Delete");
    let directory = f.list().await;
    assert!(
        !directory["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|team| team["teamName"] == "managed-team" && team["currentAvailable"] == true)
    );
    let after_assets: std::collections::BTreeSet<_> =
        f.h.state.store.asset_list_all(f.h.tenant).unwrap().into_iter().map(|asset| asset.id).collect();
    assert_eq!(after_assets, before_assets, "Team deletion must not delete or replace retained Worker assets");
}

#[tokio::test]
async fn description_only_keeps_all_users_and_explicit_empty_replacement_clears_only_human_members() {
    let f = Fixture::mock().await;
    let baseline = f.cloud_team(TEAM).await;
    let inventory = agf_api::cloud_inventory::load(&f.h.state, f.h.tenant).await.unwrap().unwrap();
    let mut asset = f.h.state.store.asset_get(f.h.tenant, inventory.assets["worker-demo"]).unwrap().unwrap();
    asset.owner = Some("manual-owner".into());
    asset.attributes.insert("manual-annotation".into(), json!("keep me"));
    f.h.state.store.asset_upsert(&asset).unwrap();
    let preview = result(f.preview(update(TEAM, "Description changed only")).await);
    assert_eq!(preview["descriptionChanged"], true);
    assert_eq!(preview["membersChanged"], false);
    assert!(preview["desired"].get("memberNames").is_none(), "omitted members mean keep, never implicit []");
    verified(&result(f.apply(&preview, Id::new()).await));
    let kept = f.cloud_team(TEAM).await;
    assert_eq!(kept["Description"], "Description changed only");
    for field in ["TeamMembers", "AdminName", "LeaderName", "WorkerNames", "Rooms"] {
        assert_eq!(kept[field], baseline[field], "Description-only must preserve {field}");
    }
    let preview = result(f.preview(replace(TEAM, json!([]))).await);
    assert_eq!(preview["membersChanged"], true);
    assert_eq!(preview["desired"]["memberNames"], json!([]));
    assert_eq!(preview["removedMembers"], json!(["member-user"]));
    verified(&result(f.apply(&preview, Id::new()).await));
    let empty = f.cloud_team(TEAM).await;
    assert_eq!(empty["TeamMembers"], json!([]));
    assert_eq!(empty["Description"], kept["Description"]);
    assert_eq!(empty["WorkerNames"], baseline["WorkerNames"], "cloud users are independent of Worker membership");
    let retained = f.h.state.store.asset_get(f.h.tenant, asset.id).unwrap().unwrap();
    assert_eq!(retained.owner, asset.owner);
    assert_eq!(retained.attributes["manual-annotation"], "keep me");
}

#[tokio::test]
async fn one_preview_has_one_writer_and_request_identity_restores_only_the_original_receipt() {
    let f = Fixture::mock().await;
    let preview = result(f.preview(update(TEAM, "One writer")).await);
    let left = Id::new();
    let right = Id::new();
    let (a, b) = tokio::join!(f.apply(&preview, left), f.apply(&preview, right));
    assert_eq!([a.status, b.status].iter().filter(|status| status.is_success()).count(), 1, "{} / {}", a.text, b.text);
    assert_eq!([a.status, b.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let (operation, request) = if a.status.is_success() { (a.json(), left) } else { (b.json(), right) };
    verified(&operation);
    assert_eq!(f.writes("UpdateTeam").await, 1);
    assert_eq!(result(f.apply(&preview, request).await), operation, "same request ID restores the saved result");
    let lookup = result(f.h.get(&format!("{BASE}?request_id={request}")).await);
    assert!(lookup["operations"].as_array().unwrap().iter().any(|run| run["id"] == operation["id"]));
    let second = result(f.preview(update(TEAM, "Another operation")).await);
    assert_eq!(
        f.apply(&second, request).await.status,
        StatusCode::CONFLICT,
        "one request ID cannot select a new preview"
    );
    assert_eq!(f.writes("UpdateTeam").await, 1);
    let consumed = result(f.h.get(&format!("{BASE}/previews/{}", preview["id"].as_str().unwrap())).await);
    assert_eq!(consumed["previewUsable"], false);
    assert_eq!(consumed["unusableReason"], "consumed");
}

#[tokio::test]
async fn strict_change_fields_cannot_write_cloud_users_workers_roles_or_other_scopes() {
    let f = Fixture::mock().await;
    let mut cases = vec![
        json!({"action":"create","team_name":"new-team"}),
        json!({"action":"create","team_name":"new-team","member_names":null}),
        json!({"action":"update","team_name":TEAM}),
        json!({"action":"update","team_name":TEAM,"description":null}),
        json!({"action":"update","team_name":TEAM,"members":null}),
        json!({"action":"update","team_name":TEAM,"members":{"mode":"keep","names":[],"confirm_full_replacement":true}}),
    ];
    for field in
        ["admin_name", "leader_name", "worker_names", "groups", "tenant_id", "instance_id", "account_id", "Name"]
    {
        let mut change = update(TEAM, "Forbidden extra field");
        change[field] = json!("untrusted-target");
        cases.push(change);
    }
    let before = snapshot(&f.h).await;
    for change in cases {
        let rejected = f.preview(change).await;
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST, "{}", rejected.text);
        assert!(rejected.content_type().starts_with("application/problem+json"));
    }
    for change in [
        json!({"action":"update","team_name":TEAM,"members":{"mode":"replace","names":[],"confirm_full_replacement":false}}),
        json!({"action":"delete","team_name":TEAM,"confirm_team_name":"another-team","confirm_async_cleanup":true}),
        json!({"action":"delete","team_name":TEAM,"confirm_team_name":TEAM,"confirm_async_cleanup":false}),
    ] {
        let rejected = f.preview(change).await;
        assert_eq!(
            rejected.status,
            StatusCode::PRECONDITION_FAILED,
            "explicit confirmation is required: {}",
            rejected.text
        );
    }
    let mut body = preview_body(update(TEAM, "Another account"), 0, false);
    body["tenant_id"] = json!(f.h.other_tenant);
    assert_eq!(f.h.post(&format!("{BASE}/previews"), body).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(snapshot(&f.h).await, before);
    for action in ["CreateTeam", "UpdateTeam", "DeleteTeam"] {
        assert_eq!(f.writes(action).await, 0);
    }
}

#[tokio::test]
async fn preview_and_operation_routes_require_auth_and_never_cross_the_selected_tenant() {
    let f = Fixture::mock().await;
    let preview = result(f.preview(update(TEAM, "Tenant-bound preview")).await);
    let path = format!("{BASE}/previews/{}", preview["id"].as_str().unwrap());
    assert_eq!(f.h.request("GET", BASE, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(f.h.request("GET", &path, Some(&f.h.viewer), None).await.status, StatusCode::FORBIDDEN);
    let issued = result(
        f.h.post(
            "/api/v1/settings/api-keys",
            json!({"name":"native-team-reader",
        "scopes":["alicloud:read"]}),
        )
        .await,
    );
    let reader = issued["plaintext"].as_str().unwrap();
    assert_eq!(f.h.request("GET", &path, Some(reader), None).await.status, StatusCode::OK);
    let list = result(f.h.request("GET", BASE, Some(reader), None).await);
    assert_eq!(list["canWrite"], false);
    assert_eq!(list["canPrepare"], false);
    for (uri, body) in [
        (format!("{BASE}/users/observe"), json!({"request_id":Id::new(),"configuration_version":1})),
        (format!("{BASE}/previews"), preview_body(update(TEAM, "Viewer"), 0, false)),
        (format!("{BASE}/operations"), apply_body(&preview, Id::new(), false)),
    ] {
        assert_eq!(f.h.request("POST", &uri, Some(&f.h.viewer), Some(body)).await.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(
        f.h.request(
            "POST",
            &format!("{BASE}/previews"),
            Some(reader),
            Some(preview_body(update(TEAM, "Read-only key cannot write"), 0, false))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let foreign = scoped(&f.h, f.h.other_tenant, "GET", &path, None).await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND, "{}", foreign.text);
    assert!(!foreign.text.contains("Tenant-bound preview"));
    let operation = result(f.apply(&preview, Id::new()).await);
    let path = format!("{BASE}/operations/{}", operation["id"].as_str().unwrap());
    assert_eq!(scoped(&f.h, f.h.other_tenant, "GET", &path, None).await.status, StatusCode::NOT_FOUND);
    let other = result(scoped(&f.h, f.h.other_tenant, "GET", BASE, None).await);
    assert_eq!(other["operations"], json!([]));
    assert_eq!(other["items"], json!([]));
}

#[tokio::test]
async fn configuration_change_since_preview_never_dispatches_the_old_write() {
    let f = Fixture::mock().await;
    let preview = result(f.preview(update(TEAM, "Never publish to another account")).await);
    let configured =
        f.h.request(
            "PUT",
            CLOUD,
            Some(&f.h.admin),
            Some(json!({"expected_version":1,
        "enabled":true,"mock":true,"settings":{"instance_id":"another-instance","account_id":"another-account"}})),
        )
        .await;
    assert_eq!(configured.status, StatusCode::OK, "{}", configured.text);
    assert_eq!(f.apply(&preview, Id::new()).await.status, StatusCode::CONFLICT);
    assert_eq!(f.writes("UpdateTeam").await, 0);
    let stale = result(f.h.get(&format!("{BASE}/previews/{}", preview["id"].as_str().unwrap())).await);
    assert_eq!(stale["previewUsable"], false);
    assert!(["scope-changed", "version-changed"].contains(&stale["unusableReason"].as_str().unwrap()));
}
