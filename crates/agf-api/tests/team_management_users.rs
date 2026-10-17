//! Public user pagination is selection evidence, never an automatic full-member replacement.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod team_management_helpers;
mod team_management_loopback_helpers;
use agf_core::ids::Id;
use common::*;
use team_management_helpers::*;
use team_management_loopback_helpers::*;

fn user(name: &str) -> Value {
    json!({"InstanceId":INSTANCE,"Name":name,"DisplayName":name,"Status":"Active",
        "Email":"USER-PRIVATE-SENTINEL@example.com","AuthMethod":"password","Note":"USER-PRIVATE-SENTINEL"})
}
fn page(items: Value, total: Value, next: Value) -> Value {
    json!({"Items":items,"TotalCount":total,"NextToken":next})
}

#[tokio::test]
async fn valid_partial_pages_and_optional_nulls_are_selectable_without_claiming_directory_completeness() {
    let rpc = FixtureRpc::new().await;
    rpc.cloud.lock().unwrap().user_pages.extend([
        (200, page(json!([user("member-user")]), json!(2), json!("next"))),
        (200, page(json!([user("admin-user")]), json!(2), Value::Null)),
    ]);
    let first = result(rpc.f.users(json!({})).await);
    assert_eq!(first["pageComplete"], true);
    assert_eq!(first["complete"], false);
    assert_eq!(first["directoryComplete"], false);
    assert_eq!(first["selectionUsable"], true);
    let cursor = first["nextCursor"].as_str().unwrap();
    assert_ne!(cursor, "next", "provider paging tokens must not be accepted as unscoped browser cursors");
    let second = result(rpc.f.users(json!({"cursor":cursor})).await);
    assert_eq!(second["complete"], true);
    assert_eq!(second["directoryComplete"], true);
    assert_eq!(second["nextCursor"], Value::Null);
    for observed in [&first, &second] {
        assert!(!observed.to_string().contains("USER-PRIVATE-SENTINEL"));
        for item in observed["items"].as_array().unwrap() {
            assert_eq!(item["existenceVerified"], false);
            assert_eq!(item["adminEligibility"], Value::Null);
        }
    }
    rpc.cloud.lock().unwrap().user_pages.push_back((200, page(json!([user("member-user")]), Value::Null, Value::Null)));
    let optional = result(rpc.f.users(json!({})).await);
    assert_eq!(optional["complete"], true);
    assert_eq!(optional["totalCount"], Value::Null);
}

#[tokio::test]
async fn bad_pages_never_publish_a_new_empty_complete_directory_or_unsafe_user_fields() {
    let rpc = FixtureRpc::new().await;
    let baseline = result(rpc.f.users(json!({})).await);
    let mut wrong_instance = user("member-user");
    wrong_instance["InstanceId"] = json!("foreign-instance");
    let mut bad_status = user("member-user");
    bad_status["Status"] = json!({"token":"USER-PRIVATE-SENTINEL"});
    let cases = [
        (200, json!({"Data":[]})),
        (200, page(json!([user("member-user"), user("member-user")]), json!(2), Value::Null)),
        (200, page(json!([wrong_instance]), json!(1), Value::Null)),
        (200, page(json!([bad_status]), json!(1), Value::Null)),
        (200, page(json!([{}]), json!(1), Value::Null)),
        (200, page(json!([user("member-user")]), json!(2), Value::Null)),
        (200, page(json!([user("member-user")]), json!(0), Value::Null)),
        (200, page(json!([user("member-user")]), json!("1"), Value::Null)),
        (200, page(json!([user("member-user")]), json!(1), json!([]))),
        (403, json!({"Code":"Forbidden.RAM","RequestId":"denied-users","Message":"USER-PRIVATE-SENTINEL"})),
    ];
    for (status, body) in cases {
        rpc.cloud.lock().unwrap().user_pages.push_back((status, body));
        let rejected = rpc.f.users(json!({})).await;
        assert!(!rejected.status.is_success(), "{}", rejected.text);
        assert!(!rejected.text.contains("USER-PRIVATE-SENTINEL"));
        let retained = rpc.f.list().await["userDirectory"].clone();
        assert_eq!(retained["snapshotId"], baseline["snapshotId"]);
        assert_eq!(retained["items"], baseline["items"]);
        assert_eq!(retained["selectionUsable"], false, "a failed refresh cannot leave old pages presented as current");
        assert_eq!(retained["complete"], true, "the historical observation stays identifiable as previously complete");
        let mut stale = preview_body(create("stale-directory-team", json!(["member-user"])), 0, true);
        stale["user_snapshot_id"] = baseline["snapshotId"].clone();
        assert_eq!(rpc.f.h.post(&format!("{BASE}/previews"), stale).await.status, StatusCode::PRECONDITION_FAILED);
    }
}

#[tokio::test]
async fn paging_identity_total_or_token_conflicts_preserve_the_last_valid_page() {
    let rpc = FixtureRpc::new().await;
    for next in [
        page(json!([user("member-user")]), json!(2), Value::Null),
        page(json!([user("admin-user")]), json!(3), Value::Null),
        page(json!([user("admin-user")]), json!(2), json!("next")),
        json!({"Code":"InternalError","RequestId":"second-page-failed"}),
    ] {
        rpc.cloud
            .lock()
            .unwrap()
            .user_pages
            .extend([(200, page(json!([user("member-user")]), json!(2), json!("next"))), (200, next)]);
        let first = result(rpc.f.users(json!({})).await);
        let rejected = rpc.f.users(json!({"cursor":first["nextCursor"]})).await;
        assert!(!rejected.status.is_success(), "{}", rejected.text);
        let retained = rpc.f.list().await["userDirectory"].clone();
        assert_eq!(retained["snapshotId"], first["snapshotId"]);
        assert_eq!(retained["items"], first["items"]);
        assert_eq!(retained["complete"], false);
        assert_eq!(retained["selectionUsable"], false);
    }
}

#[tokio::test]
async fn cursors_are_bound_to_tenant_query_configuration_and_cannot_select_another_cloud_instance() {
    let rpc = FixtureRpc::new().await;
    rpc.cloud.lock().unwrap().user_pages.push_back((200, page(json!([user("member-user")]), json!(2), json!("next"))));
    let first = result(rpc.f.users(json!({"name_like":"user"})).await);
    let cursor = first["nextCursor"].as_str().unwrap();
    let calls = rpc.actions().await.len();
    let foreign = scoped(
        &rpc.f.h,
        rpc.f.h.other_tenant,
        "POST",
        &format!("{BASE}/users/observe"),
        Some(json!({
        "request_id":Id::new(),"configuration_version":1,"confirm_live":true,"cursor":cursor,"name_like":"user"})),
    )
    .await;
    assert!(!foreign.status.is_success());
    let changed = rpc.f.users(json!({"cursor":cursor,"name_like":"admin"})).await;
    assert_eq!(changed.status, StatusCode::CONFLICT);
    let invalid = rpc.f.users(json!({"cursor":"untrusted-provider-token"})).await;
    assert_eq!(invalid.status, StatusCode::CONFLICT);
    assert_eq!(rpc.actions().await.len(), calls, "invalid cursors must fail before calling ListUsers");
    let empty = result(rpc.f.users(json!({"name_like":"no-match"})).await);
    assert_eq!(empty["items"], json!([]));
    assert_eq!(empty["directoryComplete"], false);
    let mut body = preview_body(replace(TEAM, json!(["member-user", "admin-user"])), 0, true);
    body["user_snapshot_id"] = empty["snapshotId"].clone();
    let preview = result(rpc.f.h.post(&format!("{BASE}/previews"), body).await);
    assert_eq!(preview["before"]["memberNames"], json!(["member-user"]));
    assert_eq!(preview["removedMembers"], json!([]), "an old member need not be loaded in a filtered picker page");
    assert_eq!(preview["addedMembers"], json!(["admin-user"]));
    assert_eq!(preview["verifiedUsers"].as_array().unwrap().len(), 2, "all selected users are independently rechecked");
}
