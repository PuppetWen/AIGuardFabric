//! Every cloud operation checks configuration and current authority after queue/STS waits.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod cloud_dispatch_support;
mod common;
use agf_core::ids::Id;
use cloud_dispatch_support::*;
use common::*;

#[tokio::test]
async fn configuration_changes_while_queued_prevent_stale_provider_dispatch() {
    for change in ["disabled", "endpoint", "account", "mode", "revision"] {
        let mut f = Fixture::new("DescribeAlertHistoryList", false).await;
        let blocker = tokio::spawn(blocking(f.h.clone()));
        f.wait("DescribeAlertHistoryList").await;
        let id = Id::new();
        let queued = tokio::spawn(pending(f.h.clone(), f.h.admin.clone(), id));
        f.claimed(id).await;
        let mut settings = f.settings.clone();
        if change == "endpoint" {
            settings["endpoint"] = json!("http://127.0.0.1:9");
        }
        if change == "account" {
            settings["account_id"] = json!("new-account");
        }
        f.change(settings, change != "disabled", change == "mode").await;
        f.gate.add_permits(1);
        assert_eq!(blocker.await.unwrap().status, StatusCode::OK);
        let response = queued.await.unwrap();
        failed(&response);
        assert_eq!(f.count(), 0, "queued {change} call reached the provider");
        let restored = f.h.get(&format!("{PATH}/operations/{}", response.json()["id"].as_str().unwrap())).await;
        assert_eq!(restored.json(), response.json());
    }
}

#[tokio::test]
async fn changing_configuration_during_sts_resolution_prevents_provider_write() {
    let mut f = Fixture::new("AssumeRole", true).await;
    let id = Id::new();
    let operation = tokio::spawn(pending(f.h.clone(), f.h.admin.clone(), id));
    f.wait("AssumeRole").await;
    f.change(f.settings.clone(), false, false).await;
    f.gate.add_permits(1);
    failed(&operation.await.unwrap());
    assert_eq!(f.sts.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(f.count(), 0);
}

#[tokio::test]
async fn revoking_an_already_authenticated_key_while_queued_prevents_cloud_write() {
    let mut f = Fixture::new("DescribeAlertHistoryList", false).await;
    let issued =
        f.h.post(
            "/api/v1/settings/api-keys",
            json!({"name":"cloud-dispatch",
        "scopes":["alicloud:write"]}),
        )
        .await;
    assert_eq!(issued.status, StatusCode::CREATED);
    let key = issued.json()["plaintext"].as_str().unwrap().to_owned();
    let key_id = issued.json()["api_key"]["id"].as_str().unwrap().to_owned();
    let blocker = tokio::spawn(blocking(f.h.clone()));
    f.wait("DescribeAlertHistoryList").await;
    let id = Id::new();
    let queued = tokio::spawn(pending(f.h.clone(), key, id));
    f.claimed(id).await;
    let revoked = f.h.request("DELETE", &format!("/api/v1/settings/api-keys/{key_id}"), Some(&f.h.admin), None).await;
    assert!(revoked.status.is_success(), "{}", revoked.text);
    f.gate.add_permits(1);
    assert_eq!(blocker.await.unwrap().status, StatusCode::OK);
    failed(&queued.await.unwrap());
    assert_eq!(f.count(), 0);
    // A rejected local guard must not trip the cloud circuit for a current caller.
    for _ in 0..3 {
        let current = f.h.post(&format!("{PATH}/operations"), write(1, Id::new())).await;
        assert_eq!(current.json()["status"], "succeeded", "{}", current.text);
    }
    assert_eq!(f.count(), 3);
}

#[tokio::test]
async fn current_account_status_is_rechecked_after_sts_wait() {
    let mut f = Fixture::new("AssumeRole", true).await;
    let operation = tokio::spawn(pending(f.h.clone(), f.h.admin.clone(), Id::new()));
    f.wait("AssumeRole").await;
    let mut user = f.h.state.auth_backend.find_user_with_secret(f.h.tenant, "admin").await.unwrap().unwrap().user;
    user.state = agf_core::user::UserState::Disabled;
    f.h.state.auth_backend.save_user(&user, None).await.unwrap();
    f.gate.add_permits(1);
    failed(&operation.await.unwrap());
    assert_eq!(f.count(), 0);
}

#[tokio::test]
async fn authenticated_generic_entry_cannot_bypass_native_team_preview() {
    let h = setup().await;
    let path = "/api/v1/alicloud/connections/alicloud-agentteams";
    let saved = h
        .request(
            "PUT",
            path,
            Some(&h.admin),
            Some(json!({"expected_version":0,
        "enabled":true,"mock":true,"settings":{"instance_id":"owned-instance"},"secrets":{}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    for action in ["CreateTeam", "UpdateTeam", "DeleteTeam"] {
        let response = h
            .post(
                &format!("{path}/operations"),
                json!({"request_id":Id::new(),
            "configuration_version":1,"action":action,"parameters":{"Name":"owned-team"}}),
            )
            .await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED, "{}", response.text);
    }
}

#[tokio::test]
async fn raw_apig_policy_update_cannot_create_a_dispatch_claim_or_success_receipt() {
    let h = setup().await;
    let path = "/api/v1/alicloud/connections/alicloud-apig";
    let saved = h
        .request(
            "PUT",
            path,
            Some(&h.admin),
            Some(json!({
                "expected_version":0,"enabled":true,"mock":true,
                "settings":{"region_id":"cn-hangzhou"},"secrets":{}
            })),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let before = h.get(&format!("{path}/operations")).await;
    assert_eq!(before.status, StatusCode::OK);
    for limit in [1, 100, 2_147_483_647] {
        let response = h
            .post(
                &format!("{path}/operations"),
                json!({
                    "request_id":Id::new(),"configuration_version":1,"action":"UpdatePolicy",
                    "parameters":{"policyId":"owned-policy","body":{
                        "name":"owned policy","config":json!({"enable":true,"globalRules":[{
                            "limitType":"Global","limitMode":"RequestPerMinute","limitValue":limit
                        }]}).to_string()
                    }}
                }),
            )
            .await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED, "{}", response.text);
    }
    let after = h.get(&format!("{path}/operations")).await;
    assert_eq!(after.status, StatusCode::OK);
    assert_eq!(after.json(), before.json(), "denied raw writes must not create durable dispatch facts");
}
