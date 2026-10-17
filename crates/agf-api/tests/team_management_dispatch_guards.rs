//! Recheck current authority and configuration after the last asynchronous preflight.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod team_management_helpers;
mod team_management_loopback_helpers;
use agf_core::ids::Id;
use common::*;
use team_management_helpers::*;
use team_management_loopback_helpers::*;

async fn attempting(f: &Fixture) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let rows = f.h.state.configurations.list::<Value>(f.h.tenant, STATE_KIND).await.unwrap();
            if rows.iter().any(|row| {
                row["active"]["run"]
                    .as_str()
                    .is_some_and(|run| row["operations"][run]["cloud_write"]["status"] == "attempting")
            }) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn revoking_the_confirming_key_while_queued_prevents_its_already_authenticated_write() {
    let mut rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(update(TEAM, "Revoked principal cannot resume")).await);
    let before = snapshot(&rpc.f.h).await;
    let issued = result(
        rpc.f
            .h
            .post(
                "/api/v1/settings/api-keys",
                json!({"name":"native-team-queue",
        "scopes":["alicloud:read","alicloud:write","assets:write"]}),
            )
            .await,
    );
    let key = issued["plaintext"].as_str().unwrap().to_owned();
    let key_id = issued["api_key"]["id"].as_str().unwrap().to_owned();
    while rpc.observed.try_recv().is_ok() {}
    rpc.cloud.lock().unwrap().read_delay = Some("GetUser".into());
    let h = rpc.f.h.clone();
    let blocker = tokio::spawn(async move {
        h.post(
            &format!("{CLOUD}/operations"),
            json!({"request_id":Id::new(),
        "configuration_version":1,"confirm_live":true,"action":"GetUser","parameters":{"Name":"member-user"}}),
        )
        .await
    });
    rpc.wait_action("GetUser").await;
    let h = rpc.f.h.clone();
    let body = apply_body(&preview, Id::new(), true);
    let pending =
        tokio::spawn(async move { h.request("POST", &format!("{BASE}/operations"), Some(&key), Some(body)).await });
    attempting(&rpc.f).await;
    let revoked =
        rpc.f.h.request("DELETE", &format!("/api/v1/settings/api-keys/{key_id}"), Some(&rpc.f.h.admin), None).await;
    assert!(revoked.status.is_success(), "{}", revoked.text);
    result(blocker.await.unwrap());
    let completed = pending.await.unwrap();
    if completed.status.is_success() {
        assert_ne!(completed.json()["status"], "verified");
    }
    assert_eq!(
        rpc.write_count("UpdateTeam"),
        0,
        "authentication at request entry cannot authorize dispatch after revocation"
    );
    assert_eq!(snapshot(&rpc.f.h).await, before);
}

#[tokio::test]
async fn disabling_the_connection_during_get_team_preflight_is_checked_again_before_update() {
    let mut rpc = FixtureRpc::new().await;
    let preview = result(rpc.f.preview(update(TEAM, "Final preflight is not permission to dispatch")).await);
    let inventory = agf_api::cloud_inventory::load(&rpc.f.h.state, rpc.f.h.tenant).await.unwrap().unwrap();
    let mut asset = rpc.f.h.state.store.asset_get(rpc.f.h.tenant, inventory.assets["worker-demo"]).unwrap().unwrap();
    asset.owner = Some("preflight-manual-owner".into());
    asset.attributes.insert("manual-preflight-note".into(), json!("Keep this note"));
    rpc.f.h.state.store.asset_upsert(&asset).unwrap();
    let asset_ids: std::collections::BTreeSet<_> =
        rpc.f.h.state.store.asset_list_all(rpc.f.h.tenant).unwrap().into_iter().map(|asset| asset.id).collect();
    while rpc.observed.try_recv().is_ok() {}
    rpc.cloud.lock().unwrap().read_delay = Some("GetTeam".into());
    let h = rpc.f.h.clone();
    let body = apply_body(&preview, Id::new(), true);
    let pending = tokio::spawn(async move { h.post(&format!("{BASE}/operations"), body).await });
    rpc.wait_action("GetTeam").await;
    attempting(&rpc.f).await;
    let saved = rpc
        .f
        .h
        .request(
            "PUT",
            CLOUD,
            Some(&rpc.f.h.admin),
            Some(json!({"expected_version":1,
        "enabled":false,"mock":false,"settings":{"instance_id":INSTANCE,"account_id":"team-test-account",
        "endpoint":rpc.server.uri()},"secrets":{}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let disabled_snapshot = snapshot(&rpc.f.h).await;
    let completed = pending.await.unwrap();
    if completed.status.is_success() {
        assert_eq!(completed.json()["status"], "superseded");
    }
    assert_eq!(
        rpc.write_count("UpdateTeam"),
        0,
        "a read that began under the old configuration cannot authorize the later write"
    );
    assert_eq!(
        snapshot(&rpc.f.h).await,
        disabled_snapshot,
        "late preflight completion must not restore invalidated inventory"
    );
    let retained = rpc.f.h.state.store.asset_get(rpc.f.h.tenant, asset.id).unwrap().unwrap();
    assert_eq!(retained.owner, asset.owner);
    assert_eq!(retained.attributes["manual-preflight-note"], asset.attributes["manual-preflight-note"]);
    let remaining: std::collections::BTreeSet<_> =
        rpc.f.h.state.store.asset_list_all(rpc.f.h.tenant).unwrap().into_iter().map(|asset| asset.id).collect();
    assert_eq!(remaining, asset_ids);
}
