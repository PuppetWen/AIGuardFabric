//! Complete local Mock workflow; these definitions do not claim a cloud execution.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod privatelink_provisioning_support;
use agf_core::{credential::SecretMaterial, error::DomainResult, ids::Id, time::Timestamp};
use common::*;
use privatelink_provisioning_support as p;
use secrecy::ExposeSecret;
#[tokio::test]
async fn state_and_original_receipts_are_pure_and_never_seed() -> DomainResult<()> {
    let h = setup().await;
    let before = p::snapshot(&h).await?;
    let s = p::get(&h, p::BASE).await?;
    assert!(s["source"].is_null());
    assert!(p::snapshot(&h).await? == before, "GET changed immutable snapshot");
    p::configure(&h, 0, true, "consumer").await?;
    let before = p::snapshot(&h).await?;
    let s = p::get(&h, p::BASE).await?;
    assert_eq!(s["generation"], 0);
    assert_eq!(s["source"]["accountIdentityVerified"], false);
    assert!(p::snapshot(&h).await? == before, "configured GET seeded provider");
    assert_eq!(h.get(&format!("{}/requests/{}", p::BASE, Id::new())).await.status, StatusCode::NOT_FOUND);
    Ok(())
}
#[tokio::test]
async fn explicit_create_observe_separate_accept_and_observe_have_two_writes() -> DomainResult<()> {
    let h = setup().await;
    p::configure(&h, 0, true, "consumer").await?;
    let (original, input, receipt) = p::created(&h, true).await?;
    let observed = p::observe(&h, original).await?;
    assert_eq!(observed["result"]["connectionState"], "Connecting");
    let accept =
        p::preview(&h, json!({"action":"accept","observation_request_id":p::id(&observed,"requestId")?})).await?;
    let body = p::apply_body(&h, p::id(&accept, "requestId")?, Id::new(), false).await?;
    let applied = p::post(&h, &format!("{}/apply", p::BASE), body).await?;
    assert_eq!(applied["action"], "EnableVpcEndpointConnection");
    let after = p::observe(&h, p::id(&applied, "requestId")?).await?;
    assert_eq!(after["result"]["connectionState"], "Connected");
    assert_eq!(after["connectivityVerified"], false);
    assert_eq!(p::mock_counts(&h).await?, (2, 2));
    let before = p::snapshot(&h).await?;
    assert!(p::post(&h, &format!("{}/apply", p::BASE), input).await? == receipt, "replay changed original receipt");
    assert!(p::snapshot(&h).await? == before, "replay wrote new facts/audit");
    p::chain(&h).await
}
#[tokio::test]
async fn enterprise_existing_cross_region_reference_is_not_a_create_payload() -> DomainResult<()> {
    let h = setup().await;
    p::configure(&h, 0, true, "consumer").await?;
    let observed = p::imported(&h).await?;
    assert!(observed["action"].is_null());
    assert_eq!(observed["result"]["serviceRegion"], "cn-beijing");
    let id = p::id(&observed, "requestId")?;
    let sealed = h.state.configurations.get::<Value>(h.tenant, "privatelink-provisioning-fact", id).await?.unwrap();
    let clear = p::clear(&h, &sealed)?;
    assert!(clear["intent"].is_null());
    assert!(clear["result"]["evidence"]["plan"]["cross_region_bandwidth"].is_null());
    assert_eq!(clear["source"]["version"], 1);
    assert!(clear["result"]["evidence"]["inventory_payload_hash"].is_string());
    p::configure(&h, 1, true, "provider").await?;
    let preview = p::preview(&h, json!({"action":"accept","observation_request_id":id})).await?;
    assert_eq!(preview["originalSource"]["configurationVersion"], 2);
    assert!(preview["resourceSummary"]["crossRegionBandwidth"].is_null());
    let body = p::apply_body(&h, p::id(&preview, "requestId")?, Id::new(), true).await?;
    let accepted = p::post(&h, &format!("{}/apply", p::BASE), body).await?;
    assert_eq!(accepted["result"]["endpointId"], "ep-agf-demo");
    assert_eq!(p::mock_counts(&h).await?, (1, 0));
    p::chain(&h).await
}
#[tokio::test]
async fn cas_confirmations_uuid_body_and_read_permissions_are_strict() -> DomainResult<()> {
    let h = setup().await;
    p::configure(&h, 0, true, "consumer").await?;
    let preview = p::preview(&h, json!({"action":"create","target":p::target()})).await?;
    let body = p::apply_body(&h, p::id(&preview, "requestId")?, Id::new(), true).await?;
    let before = p::snapshot(&h).await?;
    for field in ["confirm_resources_and_cost", "confirm_current_role", "confirm_no_connectivity_proof"] {
        let mut bad = body.clone();
        bad[field] = json!(false);
        assert_eq!(h.post(&format!("{}/apply", p::BASE), bad).await.status, StatusCode::PRECONDITION_FAILED);
    }
    let mut bad = body.clone();
    bad["expected_generation"] = json!(0);
    assert_eq!(h.post(&format!("{}/apply", p::BASE), bad).await.status, StatusCode::CONFLICT);
    assert!(p::snapshot(&h).await? == before, "rejected draft mutated provider");
    let accepted = p::post(&h, &format!("{}/apply", p::BASE), body.clone()).await?;
    let mut bad = body;
    bad["preview_id"] = json!(Id::new());
    assert_eq!(h.post(&format!("{}/apply", p::BASE), bad).await.status, StatusCode::CONFLICT);
    assert_eq!(
        h.request("GET", &format!("{}/requests/{}", p::BASE, p::id(&accepted, "requestId")?), Some(&h.viewer), None)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    Ok(())
}
#[tokio::test]
async fn archive_keeps_permanent_original_fact_and_no_redispatch() -> DomainResult<()> {
    let h = setup().await;
    p::configure(&h, 0, true, "consumer").await?;
    let (id, input, _) = p::created(&h, true).await?;
    let state = p::get(&h, p::BASE).await?;
    let request = Id::new();
    let body = json!({"request_id":request,"expected_generation":p::n(&state,"generation")?,"request_ids":[id]});
    let a = p::post(&h, &format!("{}/archive", p::BASE), body.clone()).await?;
    assert_eq!(a["result"]["changedCount"], 1);
    let before = p::snapshot(&h).await?;
    let original = p::get(&h, &format!("{}/requests/{id}", p::BASE)).await?;
    assert_eq!(original["archived"], true);
    assert_eq!(original["result"]["delivery"], "acknowledged");
    p::post(&h, &format!("{}/apply", p::BASE), input).await?;
    p::post(&h, &format!("{}/archive", p::BASE), body).await?;
    assert!(p::snapshot(&h).await? == before, "permanent replay changed storage");
    assert_eq!(p::mock_counts(&h).await?, (1, 0));
    p::chain(&h).await
}
#[tokio::test]
async fn disabled_source_changes_only_current_projection_and_does_not_hide_history() -> DomainResult<()> {
    let h = setup().await;
    p::configure(&h, 0, true, "consumer").await?;
    let (id, input, old) = p::created(&h, true).await?;
    p::configure(&h, 1, false, "consumer").await?;
    let before = p::snapshot(&h).await?;
    let current = p::get(&h, &format!("{}/requests/{id}", p::BASE)).await?;
    assert_eq!(current["sourceCurrent"], false);
    assert_eq!(current["originalSource"], old["originalSource"]);
    assert_eq!(current["result"], old["result"]);
    assert!(
        p::post(&h, &format!("{}/apply", p::BASE), input).await? == current,
        "disabled replay changed original result"
    );
    assert!(p::snapshot(&h).await? == before, "pure history changed storage");
    Ok(())
}

// 从真实成功 sync 的加密记录构造确定的时间夹具；只改时间，不伪造资源、页数或 scope。
async fn inventory_time_fixture(h: &Harness, record: &Value, snapshot: &Value, request: Id) -> DomainResult<()> {
    let id = agf_api::integration_store::id(h.tenant, "alicloud-privatelink");
    let mut row = record.clone();
    row["snapshot"] = serde_json::to_value(agf_api::model_gateway::encrypt(
        &h.state,
        h.tenant,
        id,
        serde_json::to_string(snapshot)?,
    )?)?;
    row["runs"][request.to_string()]["started_at"] = snapshot["started_at"].clone();
    row["runs"][request.to_string()]["finished_at"] = snapshot["checked_at"].clone();
    h.state.configurations.put(h.tenant, "privatelink-inventory", id, &row).await
}

#[tokio::test]
async fn inventory_selection_accepts_separate_observation_times_and_rejects_outside_the_successful_run()
-> DomainResult<()> {
    let h = setup().await;
    p::configure(&h, 0, true, "consumer").await?;
    let version = p::n(&p::get(&h, p::BASE).await?["source"], "configurationVersion")?;
    let request = Id::new();
    let sync = p::post(
        &h,
        "/api/v1/alicloud/privatelink/inventory/sync",
        json!({
            "request_id":request,"configuration_version":version,"confirm_live":false,
        }),
    )
    .await?;
    assert_eq!(sync["status"], "succeeded");
    assert_eq!(sync["published"], true);
    // 首先验真实 sync 产物的公开选择，不依赖下面人为设置的时间夹具。
    let available = p::get(&h, p::BASE).await?;
    let scope = p::id(&available["inventorySelection"], "scopeId")?;
    let id = agf_api::integration_store::id(h.tenant, "alicloud-privatelink");
    let original: Value = h.state.configurations.get(h.tenant, "privatelink-inventory", id).await?.unwrap();
    let encrypted: SecretMaterial = serde_json::from_value(original["snapshot"].clone())?;
    let clear = agf_api::model_gateway::cipher(&h.state)?.decrypt(&encrypted)?;
    let mut baseline: Value = serde_json::from_str(clear.expose_secret())?;
    let checked = Timestamp::now().offset_secs(-1);
    let started = checked.offset_secs(-10);
    baseline["started_at"] = json!(started);
    baseline["checked_at"] = json!(checked);
    baseline["endpoint"]["observed_at"] = json!(checked.offset_secs(-8));
    for zone in baseline["zones"].as_array_mut().unwrap() {
        zone["observed_at"] = json!(checked.offset_secs(-4));
    }
    for group in baseline["security_groups"].as_array_mut().unwrap() {
        group["observed_at"] = json!(checked.offset_secs(-2));
    }
    inventory_time_fixture(&h, &original, &baseline, request).await?;
    assert_eq!(p::get(&h, p::BASE).await?["inventorySelection"]["scopeId"], json!(scope));
    let accepted = p::post(
        &h,
        &format!("{}/observe", p::BASE),
        json!({
            "request_id":Id::new(),"configuration_version":version,"inventory_scope_id":scope,
        }),
    )
    .await?;
    assert_eq!(accepted["result"]["serviceRegion"], "cn-beijing");
    assert_eq!(accepted["result"]["inventoryScopeId"], json!(scope));
    let facts: Vec<Value> = h.state.configurations.list(h.tenant, "privatelink-provisioning-fact").await?;
    for pointer in ["/endpoint/observed_at", "/zones/0/observed_at", "/security_groups/0/observed_at"] {
        for at in [started.offset_secs(-1), checked.offset_secs(1)] {
            let mut outside = baseline.clone();
            *outside.pointer_mut(pointer).unwrap() = json!(at);
            inventory_time_fixture(&h, &original, &outside, request).await?;
            assert!(p::get(&h, p::BASE).await?["inventorySelection"].is_null(), "{pointer} {at}");
            let rejected = h
                .post(
                    &format!("{}/observe", p::BASE),
                    json!({
                        "request_id":Id::new(),"configuration_version":version,"inventory_scope_id":scope,
                    }),
                )
                .await;
            assert_eq!(rejected.status, StatusCode::PRECONDITION_FAILED, "{}", rejected.text);
            let after: Vec<Value> = h.state.configurations.list(h.tenant, "privatelink-provisioning-fact").await?;
            assert_eq!(after, facts, "拒绝越界观测不能创建或覆盖原事实");
        }
    }
    inventory_time_fixture(&h, &original, &baseline, request).await?;
    assert_eq!(p::get(&h, p::BASE).await?["inventorySelection"]["scopeId"], json!(scope));
    // 不能借用结束时间相同、但起点不同的成功 run 作为发布证明。
    let mut mismatch: Value = h.state.configurations.get(h.tenant, "privatelink-inventory", id).await?.unwrap();
    mismatch["runs"][request.to_string()]["started_at"] = json!(started.offset_secs(-1));
    h.state.configurations.put(h.tenant, "privatelink-inventory", id, &mismatch).await?;
    assert!(p::get(&h, p::BASE).await?["inventorySelection"].is_null());
    let rejected = h
        .post(
            &format!("{}/observe", p::BASE),
            json!({
                "request_id":Id::new(),"configuration_version":version,"inventory_scope_id":scope,
            }),
        )
        .await;
    assert_eq!(rejected.status, StatusCode::PRECONDITION_FAILED, "{}", rejected.text);
    let after: Vec<Value> = h.state.configurations.list(h.tenant, "privatelink-provisioning-fact").await?;
    assert_eq!(after, facts, "不匹配的成功 run 不能发布原事实");
    inventory_time_fixture(&h, &original, &baseline, request).await?;
    p::chain(&h).await
}
