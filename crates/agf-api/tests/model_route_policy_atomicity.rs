//! Actual HTTP configuration, version-zero seed adoption and read-only endpoint prerequisites.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{error::DomainResult, ids::Id};
use common::*;

async fn endpoint(h: &Harness, index: usize) -> Id {
    let response = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":format!("route-{index}"),
        "provider":"mock","model":format!("route-{index}"),"base_url":"http://mock.invalid/v1"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    serde_json::from_value(response.json()["id"].clone()).unwrap()
}

#[tokio::test]
async fn route_partial_edit_has_one_success_audit_and_stale_or_readonly_edit_changes_nothing() -> DomainResult<()> {
    let h = setup().await;
    let source = endpoint(&h, 0).await;
    let id = Id::new();
    let uri = format!("/api/v1/models/route-policies/{id}");
    let body = json!({"name":"original","primaryEndpointId":source,"enabled":true});
    let sources = h.state.configurations.list::<Value>(h.tenant, "model-endpoint").await?;
    let initial = h.request("PUT", &uri, Some(&h.admin), Some(body.clone())).await;
    assert_eq!(initial.status, StatusCode::OK);
    assert_eq!(initial.json()["version"], 1);
    let before = h.state.store.audit_stats_durable(h.tenant).await?;
    let edit = h.request("PUT", &uri, Some(&h.admin), Some(json!({"expectedVersion":1,"enabled":false}))).await;
    assert_eq!(edit.status, StatusCode::OK);
    assert_eq!(edit.json()["name"], "original");
    assert_eq!(edit.json()["version"], 2);
    let after = h.state.store.audit_stats_durable(h.tenant).await?;
    assert_eq!(after.0, before.0 + 1);
    let persisted = h.state.configurations.list::<Value>(h.tenant, "model-route-policy").await?;
    assert_eq!(
        h.request("PUT", &uri, Some(&h.admin), Some(json!({"expectedVersion":1,"enabled":true}))).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(h.request("PUT", &uri, Some(&h.viewer), Some(body)).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "model-route-policy").await?, persisted);
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "model-endpoint").await?, sources);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, after);
    assert!(!h.state.store.route_policy_get(h.tenant, id)?.unwrap().enabled);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn adopting_actual_version_zero_seed_supports_thirty_three_sources_without_writing_them() -> DomainResult<()> {
    let h = setup().await;
    let mut ids = Vec::new();
    for index in 0..33 {
        ids.push(endpoint(&h, index).await);
    }
    let id = Id::new();
    h.state.store.route_policy_upsert(&agf_api::store::ModelRoutePolicy {
        version: 0,
        id,
        tenant_id: h.tenant,
        name: "version-zero-seed".into(),
        primary_endpoint_id: ids[0].to_string(),
        fallback_endpoint_ids: ids[1..].iter().map(ToString::to_string).collect(),
        strategy: "priority".into(),
        weights: BTreeMap::new(),
        budget_cny_per_day: 0.0,
        enabled: true,
    })?;
    let before = h.state.configurations.list::<Value>(h.tenant, "model-endpoint").await?;
    let stats = h.state.store.audit_stats_durable(h.tenant).await?;
    let response = h
        .request(
            "PUT",
            &format!("/api/v1/models/route-policies/{id}"),
            Some(&h.admin),
            Some(json!({"expectedVersion":0,"name":"adopted"})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["fallback_endpoint_ids"].as_array().unwrap().len(), 32);
    assert_eq!(response.json()["version"], 1);
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "model-endpoint").await?, before);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?.0, stats.0 + 1);
    Ok(())
}

#[tokio::test]
async fn endpoint_payload_with_wrong_tenant_is_not_accepted_as_a_reference_or_audited() -> DomainResult<()> {
    let h = setup().await;
    let endpoint = endpoint(&h, 0).await;
    let mut row = h.state.configurations.get::<Value>(h.tenant, "model-endpoint", endpoint).await?.unwrap();
    row["endpoint"]["tenant_id"] = json!(h.other_tenant);
    h.state.configurations.put(h.tenant, "model-endpoint", endpoint, &row).await?;
    let stats = h.state.store.audit_stats_durable(h.tenant).await?;
    let response =
        h.post("/api/v1/models/route-policies", json!({"name":"must-not-commit","primaryEndpointId":endpoint})).await;
    assert!(response.status.is_server_error());
    assert!(h.state.configurations.list::<Value>(h.tenant, "model-route-policy").await?.is_empty());
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, stats);
    Ok(())
}
