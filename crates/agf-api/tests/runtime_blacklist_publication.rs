//! Actual authenticated writes require CAS and append exactly one audit with their configuration.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::error::DomainResult;
use common::*;

async fn create(h: &Harness) -> Value {
    let response = h
        .post(
            "/api/v1/runtime/blacklists",
            json!({"kind":"command",
        "pattern":"owned-cas-command","action":"deny","scope":"tenant"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()
}

#[tokio::test]
async fn concurrent_toggles_have_one_winner_and_stale_delete_cannot_erase_it() -> DomainResult<()> {
    let h = setup().await;
    let created = create(&h).await;
    assert_eq!(created["version"], 1);
    let id = created["id"].as_str().unwrap();
    let uri = format!("/api/v1/runtime/blacklists/{id}");
    let before = h.state.store.audit_stats_durable(h.tenant).await?;
    let body = json!({"enabled":false,"expected_version":1});
    let (left, right) = tokio::join!(
        h.request("PATCH", &uri, Some(&h.admin), Some(body.clone())),
        h.request("PATCH", &uri, Some(&h.admin), Some(body))
    );
    let statuses = [left.status, right.status];
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let rows = h.get("/api/v1/runtime/blacklists").await.json();
    let row = rows.as_array().unwrap().iter().find(|row| row["id"] == id).unwrap();
    assert_eq!(row["enabled"], false);
    assert_eq!(row["version"], 2);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?.0, before.0 + 1);
    let current = h.state.configurations.list::<Value>(h.tenant, "runtime-blacklists").await?;
    let audits = h.state.store.audit_stats_durable(h.tenant).await?;
    assert_eq!(
        h.request("DELETE", &format!("{uri}?expected_version=1"), Some(&h.admin), None).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "runtime-blacklists").await?, current);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, audits);
    assert_eq!(
        h.request("DELETE", &format!("{uri}?expected_version=2"), Some(&h.admin), None).await.status,
        StatusCode::OK
    );
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?.0, audits.0 + 1);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn missing_versions_readonly_and_foreign_writes_preserve_current_configuration() -> DomainResult<()> {
    let h = setup().await;
    let created = create(&h).await;
    let id = created["id"].as_str().unwrap();
    let uri = format!("/api/v1/runtime/blacklists/{id}");
    let before = h.state.configurations.list::<Value>(h.tenant, "runtime-blacklists").await?;
    let audits = h.state.store.audit_stats_durable(h.tenant).await?;
    assert_eq!(
        h.request("PATCH", &uri, Some(&h.admin), Some(json!({"enabled":false}))).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(h.request("DELETE", &uri, Some(&h.admin), None).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        h.request("PATCH", &uri, Some(&h.viewer), Some(json!({"enabled":false,"expected_version":1}))).await.status,
        StatusCode::FORBIDDEN
    );
    let authorization = format!("Bearer {}", h.admin);
    let foreign = h.other_tenant.to_string();
    let response = h
        .request_with(
            "PATCH",
            &uri,
            &[("Authorization", &authorization), ("X-AGF-Tenant", &foreign)],
            Some(json!({"enabled":false,"expected_version":1})),
        )
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "runtime-blacklists").await?, before);
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, audits);
    Ok(())
}

#[tokio::test]
async fn existing_unversioned_registry_is_adopted_at_version_zero_without_losing_other_rules() -> DomainResult<()> {
    let h = setup().await;
    let rows = h.get("/api/v1/runtime/blacklists").await.json();
    let id = rows[0]["id"].as_str().unwrap();
    assert_eq!(rows[0]["version"], 0);
    let uri = format!("/api/v1/runtime/blacklists/{id}");
    let response = h.request("PATCH", &uri, Some(&h.admin), Some(json!({"enabled":false,"expected_version":0}))).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["version"], 1);
    let mut stored = h.state.configurations.list::<Value>(h.tenant, "runtime-blacklists").await?.remove(0);
    for row in stored["rules"].as_array_mut().unwrap() {
        row.as_object_mut().unwrap().remove("version");
    }
    let record = agf_core::ids::Id::from_uuid(h.tenant.as_uuid());
    h.state.configurations.put(h.tenant, "runtime-blacklists", record, &stored).await?;
    let response = h.request("PATCH", &uri, Some(&h.admin), Some(json!({"enabled":true,"expected_version":0}))).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["version"], 1);
    let after = h.get("/api/v1/runtime/blacklists").await.json();
    assert_eq!(after.as_array().unwrap().len(), rows.as_array().unwrap().len());
    Ok(())
}
