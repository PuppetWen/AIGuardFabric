//! Owned SQL only: actual Key middleware constraints, CAS, irreversible governance and audit rollback.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod agentteams_role_authority_database_support;
mod common;
use agentteams_role_authority_database_support::*;
use agf_core::ids::Id;
use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires dedicated owner-checked AgentTeams role authority PostgreSQL"]
async fn two_instances_commit_one_adoption_and_replay_does_not_expand_or_reaudit_key_scopes() {
    let case = Case::open("role-concurrent").await;
    let worker = prepare(&case.h).await;
    let broad = key(&case.h, Some(worker.asset), &["*"]).await;
    let narrow = key(&case.h, Some(worker.asset), &["models:read"]).await;
    let other = case.second().await;
    let before = case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap();
    let left = worker.draft.clone();
    let mut right = left.clone();
    right["request_id"] = json!(Id::new());
    let (a, b) = tokio::join!(save(&case.h, &worker, left.clone()), save(&other, &worker, right.clone()));
    assert_eq!([a.status, b.status].iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!([a.status, b.status].iter().filter(|s| **s == StatusCode::CONFLICT).count(), 1);
    let (winner, draft) = if a.status == StatusCode::OK { (a, left) } else { (b, right) };
    let after = case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap();
    assert_eq!(after.0, before.0 + 1);
    let repeated = save(&other, &worker, draft.clone()).await;
    assert_eq!(repeated.status, StatusCode::OK);
    assert_eq!(repeated.json(), winner.json());
    assert_eq!(case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap(), after);
    let mut reused = draft;
    reused["change"] = json!({"action":"disable"});
    assert_eq!(save(&other, &worker, reused).await.status, StatusCode::CONFLICT);
    assert_eq!(other.request("GET", "/api/v1/assets", Some(&broad), None).await.status, StatusCode::OK);
    assert_eq!(other.request("GET", "/api/v1/quotas", Some(&broad), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(other.get(BASE).await.json()["mappedCount"], 1);
    assert_eq!(other.request("GET", "/api/v1/assets", Some(&narrow), None).await.status, StatusCode::FORBIDDEN);
    let raw = case.h.state.store.api_key_list_durable(case.h.tenant).await.unwrap();
    assert!(
        raw.iter().any(|key| key.bound_agent_id == Some(worker.asset) && key.scopes == vec![Permission::from_raw("*")])
    );
    assert!(case.h.state.store.audit_verify_durable(case.h.tenant).await.unwrap().passed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires dedicated owner-checked AgentTeams role authority PostgreSQL"]
async fn failed_first_adoption_rolls_back_marker_mapping_intent_and_success_audit() {
    let case = Case::open("role-rollback").await;
    let worker = prepare(&case.h).await;
    let before = case.snapshot().await;
    let asset = case.h.state.store.asset_get_durable(case.h.tenant, worker.asset).await.unwrap().unwrap();
    assert!(!asset.attributes.contains_key(MARKER));
    case.fault(|| async {
        assert!(!save(&case.h, &worker, worker.draft.clone()).await.status.is_success());
        assert_eq!(case.snapshot().await, before);
        let current = case.h.state.store.asset_get_durable(case.h.tenant, worker.asset).await.unwrap().unwrap();
        assert_eq!(current.attributes, asset.attributes);
    })
    .await;
    assert_eq!(save(&case.h, &worker, worker.draft.clone()).await.status, StatusCode::OK);
    let second = case.second().await;
    assert_eq!(second.get(&format!("{BASE}/{}", worker.asset)).await.json()["governed"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires dedicated owner-checked AgentTeams role authority PostgreSQL"]
async fn disable_or_missing_mapping_never_restores_wide_key_even_after_snapshot_refresh() {
    let case = Case::open("role-disable").await;
    let worker = prepare(&case.h).await;
    assert_eq!(save(&case.h, &worker, worker.draft.clone()).await.status, StatusCode::OK);
    let token = key(&case.h, Some(worker.asset), &["*"]).await;
    let disabled = save(&case.h, &worker, disable(1)).await;
    assert_eq!(disabled.status, StatusCode::OK);
    assert_eq!(disabled.json()["original"]["eligibility"], "disabled");
    assert_eq!(case.h.get(BASE).await.json()["mappedCount"], 0);
    assert_eq!(case.h.request("GET", "/api/v1/assets", Some(&token), None).await.status, StatusCode::FORBIDDEN);
    let refreshed = case
        .h
        .post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false}),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK);
    assert_eq!(case.h.get(&format!("{BASE}/{}", worker.asset)).await.json()["eligibility"], "disabled");
    // Explicit destructive fixture demonstrates fail-closed loss of one side, never permission restoration.
    case.check().await;
    sqlx::query("UPDATE console_configurations SET deleted_at=now() WHERE tenant_id=$1 AND kind=$2 AND id=$3")
        .bind(case.h.tenant.as_uuid())
        .bind(KIND)
        .bind(worker.asset.as_uuid())
        .execute(&case.pool)
        .await
        .unwrap();
    let second = case.second().await;
    assert_eq!(second.request("GET", "/api/v1/assets", Some(&token), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(second.get(BASE).await.json()["mappedCount"], 0);
    assert_eq!(
        second.state.store.asset_get_durable(case.h.tenant, worker.asset).await.unwrap().unwrap().attributes[MARKER],
        true
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires dedicated owner-checked AgentTeams role authority PostgreSQL"]
async fn foreign_role_or_worker_and_read_only_admin_endpoint_requests_cannot_adopt_or_mutate() {
    let case = Case::open("role-isolation").await;
    let worker = prepare(&case.h).await;
    let foreign = case.foreign().await;
    let foreign_view = foreign.get(BASE).await.json();
    let foreign_role =
        foreign_view["roles"].as_array().unwrap().iter().find(|role| role["name"] == "viewer").unwrap()["id"].clone();
    let mut input = worker.draft.clone();
    input["change"]["role_id"] = foreign_role;
    let before = case.snapshot().await;
    assert_eq!(save(&case.h, &worker, input).await.status, StatusCode::FORBIDDEN);
    assert_eq!(save(&foreign, &worker, worker.draft.clone()).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        case.h
            .request("PUT", &format!("{BASE}/{}", worker.asset), Some(&case.h.viewer), Some(worker.draft.clone()))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(case.h.get(BASE).await.status, StatusCode::OK);
    assert_eq!(case.h.get(&format!("{BASE}/{}", worker.asset)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(case.snapshot().await, before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires dedicated owner-checked AgentTeams role authority PostgreSQL"]
async fn current_department_source_revision_and_key_revocation_are_rechecked_from_durable_state() {
    let case = Case::open("role-fresh").await;
    let worker = prepare(&case.h).await;
    assert_eq!(save(&case.h, &worker, worker.draft.clone()).await.status, StatusCode::OK);
    let token = key(&case.h, Some(worker.asset), &["*"]).await;
    let second = case.second().await;
    assert_eq!(second.request("GET", "/api/v1/assets", Some(&token), None).await.status, StatusCode::OK);
    let asset = case.h.state.store.asset_get_durable(case.h.tenant, worker.asset).await.unwrap().unwrap();
    let changed=case.h.request("PATCH",&format!("/api/v1/assets/{}",worker.asset),Some(&case.h.admin),
        Some(json!({"name":asset.name,"owner":"owned-admin","department":"new-department","data_class":"confidential",
            "expected_updated_at":asset.updated_at,"reason":"owned metadata authority regression"}))).await;
    assert_eq!(changed.status, StatusCode::OK);
    assert_eq!(second.request("GET", "/api/v1/assets", Some(&token), None).await.status, StatusCode::FORBIDDEN);
    let cfg = case.h.get(CONFIG).await.json();
    let saved = case
        .h
        .request(
            "PUT",
            CONFIG,
            Some(&case.h.admin),
            Some(json!({"enabled":false,"mock":true,
        "expected_version":1,"settings":cfg["settings"],"secrets":{},"clear_secrets":[]})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    assert_eq!(second.request("GET", "/api/v1/assets", Some(&token), None).await.status, StatusCode::FORBIDDEN);
    // Disabled source does not prevent the administrator retaining a permanent local disable fact.
    assert_eq!(save(&case.h, &worker, disable(1)).await.status, StatusCode::OK);
    let original_key = case.h.state.verify_api_key(&token, None).await.unwrap();
    let revoked = case
        .h
        .request("DELETE", &format!("/api/v1/settings/api-keys/{}", original_key.id), Some(&case.h.admin), None)
        .await;
    assert_eq!(revoked.status, StatusCode::OK);
    assert_eq!(second.request("GET", "/api/v1/assets", Some(&token), None).await.status, StatusCode::UNAUTHORIZED);
}
