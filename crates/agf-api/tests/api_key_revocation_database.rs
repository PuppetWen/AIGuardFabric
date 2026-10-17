//! Opt-in owned SQL rollback/concurrency acceptance for HTTP and SOAR Key revocation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
use agf_core::{audit::AuditLog, ids::Id};
use common::*;
use configuration_audit_support::SqlCase;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

const PATH: &str = "/api/v1/settings/api-keys";

async fn owned_case(label: &str) -> SqlCase {
    // Refuse migrations and mutations until the independently created database proves ownership.
    let url = std::env::var("AGF_TEST_DATABASE_URL").expect("Set the owned isolated SQL database");
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let owner = std::env::var("AGF_KEY_AUDIT_DATABASE_OWNER").expect("Set the exact isolated database comment");
    let run_id = owner.strip_prefix("AIGuardFabric API Key audit SQL ").expect("Wrong database owner prefix");
    assert!(run_id.len() == 32 && run_id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    let actual: Option<String> = sqlx::query_scalar(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    pool.close().await;
    assert_eq!(actual.as_deref(), Some(owner.as_str()), "Database must belong to this test run");
    SqlCase::open(label).await
}

async fn issue(h: &Harness, name: &str) -> (Id, String) {
    let response = h.post(PATH, json!({"name":name,"scopes":["assets:read"]})).await;
    assert_eq!(response.status, StatusCode::CREATED);
    let body = response.json();
    (serde_json::from_value(body["api_key"]["id"].clone()).unwrap(), body["plaintext"].as_str().unwrap().to_owned())
}

async fn key_audits(h: &Harness, id: Id) -> Vec<AuditLog> {
    h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.target.kind == "api-key" && row.target.id.as_deref() == Some(id.to_string().as_str()))
        .collect()
}

async fn raw_key(case: &SqlCase, id: Id) -> Value {
    let mut tx = case.h.state.store.database().unwrap().db().begin_tenant(case.h.tenant).await.unwrap();
    let row = sqlx::query_scalar("SELECT to_jsonb(k) FROM api_keys k WHERE id=$1")
        .bind(id.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    row
}

async fn assert_private(h: &Harness, plaintext: &str) {
    let listed = h.get(PATH).await;
    assert_eq!(listed.status, StatusCode::OK);
    assert!(listed.json().get("plaintext").is_none() && !listed.text.contains(plaintext));
    let rows = h.state.store.api_key_list_durable(h.tenant).await.unwrap();
    let audit = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await.unwrap();
    assert!(!serde_json::to_string(&rows).unwrap().contains(plaintext));
    assert!(!serde_json::to_string(&audit).unwrap().contains(plaintext));
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
}

async fn release_faults(case: &SqlCase, faults: Vec<String>) {
    for name in faults {
        case.unblock_audit(&name).await;
    }
    case.pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned AGF_TEST_DATABASE_URL and exact AGF_KEY_AUDIT_DATABASE_OWNER"]
async fn http_key_mutations_roll_back_and_concurrent_instances_revoke_once() {
    let case = owned_case("key-http-atomic").await;
    let second = case.second_instance().await;
    let mut faults = Vec::new();
    let outcome = AssertUnwindSafe(async {
        let (id, plaintext) = issue(&case.h, "owned-http-key").await;
        assert!(second.state.verify_api_key(&plaintext, None).await.is_ok());
        let before = raw_key(&case, id).await;
        let chain = case.audit_stats().await;
        faults.push(case.block_audit().await);
        let failed = case.h.post(PATH, json!({"name":"must-not-publish","scopes":["assets:read"]})).await;
        assert!(failed.status.is_server_error());
        assert!(failed.json().get("plaintext").is_none());
        assert!(
            !second
                .state
                .store
                .api_key_list_durable(case.h.tenant)
                .await
                .unwrap()
                .iter()
                .any(|key| key.name == "must-not-publish")
        );
        assert!(
            !case.h.state.store.api_key_list(case.h.tenant).unwrap().iter().any(|key| key.name == "must-not-publish")
        );
        let failed = case.h.request("DELETE", &format!("{PATH}/{id}"), Some(&case.h.admin), None).await;
        assert!(failed.status.is_server_error());
        assert_eq!(raw_key(&case, id).await, before);
        assert_eq!(case.audit_stats().await, chain);
        assert!(second.state.verify_api_key(&plaintext, None).await.is_ok());
        case.unblock_audit(faults.last().unwrap()).await;
        faults.pop();

        let foreign = case.foreign_instance().await;
        let foreign_chain = foreign.state.store.audit_stats_durable(foreign.tenant).await.unwrap();
        assert_eq!(
            foreign.request("DELETE", &format!("{PATH}/{id}"), Some(&foreign.admin), None).await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(foreign.state.store.audit_stats_durable(foreign.tenant).await.unwrap(), foreign_chain);
        // This fresh key belongs to this tenant but cannot grant settings:admin to itself.
        assert_eq!(
            second.request("DELETE", &format!("{PATH}/{id}"), Some(&plaintext), None).await.status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(case.audit_stats().await, chain);
        let path = format!("{PATH}/{id}");
        let (a, b) = tokio::join!(
            case.h.request("DELETE", &path, Some(&case.h.admin), None),
            second.request("DELETE", &path, Some(&second.admin), None)
        );
        assert_eq!(a.status, StatusCode::OK);
        assert_eq!(b.status, StatusCode::OK);
        assert_eq!(key_audits(&second, id).await.len(), 2, "one issue and one successful revoke");
        assert!(second.state.verify_api_key(&plaintext, None).await.is_err());
        let after_chain = case.audit_stats().await;
        assert_eq!(after_chain.0, chain.0 + 1);
        // An unchanged repeat succeeds even while the audit dependency rejects new writes.
        faults.push(case.block_audit().await);
        assert_eq!(second.request("DELETE", &path, Some(&second.admin), None).await.status, StatusCode::OK);
        assert_eq!(case.audit_stats().await, after_chain);
        let fresh = case.second_instance().await;
        assert!(fresh.state.verify_api_key(&plaintext, None).await.is_err());
        assert_private(&fresh, &plaintext).await;
        assert!(!raw_key(&case, id).await.to_string().contains(&plaintext));
    })
    .catch_unwind()
    .await;
    release_faults(&case, faults).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned AGF_TEST_DATABASE_URL and exact AGF_KEY_AUDIT_DATABASE_OWNER"]
async fn soar_key_audit_failure_keeps_authentication_and_manual_metadata_unchanged() {
    let case = owned_case("key-soar-atomic").await;
    let second = case.second_instance().await;
    let mut faults = Vec::new();
    let outcome = AssertUnwindSafe(async {
        let created = case.h.post("/api/v1/cases", json!({"title":"Owned Key audit case"})).await;
        assert_eq!(created.status, StatusCode::CREATED);
        let case_id: Id = serde_json::from_value(created.json()["case"]["id"].clone()).unwrap();
        let (id, plaintext) = issue(&case.h, "soar-metadata-target").await;
        let mut tx = case.h.state.store.database().unwrap().db().begin_tenant(case.h.tenant).await.unwrap();
        sqlx::query("UPDATE api_keys SET name=$2,allowed_cidrs=$3,expires_at=$4 WHERE id=$1")
            .bind(id.as_uuid())
            .bind("operator-renamed-key")
            .bind(json!(["127.0.0.0/8"]))
            .bind(Timestamp::now().offset_secs(7200).as_datetime())
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let before = raw_key(&case, id).await;
        assert!(second.state.verify_api_key(&plaintext, Some("127.0.0.1")).await.is_ok());
        let chain = case.audit_stats().await;
        let path = format!("/api/v1/cases/{case_id}/playbook");
        let body = json!({"approve":true,"playbook":{"key":"sql-key-revoke","name":"Owned SQL key action",
            "trigger":{},"steps":[{"name":"Revoke Key","action":"revoke-credential","params":{"api_key_id":id}}]}});
        faults.push(case.block_audit().await);
        let failed = case.h.post(&path, body.clone()).await;
        assert!(failed.status.is_server_error());
        assert_eq!(raw_key(&case, id).await, before, "failed audit must not revoke or overwrite operator metadata");
        assert_eq!(case.audit_stats().await, chain);
        assert!(second.state.verify_api_key(&plaintext, Some("127.0.0.1")).await.is_ok());
        let failed_runs: Vec<agf_api::store::SoarRunRecord> =
            case.h.state.configurations.list(case.h.tenant, "soar-run").await.unwrap();
        assert_eq!(failed_runs.len(), 1);
        assert!(failed_runs[0].run.has_failure(), "The attempted Key action must not be reported as successful");
        case.unblock_audit(faults.last().unwrap()).await;
        faults.pop();
        let saved = case.h.post(&path, body.clone()).await;
        assert_eq!(saved.status, StatusCode::OK);
        assert_eq!(saved.json()["has_failure"], false);
        let mut after = raw_key(&case, id).await;
        assert_eq!(after["revoked"], true);
        assert!(!after.to_string().contains(&plaintext));
        let mut before = before;
        for field in ["revoked", "updated_at"] {
            before.as_object_mut().unwrap().remove(field);
            after.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(after, before, "the revocation changes no operator-maintained credential metadata");
        let rows = key_audits(&second, id).await;
        let revoked: Vec<_> = rows.iter().filter(|row| row.actor.name == "soar-api-key-revoke").collect();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].after, Some(json!({"id":id,"revoked":true,"case_id":case_id})));
        let repeated = second.post(&path, body).await;
        assert_eq!(repeated.status, StatusCode::OK);
        assert_eq!(repeated.json()["has_failure"], false);
        assert_eq!(key_audits(&second, id).await.len(), 2);
        let fresh = case.second_instance().await;
        assert!(fresh.state.verify_api_key(&plaintext, Some("127.0.0.1")).await.is_err());
        assert_private(&fresh, &plaintext).await;
    })
    .catch_unwind()
    .await;
    release_faults(&case, faults).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
