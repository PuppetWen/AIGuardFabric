//! Key mutation audits, unchanged repeats, permissions and SOAR associations use real API contracts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget},
    ids::Id,
};
use common::*;

const PATH: &str = "/api/v1/settings/api-keys";

fn audit(tenant: TenantId, id: Id) -> AuditLog {
    AppState::audit_entry(
        tenant,
        AuditAction::Grant,
        AuditOutcome::Success,
        AuditActor::system("key-atomicity-test"),
        AuditTarget::new("api-key", Some(id.to_string()), None),
        "Owned key mutation test",
    )
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

fn revoke_book(id: Id) -> Value {
    json!({"approve":true,"playbook":{"key":"owned-key-revoke","name":"Owned key revocation",
        "trigger":{},"steps":[{"name":"Revoke platform key","action":"revoke-credential","params":{"api_key_id":id}}]}})
}

#[tokio::test]
async fn concurrent_and_repeated_revocation_publish_only_one_success_audit() {
    let h = setup().await;
    let issued = h.post(PATH, json!({"name":"owned-revoke","scopes":["assets:read"],"expires_in_secs":3600})).await;
    assert_eq!(issued.status, StatusCode::CREATED);
    let body = issued.json();
    let id: Id = serde_json::from_value(body["api_key"]["id"].clone()).unwrap();
    let plaintext = body["plaintext"].as_str().unwrap();
    let before =
        h.state.store.api_key_list_durable(h.tenant).await.unwrap().into_iter().find(|key| key.id == id).unwrap();
    assert!(h.state.verify_api_key(plaintext, None).await.is_ok());
    let path = format!("{PATH}/{id}");
    let (first, second) = tokio::join!(
        h.request("DELETE", &path, Some(&h.admin), None),
        h.request("DELETE", &path, Some(&h.admin), None)
    );
    for response in [first, second, h.request("DELETE", &path, Some(&h.admin), None).await] {
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.json(), json!({"id":id,"revoked":true}));
        assert!(!response.text.contains(plaintext));
    }
    let rows = key_audits(&h, id).await;
    assert_eq!(rows.len(), 2, "one issue and one revoke, regardless of repeats");
    assert!(!serde_json::to_string(&rows).unwrap().contains(plaintext));
    let mut after =
        h.state.store.api_key_list_durable(h.tenant).await.unwrap().into_iter().find(|key| key.id == id).unwrap();
    assert!(after.revoked);
    after.revoked = false;
    assert_eq!(serde_json::to_value(after).unwrap(), serde_json::to_value(before).unwrap());
    assert!(h.state.verify_api_key(plaintext, None).await.is_err());
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
}

#[tokio::test]
async fn mismatched_audit_cannot_publish_or_revoke_a_key() {
    let h = setup().await;
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest::named(h.tenant, "unpublished", Timestamp::now()));
    let valid = audit(h.tenant, issued.record.id);
    let mut invalid = Vec::new();
    let mut wrong = valid.clone();
    wrong.tenant_id = h.other_tenant;
    invalid.push(wrong);
    let mut wrong = valid.clone();
    wrong.target.id = Some(Id::new().to_string());
    invalid.push(wrong);
    let mut wrong = valid.clone();
    wrong.target.kind = "case".into();
    invalid.push(wrong);
    let mut wrong = valid.clone();
    wrong.action = AuditAction::Read;
    invalid.push(wrong);
    let mut wrong = valid.clone();
    wrong.outcome = AuditOutcome::Failure;
    invalid.push(wrong);
    let before = h.state.store.audit_stats_durable(h.tenant).await.unwrap();
    for entry in &invalid {
        assert!(h.state.store.api_key_create_audited(&issued.record, entry.clone()).await.is_err());
        assert!(h.state.verify_api_key(&issued.plaintext, None).await.is_err());
        assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), before);
    }
    h.state.store.api_key_create_audited(&issued.record, valid).await.unwrap();
    let before = h.state.store.audit_stats_durable(h.tenant).await.unwrap();
    for entry in invalid {
        assert!(h.state.store.api_key_revoke_audited(h.tenant, issued.record.id, entry).await.is_err());
        assert!(h.state.verify_api_key(&issued.plaintext, None).await.is_ok());
        assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), before);
    }
}

#[tokio::test]
async fn denied_and_foreign_revocations_do_not_change_the_key_or_audit() {
    let h = setup().await;
    let issued = h.post(PATH, json!({"name":"permission-check","scopes":["assets:read"]})).await;
    assert_eq!(issued.status, StatusCode::CREATED);
    let body = issued.json();
    let id: Id = serde_json::from_value(body["api_key"]["id"].clone()).unwrap();
    let before = h.state.store.audit_stats_durable(h.tenant).await.unwrap();
    for token in [&h.viewer, &h.api_key] {
        assert_eq!(h.request("DELETE", &format!("{PATH}/{id}"), Some(token), None).await.status, StatusCode::FORBIDDEN);
        assert_eq!(
            h.request("POST", PATH, Some(token), Some(json!({"name":"denied","scopes":["assets:read"]}))).await.status,
            StatusCode::FORBIDDEN
        );
    }
    let headers = [("authorization", format!("Bearer {}", h.admin)), ("x-agf-tenant", h.other_tenant.to_string())];
    let borrowed: Vec<_> = headers.iter().map(|(name, value)| (*name, value.as_str())).collect();
    assert_eq!(h.request_with("DELETE", &format!("{PATH}/{id}"), &borrowed, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        h.request("DELETE", &format!("{PATH}/{}", Id::new()), Some(&h.admin), None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), before);
    assert!(h.state.verify_api_key(body["plaintext"].as_str().unwrap(), None).await.is_ok());
}

#[tokio::test]
async fn soar_revocation_has_a_safe_key_audit_with_the_case_association() {
    let h = setup().await;
    let case = create_case_for_soc(&h, "Owned key action", "high").await;
    let issued = h.post(PATH, json!({"name":"soar-target","scopes":["assets:read"]})).await;
    assert_eq!(issued.status, StatusCode::CREATED);
    let body = issued.json();
    let id: Id = serde_json::from_value(body["api_key"]["id"].clone()).unwrap();
    let path = format!("/api/v1/cases/{case}/playbook");
    for _ in 0..2 {
        let run = h.post(&path, revoke_book(id)).await;
        assert_eq!(run.status, StatusCode::OK);
        assert_eq!(run.json()["has_failure"], false);
    }
    let rows = key_audits(&h, id).await;
    let revoked: Vec<_> = rows.iter().filter(|row| row.actor.name == "soar-api-key-revoke").collect();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].after, Some(json!({"id":id,"revoked":true,"case_id":case})));
    assert!(!serde_json::to_string(&rows).unwrap().contains(body["plaintext"].as_str().unwrap()));
    assert!(h.state.verify_api_key(body["plaintext"].as_str().unwrap(), None).await.is_err());
}
