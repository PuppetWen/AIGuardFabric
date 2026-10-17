//! Actual owned PostgreSQL, RLS and AEAD tests. No provider requests, vector extension or fake billing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
#[path = "configuration_audit_support/mod.rs"]
mod configuration_audit_support;
mod semantic_response_cache_database_support;
use agf_storage::{Database, semantic_response_cache::*};
use common::*;
use semantic_response_cache_database_support::*;

#[tokio::test]
#[ignore = "requires a dedicated owner-comment/OID verified semantic cache database"]
async fn two_instances_read_same_encrypted_entry_and_get_is_pure() {
    let fixture = Fixture::open("semantic-shared").await;
    let domain = fixture.issuer.issue(fixture.evidence()).unwrap();
    fixture.admit(&domain, "private owned cache answer", 900).await;
    let before = fixture.stats().await;
    let audit = fixture.case.audit_stats().await;
    let second = fixture.repository();
    let result = second.lookup(&domain, &query(), &Authority(&fixture)).await.unwrap();
    assert!(matches!(result, Lookup::Hit { .. }));
    assert_eq!(fixture.stats().await, before);
    assert_eq!(fixture.case.audit_stats().await, audit);
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT payload FROM semantic_response_cache_v2 WHERE tenant_id=$1")
        .bind(domain.tenant().as_uuid())
        .fetch_one(&fixture.case.pool)
        .await
        .unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains("private owned cache answer"));
}

#[tokio::test]
#[ignore = "requires a dedicated owner-comment/OID verified semantic cache database"]
async fn foreign_rls_and_full_same_version_source_change_never_return_a_hit() {
    let fixture = Fixture::open("semantic-fences").await;
    let domain = fixture.issuer.issue(fixture.evidence()).unwrap();
    fixture.admit(&domain, "owned", 900).await;
    let foreign = fixture.case.foreign_instance().await;
    let database = Database::from_pool(fixture.case.pool.clone());
    let mut tx = database.begin_tenant(foreign.tenant).await.unwrap();
    assert_eq!(tx.scalar_i64("SELECT count(*) FROM semantic_response_cache_v2").await.unwrap(), 0);
    tx.commit().await.unwrap();
    fixture
        .case
        .h
        .state
        .configurations
        .put(domain.tenant(), "semantic-cache-fixture", fixture.source, &json!({"version":1,"enabled":false}))
        .await
        .unwrap();
    assert!(fixture.repository().lookup(&domain, &query(), &Authority(&fixture)).await.is_err());
}

#[tokio::test]
#[ignore = "requires a dedicated owner-comment/OID verified semantic cache database"]
async fn authenticated_payload_tamper_with_valid_shape_is_fail_closed() {
    let fixture = Fixture::open("semantic-aead").await;
    let domain = fixture.issuer.issue(fixture.evidence()).unwrap();
    let id = fixture.admit(&domain, "owned", 900).await;
    check_owner().await;
    let bytes: Vec<u8> =
        sqlx::query_scalar("SELECT payload FROM semantic_response_cache_v2 WHERE tenant_id=$1 AND id=$2")
            .bind(domain.tenant().as_uuid())
            .bind(id.as_uuid())
            .fetch_one(&fixture.case.pool)
            .await
            .unwrap();
    let mut changed: Value = serde_json::from_slice(&bytes).unwrap();
    let ciphertext = changed["secret"]["ciphertext_b64"].as_str().unwrap();
    let replacement = if ciphertext.starts_with('A') { "B" } else { "A" };
    changed["secret"]["ciphertext_b64"] = json!(format!("{replacement}{}", &ciphertext[1..]));
    let changed = serde_json::to_vec(&changed).unwrap();
    sqlx::query("UPDATE semantic_response_cache_v2 SET payload=$1,sealed_bytes=$2 WHERE tenant_id=$3 AND id=$4")
        .bind(&changed)
        .bind(i32::try_from(changed.len()).unwrap())
        .bind(domain.tenant().as_uuid())
        .bind(id.as_uuid())
        .execute(&fixture.case.pool)
        .await
        .unwrap();
    assert!(fixture.repository().lookup(&domain, &query(), &Authority(&fixture)).await.is_err());
}

#[tokio::test]
#[ignore = "requires a dedicated owner-comment/OID verified semantic cache database"]
async fn natural_expiry_does_not_write_or_extend_the_entry() {
    let fixture = Fixture::open("semantic-expiry").await;
    let domain = fixture.issuer.issue(fixture.evidence()).unwrap();
    fixture.admit(&domain, "owned", 1).await;
    let before = fixture.stats().await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(matches!(
        fixture.repository().lookup(&domain, &query(), &Authority(&fixture)).await.unwrap(),
        Lookup::Miss
    ));
    assert_eq!(fixture.stats().await, before);
}

#[tokio::test]
#[ignore = "requires a dedicated owner-comment/OID verified semantic cache database"]
async fn concurrent_admission_and_513_rows_keep_tenant_capacity_bounded_and_candidates_unambiguous() {
    let fixture = Fixture::open("semantic-capacity").await;
    let domain = fixture.issuer.issue(fixture.evidence()).unwrap();
    let (left, right) = tokio::join!(fixture.admit(&domain, "first", 900), fixture.admit(&domain, "second", 900));
    assert_ne!(left, right);
    assert!(matches!(
        fixture.repository().lookup(&domain, &query(), &Authority(&fixture)).await.unwrap(),
        Lookup::Ambiguous
    ));
    for _ in 0..511 {
        fixture.admit(&domain, "owned", 900).await;
    }
    let (count, bytes, _) = fixture.stats().await;
    assert_eq!(count, 512);
    assert!(bytes <= 16 * 1024 * 1024);
    assert!(matches!(
        fixture.repository().lookup(&domain, &query(), &Authority(&fixture)).await.unwrap(),
        Lookup::CandidateLimit
    ));
}

#[tokio::test]
#[ignore = "requires a dedicated owner-comment/OID verified semantic cache database"]
async fn caller_transaction_rollback_does_not_publish_cache_candidate() {
    let fixture = Fixture::open("semantic-rollback").await;
    let domain = fixture.issuer.issue(fixture.evidence()).unwrap();
    let before = fixture.stats().await;
    let database = Database::from_pool(fixture.case.pool.clone());
    let mut tx = database.begin_tenant(domain.tenant()).await.unwrap();
    fixture.repository().admit_in_transaction(&mut tx, &domain, admission("must roll back", 900)).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(fixture.stats().await, before);
}
