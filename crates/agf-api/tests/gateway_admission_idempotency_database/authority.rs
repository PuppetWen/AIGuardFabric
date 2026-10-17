use super::*;
use agf_core::ids::Id;

#[tokio::test]
#[ignore = "requires exact-owned gateway settlement PostgreSQL; actual priced HTTP loopback only"]
async fn write_only_key_can_first_admit_but_missing_read_never_reopens_an_occupied_key() -> DomainResult<()> {
    let owned = Owned::open("gw-key-write-only").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    configure(&h, &provider).await;
    let key = h.post("/api/v1/settings/api-keys", json!({"name":"owned-write-only","scopes":["models:write"]})).await;
    assert_eq!(key.status, StatusCode::CREATED);
    let token = key.json()["plaintext"].as_str().ok_or_else(invalid)?.to_owned();
    let first = post(&h, &token, "owned-write-only", "/v1/chat/completions", body("write-only")).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let id = attempt(&first)?;
    let before = rows(&owned).await?;
    let audits = owned.case.audit_stats().await;
    for path in ["/v1/chat/completions", "/api/v1/chat/completions"] {
        let duplicate = post(&h, &token, "owned-write-only", path, body("write-only")).await;
        assert_eq!(duplicate.status, StatusCode::FORBIDDEN);
        assert!(duplicate.header("x-agf-attempt-id").is_empty());
        assert!(!duplicate.text.contains(&id.to_string()));
    }
    assert_eq!(lookup(&h, &token, "owned-write-only").await.status, StatusCode::FORBIDDEN);
    assert_eq!(provider.calls(), 1);
    assert_eq!(rows(&owned).await?, before);
    assert_eq!(owned.case.audit_stats().await, audits);
    owned.chain().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact-owned gateway settlement PostgreSQL; actual priced HTTP loopback only"]
async fn original_key_revoked_during_real_admission_audit_wait_rolls_back_key_fact_and_reservations() -> DomainResult<()>
{
    let owned = Owned::open("gw-key-revoked").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    configure(&h, &provider).await;
    let key = h
        .post("/api/v1/settings/api-keys", json!({"name":"owned-audit-key","scopes":["models:read","models:write"]}))
        .await;
    assert_eq!(key.status, StatusCode::CREATED);
    let key_id: Id = serde_json::from_value(key.json()["api_key"]["id"].clone())?;
    let token = key.json()["plaintext"].as_str().ok_or_else(invalid)?.to_owned();
    h.get("/api/v1/policies").await;
    h.get("/api/v1/quotas").await;
    let before = rows(&owned).await?;
    let audits = owned.case.audit_stats().await;
    let gate = Gate::install(&owned, key_id).await?;
    let response = gate
        .invoke(&owned, h.clone(), token, "owned-revoked", || async {
            owned.ownership.verify(&owned.case.pool).await?;
            let changed = sqlx::query(
                "UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked",
            )
            .bind(h.tenant.as_uuid())
            .bind(key_id.as_uuid())
            .execute(&owned.case.pool)
            .await
            .map_err(|error| agf_storage::map_sqlx_err("owned_gateway_key_revoke", &error))?;
            assert_eq!(changed.rows_affected(), 1);
            Ok(())
        })
        .await?;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(rows(&owned).await?, before);
    assert_eq!(owned.case.audit_stats().await, audits);
    assert_eq!(provider.calls(), 0);
    owned.chain().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact-owned gateway settlement PostgreSQL; actual priced HTTP loopback only"]
async fn original_jwt_expiry_during_real_audit_wait_prevents_durable_key_and_any_provider_call() -> DomainResult<()> {
    let owned = Owned::open("gw-key-jwt-expiry").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    configure(&h, &provider).await;
    h.get("/api/v1/policies").await;
    h.get("/api/v1/quotas").await;
    let before = rows(&owned).await?;
    let audits = owned.case.audit_stats().await;
    let subject = Id::parse(&h.state.auth.issuer().verify(&h.admin)?.sub).map_err(|_| invalid())?;
    let gate = Gate::install(&owned, subject).await?;
    let (token, claims) = short_token(&h)?;
    let response = gate.invoke(&owned, h.clone(), token, "owned-jwt-expiry", || wait_expired(&claims)).await?;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(rows(&owned).await?, before);
    assert_eq!(owned.case.audit_stats().await, audits);
    assert_eq!(provider.calls(), 0);
    owned.chain().await?;
    Ok(())
}
