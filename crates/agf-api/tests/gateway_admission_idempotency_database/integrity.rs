use super::*;

#[tokio::test]
#[ignore = "requires exact-owned gateway settlement PostgreSQL; actual priced HTTP loopback only"]
async fn local_lookup_ignores_unavailable_cloud_source_but_foreign_identity_or_retired_index_never_reexecutes()
-> DomainResult<()> {
    let owned = Owned::open("gw-key-integrity").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    let first = post(&h, &identities[0].key, "owned-integrity", "/v1/chat/completions", body("integrity")).await;
    assert_eq!(first.status, StatusCode::OK);
    let id = attempt(&first)?;
    assert_eq!(lookup(&h, &identities[1].key, "owned-integrity").await.status, StatusCode::NOT_FOUND);
    let endpoint = h.get("/api/v1/gateway/endpoints").await.json()["items"][0].clone();
    let endpoint_id = endpoint["id"].as_str().ok_or_else(invalid)?;
    assert_eq!(
        h.request(
            "DELETE",
            &format!("/api/v1/gateway/endpoints/{endpoint_id}?expected_version={}", endpoint["version"]),
            Some(&h.admin),
            None
        )
        .await
        .status,
        StatusCode::OK
    );
    let second = live(owned.case.second_instance().await);
    let stable = rows(&owned).await?;
    let audits = owned.case.audit_stats().await;
    let original = lookup(&second, &identities[0].key, "owned-integrity").await;
    assert_eq!(original.status, StatusCode::OK);
    assert_eq!(original.json()["attemptId"], json!(id));
    assert_eq!(
        post(&second, &identities[0].key, "owned-integrity", "/v1/chat/completions", body("integrity")).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(rows(&owned).await?, stable);
    assert_eq!(owned.case.audit_stats().await, audits);
    assert_eq!(provider.calls(), 1);
    owned.ownership.verify(&owned.case.pool).await?;
    let changed = sqlx::query(
        "UPDATE console_configurations SET deleted_at=now() WHERE tenant_id=$1 AND kind=$2 AND deleted_at IS NULL",
    )
    .bind(h.tenant.as_uuid())
    .bind(INDEX)
    .execute(&owned.case.pool)
    .await
    .map_err(|error| agf_storage::map_sqlx_err("owned_gateway_key_tombstone", &error))?;
    assert_eq!(changed.rows_affected(), 1);
    let tombstone = rows(&owned).await?;
    let refused = post(&second, &identities[0].key, "owned-integrity", "/v1/chat/completions", body("integrity")).await;
    assert_eq!(refused.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(refused.header("x-agf-attempt-id").is_empty());
    assert_eq!(lookup(&second, &identities[0].key, "owned-integrity").await.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(rows(&owned).await?, tombstone);
    assert_eq!(owned.case.audit_stats().await, audits);
    assert_eq!(provider.calls(), 1);
    owned.chain().await?;
    Ok(())
}
