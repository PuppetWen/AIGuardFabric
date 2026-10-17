//! Real router regressions for optional CAS, audit cardinality and read-only offline guards.
mod common;
use agf_core::ids::Id;
use common::*;
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn definition() -> &'static str {
    "key: OWNED-PUBLICATION\nname: Owned publication\ndomain: prompt-attack\nseverity: high\nkind: keyword\ntarget: prompt\naction: deny\ndetection:\n  type: keyword\n  any: [ownedPublicationMarker]\nsamples:\n  positive: [ownedPublicationMarker]\n  negative: [clean]\n"
}
async fn skill(h: &Harness) -> Result<(Id, Value), Box<dyn std::error::Error + Send + Sync>> {
    let response = h
        .post(
            "/api/v1/assets/register",
            json!({"request_id":Id::new(),"kind":"skill",
        "fingerprint":"owned-publication-skill","name":"Owned Skill","owner":"Reviewer",
        "data_class":"internal","note":"Owned publication fixture"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let id: Id = serde_json::from_value(response.json()["asset"]["id"].clone())?;
    let response = h.get(&format!("/api/v1/skills/{id}")).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    Ok((id, response.json()["skill"].clone()))
}

#[tokio::test]
async fn concurrent_rule_patch_has_one_cas_winner_and_one_audit() -> TestResult {
    let h = setup().await;
    let created = h.post("/api/v1/rules", json!({"yaml":definition(),"expectedVersion":0})).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let before = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?;
    let uri = "/api/v1/rules/OWNED-PUBLICATION";
    let payload = json!({"expectedVersion":1,"enabled":false});
    let (left, right) = tokio::join!(
        h.request("PATCH", uri, Some(&h.admin), Some(payload.clone())),
        h.request("PATCH", uri, Some(&h.admin), Some(payload))
    );
    assert_eq!([left.status, right.status].iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!([left.status, right.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let after = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?;
    assert_eq!(after.len(), before.len() + 1);
    assert!(after.iter().all(agf_core::audit::AuditLog::verify));
    let current = h.get(uri).await.json();
    assert_eq!(current["rule"]["version"], 2);
    assert_eq!(current["rule"]["enabled"], false);
    let stale = h.post("/api/v1/rules/OWNED-PUBLICATION/versions/1/restore?expectedVersion=1", json!({})).await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(h.get(uri).await.json(), current);
    assert_eq!(h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?.len(), after.len());
    Ok(())
}

#[tokio::test]
async fn skill_review_and_allowlist_guard_never_create_or_modify_a_mirror_configuration() -> TestResult {
    let h = setup().await;
    let (id, initial) = skill(&h).await?;
    let sentinel = json!({"existing":"unrelated legacy config"});
    h.state.configurations.put(h.tenant, "asset", id, &sentinel).await?;
    let before: Vec<Value> = h.state.configurations.list(h.tenant, "asset").await?;
    let response = h
        .post(
            &format!("/api/v1/skills/{id}/status"),
            json!({"to":"under-review",
        "note":"Reviewed", "expectedUpdatedAt":initial["review"]["updatedAt"]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let revision = response.json()["review"]["updatedAt"].clone();
    let uri = format!("/api/v1/skills/{id}/whitelist");
    let body = json!({"domains":["owned.test"],"paths":[],"expectedUpdatedAt":revision});
    let before_audits = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?.len();
    let (left, right) = tokio::join!(
        h.request("PUT", &uri, Some(&h.admin), Some(body.clone())),
        h.request("PUT", &uri, Some(&h.admin), Some(body))
    );
    assert_eq!([left.status, right.status].iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!([left.status, right.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    assert_eq!(h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?.len(), before_audits + 1);
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "asset").await?, before);
    // A second Skill has no configuration key at all, before or after its reviewed mutation.
    let second = h
        .post(
            "/api/v1/assets/register",
            json!({"request_id":Id::new(),"kind":"skill",
        "fingerprint":"owned-second-skill","name":"Second Skill","owner":"Reviewer",
        "data_class":"internal","note":"Owned"}),
        )
        .await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text);
    let second_id: Id = serde_json::from_value(second.json()["asset"]["id"].clone())?;
    let response =
        h.post(&format!("/api/v1/skills/{second_id}/status"), json!({"to":"under-review","note":"Reviewed"})).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert!(h.state.configurations.get::<Value>(h.tenant, "asset", second_id).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn disabled_tenant_and_revoked_key_cannot_change_a_skill() -> TestResult {
    let mut h = setup().await;
    // 默认管理租户不能停用；本用例使用独立租户，仍经真实路由认证。
    let tenant = agf_api::tenant_directory::new(format!("skill-{}", Id::new()), "Owned Skill tenant".into());
    h.tenant = tenant.id;
    agf_api::tenant_directory::save(&h.state, tenant, true).await?;
    let value = axum::http::HeaderValue::from_str(&h.tenant.to_string())?;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", value.clone());
        async move { request }
    }));
    let (id, initial) = skill(&h).await?;
    let issued = h.post("/api/v1/settings/api-keys", json!({"name":"owned-skill-key","scopes":["skills:write"]})).await;
    assert_eq!(issued.status, StatusCode::CREATED, "{}", issued.text);
    let token = issued.json()["plaintext"].as_str().ok_or("key plaintext missing")?.to_owned();
    let key: Id = serde_json::from_value(issued.json()["api_key"]["id"].clone())?;
    h.state.store.api_key_revoke(h.tenant, key)?;
    let uri = format!("/api/v1/skills/{id}/status");
    let body = json!({"to":"under-review","note":"Reviewed","expectedUpdatedAt":initial["review"]["updatedAt"]});
    let denied = h.request("POST", &uri, Some(&token), Some(body.clone())).await;
    assert!(denied.status.is_client_error(), "{}", denied.text);
    let mut tenant = agf_api::tenant_directory::get(&h.state, h.tenant).await?;
    tenant.enabled = false;
    agf_api::tenant_directory::save(&h.state, tenant, false).await?;
    let denied = h.post(&uri, body).await;
    assert!(denied.status.is_client_error(), "{}", denied.text);
    let asset = h.state.store.asset_get(h.tenant, id)?.ok_or("Skill missing")?;
    assert_eq!(serde_json::to_value(asset.updated_at)?, initial["review"]["updatedAt"]);
    Ok(())
}
