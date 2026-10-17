//! Management routes only; no test here claims that paid semantic chat is wired.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::error::DomainResult;
use common::*;

const PROFILE: &str = "/api/v1/models/semantic-cache/profile";
const KIND: &str = "semantic-cache-profile";

async fn body(h: &Harness) -> Value {
    let mut ids = Vec::new();
    for model in ["owned-chat", "owned-embedding"] {
        let endpoint = h
            .post(
                "/api/v1/gateway/endpoints",
                json!({"name":model,"model":model,
            "provider":"mock","base_url":"http://mock.invalid/v1","local_deployment":true}),
            )
            .await;
        assert_eq!(endpoint.status, StatusCode::CREATED);
        ids.push(endpoint.json()["id"].clone());
    }
    json!({"expected_version":0,"enabled":true,"settings":{
        "chat_endpoint_id":ids[0],"chat_model":"owned-chat","chat_model_revision":"owned-chat-revision-1",
        "embedding_endpoint_id":ids[1],"embedding_model":"owned-embedding","embedding_model_revision":"local-revision-1",
        "dimensions":64,"send_dimensions":false,"max_input_tokens":8192,"embedding_micro_per_1k":0,
        "threshold_ppm":950_000,"ttl_seconds":300,"classification_floor":"internal","mode":"mock_vector"}})
}
async fn snapshot(h: &Harness) -> DomainResult<Value> {
    Ok(json!({"profiles":h.state.configurations.list::<Value>(h.tenant,KIND).await?,
        "audit":h.state.store.audit_stats(h.tenant)?}))
}

#[tokio::test]
async fn missing_profile_get_is_default_disabled_and_has_no_initialization_or_audit() -> DomainResult<()> {
    let h = setup().await;
    let before = snapshot(&h).await?;
    let reply = h.get(PROFILE).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"version":0,"enabled":false,"settings":null,
        "placementVerified":false,"providerWeightsRevisionVerified":false})
    );
    assert_eq!(snapshot(&h).await?, before);
    assert_eq!(h.request("GET", PROFILE, None, None).await.status, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn concurrent_profile_cas_has_one_success_audit_and_stale_body_is_preserved() -> DomainResult<()> {
    let h = setup().await;
    let input = body(&h).await;
    let before = h.state.store.audit_stats(h.tenant)?;
    let (first, second) = tokio::join!(
        h.request("PUT", PROFILE, Some(&h.admin), Some(input.clone())),
        h.request("PUT", PROFILE, Some(&h.admin), Some(input.clone()))
    );
    let statuses = [first.status, second.status];
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    assert_eq!(h.state.store.audit_stats(h.tenant)?.0, before.0 + 1);
    let current = h.get(PROFILE).await.json();
    assert_eq!(current["version"], 1);
    assert_eq!(current["placementVerified"], false);
    assert_eq!(current["providerWeightsRevisionVerified"], false);
    assert_eq!(current["settings"], input["settings"]);
    let prior = snapshot(&h).await?;
    assert_eq!(h.request("PUT", PROFILE, Some(&h.admin), Some(input)).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&h).await?, prior);
    Ok(())
}

#[tokio::test]
async fn unmanaged_urls_price_and_permission_fail_without_changing_configuration() -> DomainResult<()> {
    let h = setup().await;
    let valid = body(&h).await;
    let before = snapshot(&h).await?;
    for key in ["url", "domain", "authority", "api_key"] {
        let mut input = valid.clone();
        input[key] = json!("not-server-owned");
        assert_eq!(h.request("PUT", PROFILE, Some(&h.admin), Some(input)).await.status, StatusCode::BAD_REQUEST);
    }
    let mut priced_mock = valid.clone();
    priced_mock["settings"]["embedding_micro_per_1k"] = json!(1);
    assert_eq!(h.request("PUT", PROFILE, Some(&h.admin), Some(priced_mock)).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.request("PUT", PROFILE, Some(&h.viewer), Some(valid)).await.status, StatusCode::FORBIDDEN);
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}

#[tokio::test]
async fn endpoint_reference_cannot_cross_tenant_and_disable_remains_explicit_cas() -> DomainResult<()> {
    let h = setup().await;
    let input = body(&h).await;
    let token = format!("Bearer {}", h.admin);
    let tenant = h.other_tenant.to_string();
    let headers = [("Authorization", token.as_str()), ("X-AGF-Tenant", tenant.as_str())];
    let before = h.state.configurations.list::<Value>(h.other_tenant, KIND).await?;
    assert_eq!(
        h.request_with("PUT", PROFILE, &headers, Some(input.clone())).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(h.state.configurations.list::<Value>(h.other_tenant, KIND).await?, before);
    assert_eq!(h.request("PUT", PROFILE, Some(&h.admin), Some(input)).await.status, StatusCode::OK);
    let saved = h.get(PROFILE).await.json();
    let disabled = json!({"expected_version":1,"enabled":false,"settings":saved["settings"]});
    let reply = h.request("PUT", PROFILE, Some(&h.admin), Some(disabled)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["version"], 2);
    assert_eq!(reply.json()["enabled"], false);
    assert_eq!(h.request_with("GET", PROFILE, &headers, None).await.json()["version"], 0);
    Ok(())
}
