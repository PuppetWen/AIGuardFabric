//! UI capabilities use the same evaluated authorization as protected handlers.
#![allow(clippy::unwrap_used)]
mod common;
use common::*;

#[tokio::test]
async fn session_access_respects_builtin_roles_and_key_scopes() {
    let h = setup().await;
    let admin = h.get("/api/v1/auth/me").await.json();
    assert_eq!(admin["access"]["rules:write"], true);
    assert_eq!(admin["access"]["platform:admin"], true);
    let viewer = h.request("GET", "/api/v1/auth/me", Some(&h.viewer), None).await;
    assert_eq!(viewer.status, StatusCode::OK);
    assert_eq!(viewer.json()["access"]["assets:read"], true);
    assert_eq!(viewer.json()["access"]["findings:read"], true);
    assert_eq!(viewer.json()["access"]["findings:write"], false);
    assert_eq!(viewer.json()["access"]["rules:read"], false);
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("rules:*"), Permission::from_raw("assets:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "page-access", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&issued.record).await.unwrap();
    let response = h.request_with("GET", "/api/v1/auth/me", &[("x-agf-key", &issued.plaintext)], None).await;
    assert_eq!(response.status, StatusCode::OK);
    let access = &response.json()["access"];
    assert_eq!(access["rules:read"], true);
    assert_eq!(access["rules:write"], true);
    assert_eq!(access["assets:read"], true);
    assert_eq!(access["assets:write"], false);
    assert_eq!(access["settings:read"], false);
    assert_eq!(access["platform:admin"], false);
    assert_eq!(
        h.request_with(
            "GET",
            "/api/v1/auth/me",
            &[("x-agf-key", &issued.plaintext), ("x-agf-tenant", &h.other_tenant.to_string())],
            None
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
}
