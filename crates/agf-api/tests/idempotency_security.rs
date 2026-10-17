//! Replay must preserve resource/tenant identity and recheck current authorization.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{
    error::ApiError,
    middleware::{Principal, idempotency},
};
use axum::{
    Json,
    extract::{Path, State},
    routing::post,
};
use common::*;
use std::sync::atomic::{AtomicU64, Ordering};

async fn harness() -> (Harness, Arc<AtomicU64>) {
    let mut h = setup().await;
    let count = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&count);
    h.app = Router::new()
        .route(
            "/api/v1/items/{id}",
            post(
                move |State(state): State<AppState>,
                      principal: Principal,
                      Path(id): Path<String>,
                      Json(body): Json<Value>| {
                    let counter = Arc::clone(&counter);
                    async move {
                        principal.require(&state, "assets", "write")?;
                        let sequence = counter.fetch_add(1, Ordering::SeqCst) + 1;
                        if body["slow"] == true {
                            tokio::time::sleep(std::time::Duration::from_millis(70)).await;
                        }
                        let status =
                            if body["fail"] == true { StatusCode::INTERNAL_SERVER_ERROR } else { StatusCode::OK };
                        let body =
                            if body["large"] == true { json!({"value":"x".repeat(2*1024*1024+1)}) } else { body };
                        Ok::<_, ApiError>((
                            status,
                            Json(json!({"id":id,"tenant":principal.tenant,"sequence":sequence,"input":body})),
                        ))
                    }
                },
            ),
        )
        .layer(axum::middleware::from_fn_with_state(h.state.clone(), idempotency))
        .with_state(h.state.clone());
    (h, count)
}
async fn call(h: &Harness, path: &str, tenant: TenantId, key: &str, body: Value) -> Resp {
    h.request_with(
        "POST",
        path,
        &[
            ("authorization", &format!("Bearer {}", h.admin)),
            ("x-agf-tenant", &tenant.to_string()),
            ("idempotency-key", key),
        ],
        Some(body),
    )
    .await
}

#[tokio::test]
async fn actual_uri_tenant_and_body_are_bound_to_the_receipt() {
    let (h, count) = harness().await;
    let path = "/api/v1/items/a";
    let first = call(&h, path, h.tenant, "same", json!({"value":1})).await;
    assert_eq!(first.status, StatusCode::OK);
    let replay = call(&h, path, h.tenant, "same", json!({"value":1})).await;
    assert_eq!(replay.json(), first.json());
    assert_eq!(replay.header("idempotency-replayed"), "true");
    let conflict = call(&h, path, h.tenant, "same", json!({"value":2})).await;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    let other = call(&h, path, h.other_tenant, "same", json!({"value":1})).await;
    assert_eq!(other.status, StatusCode::OK);
    assert_eq!(other.json()["tenant"], h.other_tenant.to_string());
    let second = call(&h, "/api/v1/items/b", h.tenant, "same", json!({"value":1})).await;
    assert_eq!(second.json()["id"], "b");
    let query = call(&h, "/api/v1/items/b?mode=other", h.tenant, "same", json!({"value":1})).await;
    assert_eq!(query.header("idempotency-replayed"), "");
    assert_eq!(count.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn simultaneous_and_uncertain_requests_do_not_execute_twice() {
    let (h, count) = harness().await;
    let body = json!({"slow":true});
    let (a, b) = tokio::join!(
        call(&h, "/api/v1/items/a", h.tenant, "parallel", body.clone()),
        call(&h, "/api/v1/items/a", h.tenant, "parallel", body.clone())
    );
    assert_eq!([a.status, b.status].iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!([a.status, b.status].iter().filter(|s| **s == StatusCode::CONFLICT).count(), 1);
    assert_eq!(call(&h, "/api/v1/items/a", h.tenant, "parallel", body).await.header("idempotency-replayed"), "true");
    let failed = call(&h, "/api/v1/items/a", h.tenant, "uncertain", json!({"fail":true})).await;
    assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        call(&h, "/api/v1/items/a", h.tenant, "uncertain", json!({"fail":true})).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn revocation_and_role_changes_cannot_replay_cached_write_results() {
    let (h, count) = harness().await;
    let claims = h.state.auth.issuer().verify(&h.viewer).unwrap();
    let viewer = h.state.auth_backend.find_user(h.tenant, claims.sub.parse().unwrap()).await.unwrap().unwrap();
    h.state.auth_backend.save_account(&viewer, None, &["tenant-admin".into()]).await.unwrap();
    let headers = [("authorization", format!("Bearer {}", h.viewer)), ("idempotency-key", "role-change".into())];
    // Keep the borrowed header list alive across each request.
    let borrowed = headers.iter().map(|(k, v)| (*k, v.as_str())).collect::<Vec<_>>();
    assert_eq!(h.request_with("POST", "/api/v1/items/a", &borrowed, Some(json!({}))).await.status, StatusCode::OK);
    let viewer = h.state.auth_backend.find_user(h.tenant, viewer.id).await.unwrap().unwrap();
    h.state.auth_backend.save_account(&viewer, None, &["viewer".into()]).await.unwrap();
    assert_eq!(
        h.request_with("POST", "/api/v1/items/a", &borrowed, Some(json!({}))).await.status,
        StatusCode::FORBIDDEN
    );
    let key = h
        .state
        .store
        .api_key_list_durable(h.tenant)
        .await
        .unwrap()
        .into_iter()
        .find(|key| key.name == "integration-test")
        .unwrap();
    let key_headers = [("x-agf-key", h.api_key.as_str()), ("idempotency-key", "key-revoke")];
    assert_eq!(h.request_with("POST", "/api/v1/items/a", &key_headers, Some(json!({}))).await.status, StatusCode::OK);
    h.state.store.api_key_revoke_durable(h.tenant, key.id).await.unwrap();
    assert_eq!(
        h.request_with("POST", "/api/v1/items/a", &key_headers, Some(json!({}))).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn credentials_and_unbounded_responses_are_never_cached_or_truncated() {
    let (mut h, count) = harness().await;
    let response = call(&h, "/api/v1/items/large", h.tenant, "large", json!({"large":true})).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.bytes.len() > 2 * 1024 * 1024);
    assert_eq!(
        call(&h, "/api/v1/items/large", h.tenant, "large", json!({"large":true})).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    h.app = build_router(h.state.clone());
    let key = call(
        &h,
        "/api/v1/settings/api-keys",
        h.tenant,
        "secret",
        json!({"name":"must-not-create","scopes":["assets:read"]}),
    )
    .await;
    assert_eq!(key.status, StatusCode::BAD_REQUEST);
    assert!(!h.state.store.api_key_list_durable(h.tenant).await.unwrap().iter().any(|k| k.name == "must-not-create"));
}

#[tokio::test]
async fn collector_mtls_replay_authenticates_the_certificate_again() {
    if std::env::var("AGF_REPLAY_MTLS_CHILD").as_deref() != Ok("1") {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "collector_mtls_replay_authenticates_the_certificate_again", "--nocapture"])
            .env("AGF_REPLAY_MTLS_CHILD", "1")
            .env("AGF_AGENT_MTLS_TRUST_PROXY", "1")
            .env("AGF_AGENT_MTLS_REQUIRED", "1")
            .env("AGF_AGENT_MTLS_MAP", "CN=replay-collector=tenant-admin")
            .env("AGF_TRUSTED_PROXIES", "127.0.0.1/32")
            .env_remove("AGF_AGENT_MTLS_DEFAULT_ROLE")
            .env_remove("AGF_AGENT_MTLS_DEFAULT_TENANT")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    use base64::Engine as _;
    let h = setup().await;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, "replay-collector");
    let cert = params.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(cert.der());
    let body =
        json!({"collector_id":"replay-mtls","raw_logs":[{"text":"replay certificate fixture","protocol":"webhook"}]});
    let headers = [
        ("x-agf-client-cert-der", encoded.as_str()),
        ("x-ssl-client-verify", "SUCCESS"),
        ("idempotency-key", "mtls-replay"),
    ];
    let first = certificate_request(&h, &headers, body.clone(), "127.0.0.1:9000").await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let replay = certificate_request(&h, &headers, body.clone(), "127.0.0.1:9000").await;
    assert_eq!(replay.header("idempotency-replayed"), "true");
    let mut invalid = headers;
    invalid[1] = ("x-ssl-client-verify", "FAILED");
    assert_eq!(
        certificate_request(&h, &invalid, body.clone(), "127.0.0.1:9000").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(certificate_request(&h, &headers, body, "192.0.2.8:9000").await.status, StatusCode::UNAUTHORIZED);
}

async fn certificate_request(h: &Harness, headers: &[(&str, &str)], body: Value, peer: &str) -> Resp {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/ingest/agent")
        .extension(axum::extract::ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()))
        .header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    send(&h.app, request.body(Body::from(body.to_string())).unwrap()).await
}
