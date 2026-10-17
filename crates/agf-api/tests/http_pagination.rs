//! 分页 / 过滤 / 排序 / 字段裁剪、幂等键重放、限流与探针豁免。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

// ===========================================================================
// 5. 分页 / 过滤 / 排序 / 字段裁剪
// ===========================================================================

#[tokio::test]
async fn page_size_is_clamped_to_max() {
    let h = setup().await;
    seed_assets(&h, 3).await;
    let resp = h.get("/api/v1/assets?page_size=100000").await;
    assert_eq!(resp.status, StatusCode::OK);
    let body = resp.json();
    assert_eq!(body["page_size"], 200, "页大小必须夹到上限 200");
    assert_eq!(body["total"], 3);
}

#[tokio::test]
async fn page_zero_is_normalized_to_one() {
    let h = setup().await;
    seed_assets(&h, 2).await;
    let resp = h.get("/api/v1/assets?page=0&page_size=1").await;
    let body = resp.json();
    assert_eq!(body["page"], 1);
    assert_eq!(body["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(body["has_more"], true);
}

#[tokio::test]
async fn fields_projection_trims_response() {
    let h = setup().await;
    seed_assets(&h, 1).await;
    let resp = h.get("/api/v1/assets?fields=id,name").await;
    let body = resp.json();
    let item = &body["items"][0];
    assert!(item.get("id").is_some());
    assert!(item.get("name").is_some());
    assert!(item.get("attributes").is_none(), "未请求字段必须被裁掉: {item}");
}

#[tokio::test]
async fn filter_and_search_and_sort_work() {
    let h = setup().await;
    let _ = ingest_mcp(&h, "fp-a", "stdio:alpha").await;
    let _ = ingest_mcp(&h, "fp-b", "stdio:beta").await;
    let filtered = h.get("/api/v1/assets?kind=mcp-server&min_exposure=50").await.json();
    assert_eq!(filtered["total"], 2);
    let empty = h.get("/api/v1/assets?kind=agent").await.json();
    assert_eq!(empty["total"], 0);
    let searched = h.get("/api/v1/assets?q=fp-a").await.json();
    assert_eq!(searched["total"], 1);
    let bad = h.get("/api/v1/assets?min_exposure=lots").await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// 6. 幂等
// ===========================================================================

#[tokio::test]
async fn idempotency_key_replays_first_response() {
    let h = setup().await;
    let body = json!({"assets": [{"kind": "skill", "name": "s1", "fingerprint": "fp-idem"}]});
    let first = h
        .request_with(
            "POST",
            "/api/v1/assets/discovery",
            &[("authorization", &format!("Bearer {}", h.admin)), ("idempotency-key", "key-1")],
            Some(body.clone()),
        )
        .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.header("idempotency-replayed"), "");
    let second = h
        .request_with(
            "POST",
            "/api/v1/assets/discovery",
            &[("authorization", &format!("Bearer {}", h.admin)), ("idempotency-key", "key-1")],
            Some(body),
        )
        .await;
    assert_eq!(second.status, first.status);
    assert_eq!(second.header("idempotency-replayed"), "true");
    assert_eq!(second.json()["stats"], first.json()["stats"]);
    assert_eq!(h.state.store.asset_list_all(h.tenant).unwrap().len(), 1, "幂等重放不得重复入库");
}

#[tokio::test]
async fn different_idempotency_keys_execute_separately() {
    let h = setup().await;
    let body = json!({"assets": [{"kind": "skill", "name": "s2", "fingerprint": "fp-idem-2"}]});
    for key in ["key-a", "key-b"] {
        let resp = h
            .request_with(
                "POST",
                "/api/v1/assets/discovery",
                &[("authorization", &format!("Bearer {}", h.admin)), ("idempotency-key", key)],
                Some(body.clone()),
            )
            .await;
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.header("idempotency-replayed"), "");
    }
}

// ===========================================================================
// 7. 限流
// ===========================================================================

#[tokio::test]
async fn rate_limit_returns_429_with_headers() {
    let h = setup_with_limits(RateLimitTiers {
        identity: RateLimitTier::new(2, 0.0),
        tenant: RateLimitTier::new(1_000, 1_000.0),
        global: RateLimitTier::new(10_000, 10_000.0),
    })
    .await;
    let first = h.get("/api/v1/assets").await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(!first.header("x-ratelimit-limit").is_empty());
    let _ = h.get("/api/v1/assets").await;
    let third = h.get("/api/v1/assets").await;
    assert_eq!(third.status, StatusCode::TOO_MANY_REQUESTS, "{}", third.text);
    assert_eq!(third.code(), "rate_limited");
    assert!(!third.header("retry-after").is_empty());
}

#[tokio::test]
async fn probes_are_exempt_from_rate_limit() {
    let h = setup_with_limits(RateLimitTiers {
        identity: RateLimitTier::new(1, 0.0),
        tenant: RateLimitTier::new(1, 0.0),
        global: RateLimitTier::new(1, 0.0),
    })
    .await;
    for _ in 0..5 {
        assert_eq!(h.request("GET", "/healthz", None, None).await.status, StatusCode::OK);
        assert_eq!(h.request("GET", "/readyz", None, None).await.status, StatusCode::OK);
    }
}

#[tokio::test]
async fn invalid_credentials_cannot_charge_a_real_tenant_bucket() {
    let h = setup_with_limits(RateLimitTiers {
        identity: RateLimitTier::new(10, 0.0),
        tenant: RateLimitTier::new(1, 0.0),
        global: RateLimitTier::new(10, 0.0),
    })
    .await;
    let tenant = h.tenant.to_string();
    let rejected = h
        .request_with(
            "GET",
            "/api/v1/assets",
            &[("authorization", "Bearer invalid-token"), ("x-agf-tenant", &tenant)],
            None,
        )
        .await;
    assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.get("/api/v1/assets").await.status, StatusCode::OK);
}

#[tokio::test]
async fn ignored_api_key_header_cannot_rotate_authenticated_identity() {
    let h = setup_with_limits(RateLimitTiers {
        identity: RateLimitTier::new(1, 0.0),
        tenant: RateLimitTier::new(10, 0.0),
        global: RateLimitTier::new(10, 0.0),
    })
    .await;
    assert_eq!(h.get("/api/v1/assets").await.status, StatusCode::OK);
    let auth = format!("Bearer {}", h.admin);
    let second = h
        .request_with("GET", "/api/v1/assets", &[("authorization", &auth), ("x-api-key", "unused-on-this-route")], None)
        .await;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn required_shared_limiter_fails_closed_without_redis() {
    let h = setup().await;
    let mut state = h.state.clone();
    state.shared_rate_limit_required = true;
    let app = build_router(state);
    let auth = format!("Bearer {}", h.admin);
    let request = Request::builder()
        .uri("/api/v1/assets")
        .header(header::AUTHORIZATION, auth)
        .body(Body::empty())
        .expect("request");
    let denied = send(&app, request).await;
    assert_eq!(denied.status, StatusCode::SERVICE_UNAVAILABLE);
    let ready = send(&app, Request::builder().uri("/readyz").body(Body::empty()).expect("request")).await;
    assert_eq!(ready.status, StatusCode::SERVICE_UNAVAILABLE);
}
