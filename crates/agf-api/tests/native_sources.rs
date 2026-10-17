//! Native source records are managed by the same tenant-scoped console endpoints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

#[tokio::test]
async fn delivery_status_requires_login_and_identifies_non_durable_demo() {
    let h = setup().await;
    let unauthenticated = h.request("GET", "/api/v1/sources/delivery", None, None).await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    let status = h.get("/api/v1/sources/delivery").await;
    assert_eq!(status.status, StatusCode::OK, "{}", status.text);
    assert_eq!(status.json()["storage"], "memory");
    assert!(status.json()["pending"].is_null());
    assert_eq!(status.json()["workerEnabled"], false);
}

#[tokio::test]
async fn native_bindings_preserve_protocol_and_reject_http_push() {
    let h = setup().await;
    for receiver in [
        "syslog-udp",
        "syslog-tcp",
        "syslog-tls",
        "kafka",
        "pulsar-native",
        "nats-jetstream",
        "mqtt",
        "object-pull",
        "sql-pull",
        "snmp-trap",
        "webhook",
        "otlp",
        "otlp-traces",
        "otlp-metrics",
        "otlp-grpc",
        "otlp-grpc-traces",
        "otlp-grpc-metrics",
    ] {
        let created = h
            .post("/api/v1/ingest/sources", json!({"name":receiver,"protocol":"native","nativeReceiver":receiver}))
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
        assert_eq!(created.json()["native_receiver"], receiver);
        let id = created.json()["id"].as_str().unwrap().to_owned();
        let uri = format!("/api/v1/ingest/sources/{id}");
        assert_eq!(
            h.post(&format!("{uri}/events"), json!({"message":"wrong transport"})).await.status,
            StatusCode::BAD_REQUEST
        );
        let edited = h
            .request(
                "PUT",
                &uri,
                Some(&h.admin),
                Some(json!({"name":"renamed", "protocol":"native", "nativeReceiver":receiver, "enabled":false})),
            )
            .await;
        assert_eq!(edited.status, StatusCode::OK, "{}", edited.text);
        assert_eq!(edited.json()["native_receiver"], receiver);
        assert_eq!(edited.json()["enabled"], false);
        if receiver == "syslog-udp" {
            let wrong = h
                .request(
                    "PUT",
                    &uri,
                    Some(&h.admin),
                    Some(json!({"name":"wrong", "protocol":"native", "nativeReceiver":"syslog-tcp"})),
                )
                .await;
            assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
        }
        let foreign = h
            .request_with(
                "GET",
                &uri,
                &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.other_tenant.to_string())],
                None,
            )
            .await;
        assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    }
    let invalid = h
        .post("/api/v1/ingest/sources", json!({"name":"unknown", "protocol":"native", "nativeReceiver":"kafak"}))
        .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn source_security_controls_validate_preserve_and_clear_explicitly() {
    let h = setup().await;
    assert_eq!(h.get("/api/v1/ingest/sources").await.json()["can_write"], true);
    let reader = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("sources:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "source-reader", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&reader.record).await.unwrap();
    let read_only = h.request_with("GET", "/api/v1/ingest/sources", &[("x-agf-key", &reader.plaintext)], None).await;
    assert_eq!(read_only.status, StatusCode::OK, "{}", read_only.text);
    assert_eq!(read_only.json()["can_write"], false);
    for (receiver, cidrs, mtls) in [
        ("kafka", json!(["192.0.2.0/24"]), false),
        ("syslog-tcp", json!([]), true),
        ("otlp", json!([]), true),
        ("syslog-tls", json!(["not-a-network"]), true),
    ] {
        let response = h
            .post(
                "/api/v1/ingest/sources",
                json!({
                    "name":"invalid policy", "protocol":"native", "nativeReceiver":receiver,
                    "allowedCidrs":cidrs, "requireMtls":mtls
                }),
            )
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
    }
    for receiver in ["syslog-tls", "otlp-grpc", "otlp-grpc-traces", "otlp-grpc-metrics"] {
        let created = h
            .post(
                "/api/v1/ingest/sources",
                json!({
                    "name":"secured", "protocol":"native", "nativeReceiver":receiver,
                    "allowedCidrs":["192.0.2.0/24", "2001:db8::/32"], "requireMtls":true
                }),
            )
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
        let uri = format!("/api/v1/ingest/sources/{}", created.json()["id"].as_str().unwrap());
        let mut input = json!({"name":"renamed", "protocol":"native", "nativeReceiver":receiver});
        let preserved = h.request("PUT", &uri, Some(&h.admin), Some(input.clone())).await;
        assert_eq!(preserved.status, StatusCode::OK, "{}", preserved.text);
        assert_eq!(preserved.json()["require_mtls"], true);
        assert_eq!(preserved.json()["allowed_cidrs"].as_array().unwrap().len(), 2);
        input["allowedCidrs"] = json!([]);
        input["requireMtls"] = json!(false);
        let cleared = h.request("PUT", &uri, Some(&h.admin), Some(input)).await;
        assert_eq!(cleared.status, StatusCode::OK, "{}", cleared.text);
        assert_eq!(cleared.json()["allowed_cidrs"], json!([]));
        assert_eq!(cleared.json()["require_mtls"], false);
    }
}
