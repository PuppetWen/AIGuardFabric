//! Configuration is durable/encrypted; explicit TCP probes never send business data.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use tokio::io::AsyncReadExt;

const PATH: &str = "/api/v1/integrations/adapters/webhook/configuration";
#[tokio::test]
async fn smtp_and_syslog_tcp_probes_use_the_actual_transport_settings() {
    let mut h = setup().await;
    std::sync::Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = agf_api::build_router(h.state.clone());
    for vendor in ["email", "syslog-forwarder"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let settings = if vendor == "email" {
            json!({"smtp_host":"127.0.0.1","smtp_port":address.port(),"from":"agf@example.test",
                "to":"soc@example.test","smtp_security":"none"})
        } else {
            json!({"endpoint":format!("syslog://{address}"),"protocol":"tcp"})
        };
        let saved = h
            .request(
                "PUT",
                &format!("/api/v1/integrations/adapters/{vendor}/configuration"),
                Some(&h.admin),
                Some(json!({"expected_version":0,"enabled":true,"mock":false,"settings":settings})),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
        let receive = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut byte = [0_u8; 1];
            connection.read(&mut byte).await.unwrap()
        });
        let probe = h.post(&format!("/api/v1/integrations/adapters/{vendor}/probe"), json!({})).await;
        assert_eq!(probe.json()["tcp_reachable"], true, "{}", probe.text);
        assert_eq!(probe.json()["port"], address.port());
        assert_eq!(receive.await.unwrap(), 0);
    }
}
async fn save(h: &Harness, version: u64, secrets: Value, mock: bool) -> Resp {
    h.request(
        "PUT",
        PATH,
        Some(&h.admin),
        Some(json!({"expected_version":version,"enabled":true,
        "mock":mock,"settings":{},"secrets":secrets})),
    )
    .await
}
#[tokio::test]
async fn configuration_masks_secrets_and_rejects_cross_tenant_and_stale_updates() {
    let h = setup().await;
    let created = save(
        &h,
        0,
        json!({"webhook_url":"http://127.0.0.1:18088/private-SECRET","auth_header_value":"Bearer TEST-SECRET"}),
        false,
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert_eq!(created.json()["version"], 1);
    assert!(!created.text.contains("TEST-SECRET") && !created.text.contains("private-SECRET"));
    let row = agf_api::integration_store::load(&h.state, h.tenant, "webhook").await.unwrap().unwrap();
    assert!(!serde_json::to_string(&row).unwrap().contains("SECRET"));
    assert!(!format!("{row:?}").contains("SECRET"));
    assert_eq!(
        agf_api::integration_store::decrypt(&h.state, h.tenant, &row).unwrap().secrets["auth_header_value"],
        "Bearer TEST-SECRET"
    );
    assert!(agf_api::integration_store::decrypt(&h.state, h.other_tenant, &row).is_err());
    let updated = save(&h, 1, json!({"webhook_url":"","auth_header_value":""}), false).await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.json()["secret_keys"].as_array().unwrap().len(), 2);
    assert_eq!(save(&h, 1, json!({}), false).await.status, StatusCode::CONFLICT);
    assert_eq!(h.request("GET", PATH, Some(&h.viewer), None).await.status, StatusCode::FORBIDDEN);
    let foreign = h
        .request_with(
            "GET",
            PATH,
            &[("Authorization", &format!("Bearer {}", h.admin)), ("X-AGF-Tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(foreign.status, StatusCode::OK);
    assert_eq!(foreign.json()["version"], 0);
    let invalid = save(&h, 2, json!({"unknown_secret":"nope"}), false).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.get(PATH).await.json()["version"], 2);
}

#[tokio::test]
async fn live_tcp_probe_reaches_local_server_without_sending_credentials_or_messages() {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/private-secret-path", listener.local_addr().unwrap());
    assert_eq!(
        save(&h, 0, json!({"webhook_url":endpoint,"auth_header_value":"Bearer PRIVATE"}), false).await.status,
        StatusCode::OK
    );
    let receive = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut data = [0_u8; 128];
        tokio::time::timeout(std::time::Duration::from_secs(2), socket.read(&mut data)).await.unwrap().unwrap()
    });
    let probe = h.post("/api/v1/integrations/adapters/webhook/probe", json!({})).await;
    assert_eq!(probe.status, StatusCode::OK, "{}", probe.text);
    assert_eq!(probe.json()["tcp_reachable"], true);
    assert_eq!(probe.json()["mocked"], false);
    assert!(!probe.text.contains("private-secret-path") && !probe.text.contains("PRIVATE"));
    assert_eq!(receive.await.unwrap(), 0, "TCP check must not send HTTP payloads");
    assert_eq!(h.get(PATH).await.json()["probe"]["tcp_reachable"], true);
    let unavailable = h.post("/api/v1/integrations/adapters/webhook/probe", json!({})).await;
    assert_eq!(unavailable.json()["tcp_reachable"], false);
}

#[tokio::test]
async fn mock_probe_is_explicit_and_endpoint_change_does_not_reuse_credentials() {
    let h = setup().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/original", listener.local_addr().unwrap());
    assert_eq!(
        save(&h, 0, json!({"webhook_url":endpoint,"auth_header_value":"Bearer SECRET"}), true).await.status,
        StatusCode::OK
    );
    let probe = h.post("/api/v1/integrations/adapters/webhook/probe", json!({})).await;
    assert_eq!(probe.json()["mocked"], true);
    assert_eq!(probe.json()["tcp_reachable"], Value::Null);
    assert!(tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept()).await.is_err());
    let changed = save(&h, 1, json!({"webhook_url":"http://127.0.0.1:18099/new"}), true).await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(changed.json()["secret_keys"], json!(["webhook_url"]));
    assert_eq!(changed.json()["probe"], Value::Null, "old probe must not describe a new configuration");
    let list = h.get("/api/v1/integrations/adapters").await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.text);
    assert!(list.json().as_array().unwrap().iter().any(|row| row["id"] == "webhook" && row["mock"] == true));
}
