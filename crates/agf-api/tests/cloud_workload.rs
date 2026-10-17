//! ECS IMDSv2/OIDC 联调只访问随机本地端口；不读取实际主机身份。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_alicloud::credential::{sts_async::AssumeRoleRequest, workload};
use agf_core::{cloud::CloudCredentialKind, ids::TenantId, time::Timestamp};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

fn temporary() -> Value {
    json!({"Code":"Success","AccessKeyId":"LOCAL-AK","AccessKeySecret":"LOCAL-SECRET",
    "SecurityToken":"LOCAL-TOKEN","Expiration":Timestamp::now().offset_secs(1800).to_rfc3339()})
}
fn role() -> AssumeRoleRequest {
    AssumeRoleRequest {
        role_arn: "acs:ram::1234567890123456:role/local-test".into(),
        session_name: "local-session".into(),
        duration_seconds: 3600,
        external_id: None,
        policy: None,
    }
}
#[tokio::test]
async fn ecs_uses_imdsv2_and_never_falls_back_to_unauthenticated_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/latest/api/token"))
        .and(header("x-aliyun-ecs-metadata-token-ttl-seconds", "21600"))
        .respond_with(ResponseTemplate::new(200).set_body_string("LOCAL-METADATA-TOKEN"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/latest/meta-data/ram/security-credentials/"))
        .and(header("x-aliyun-ecs-metadata-token", "LOCAL-METADATA-TOKEN"))
        .respond_with(ResponseTemplate::new(200).set_body_string("test-role"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/latest/meta-data/ram/security-credentials/test-role"))
        .and(header("x-aliyun-ecs-metadata-token", "LOCAL-METADATA-TOKEN"))
        .respond_with(ResponseTemplate::new(200).set_body_json(temporary()))
        .expect(1)
        .mount(&server)
        .await;
    let credential = workload::ecs_role(&server.uri(), None, false).await.unwrap();
    assert_eq!(credential.kind, CloudCredentialKind::InstanceRole);
    assert!(credential.expires_at.is_some());
    assert!(!format!("{credential:?}").contains("LOCAL-SECRET"));
    server.verify().await;
    server.reset().await;
    Mock::given(method("PUT")).respond_with(ResponseTemplate::new(405)).mount(&server).await;
    assert!(workload::ecs_role(&server.uri(), Some("test-role"), false).await.is_err());
    let calls = server.received_requests().await.unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, "PUT");
}
#[tokio::test]
async fn oidc_exchange_posts_the_token_in_form_and_redacts_error_responses() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Credentials":temporary()})))
        .mount(&server)
        .await;
    let provider = "acs:ram::1234567890123456:oidc-provider/local";
    let token = "LOCAL.TOKEN+WITH&SYMBOLS";
    let credential = workload::oidc_role(&server.uri(), &role(), provider, token, false).await.unwrap();
    assert_eq!(credential.kind, CloudCredentialKind::WorkloadIdentity);
    let calls = server.received_requests().await.unwrap();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].url.query().is_none());
    let form = url::form_urlencoded::parse(&calls[0].body).into_owned().collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(form["OIDCToken"], token);
    assert_eq!(form["Action"], "AssumeRoleWithOIDC");
    assert!(!form.contains_key("Signature") && !form.contains_key("AccessKeyId"));
    server.reset().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(403).set_body_string(token)).mount(&server).await;
    let error = workload::oidc_role(&server.uri(), &role(), provider, token, false).await.unwrap_err();
    assert!(!error.to_string().contains(token));
}
#[tokio::test]
async fn mock_invalid_metadata_and_expired_workload_credentials_fail_without_external_calls() {
    let server = MockServer::start().await;
    assert!(workload::ecs_role(&server.uri(), None, true).await.is_err());
    assert!(workload::ecs_role("http://arbitrary.example", None, false).await.is_err());
    assert!(workload::oidc_role(&server.uri(), &role(), "unused", "unused", true).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
    let mut expired = temporary();
    expired["Expiration"] = json!("2001-01-01T00:00:00Z");
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Credentials":expired})))
        .mount(&server)
        .await;
    assert!(
        workload::oidc_role(
            &server.uri(),
            &role(),
            "acs:ram::1234567890123456:oidc-provider/local",
            "LOCAL-TOKEN",
            false
        )
        .await
        .is_err()
    );
}
#[test]
fn host_identity_allowlist_is_explicit_and_tenant_scoped() {
    let tenant = TenantId::default_tenant();
    assert!(!agf_api::cloud_credentials::tenant_allowed(tenant, ""));
    assert!(!agf_api::cloud_credentials::tenant_allowed(tenant, "*"));
    assert!(agf_api::cloud_credentials::tenant_allowed(tenant, &format!(" invalid, {tenant} ")));
    assert!(!agf_api::cloud_credentials::tenant_allowed(TenantId::new(), &tenant.to_string()));
}
