//! Cloud HTTP checks use only loopback listeners and synthetic credentials.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_alicloud::{
    credential::{
        CloudCredential,
        sts_async::{AssumeRoleRequest, assume_role, from_secret_json},
    },
    http::{ReqwestTransport, RpcRequest, RpcResponse, SignStyle, check_response},
};
use agf_core::{error::DomainError, time::Timestamp};
use serde_json::json;
use std::collections::BTreeMap;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, query_param},
};

fn request() -> AssumeRoleRequest {
    AssumeRoleRequest {
        role_arn: "acs:ram::1234567890123456:role/agf-reader".into(),
        session_name: "agf-local-test".into(),
        duration_seconds: 3600,
        external_id: Some("local-external-id".into()),
        policy: None,
    }
}
fn source() -> CloudCredential {
    CloudCredential::long_term("LTAI_LOCAL_TEST_SOURCE", "LOCAL-SOURCE-SECRET")
}
#[tokio::test]
async fn sts_signs_real_local_request_and_validates_temporary_credentials() {
    let server = MockServer::start().await;
    let expiry = Timestamp::now().offset_secs(1800).to_rfc3339();
    Mock::given(method("POST")).and(query_param("Action","AssumeRole")).and(query_param("Version","2015-04-01"))
        .and(query_param("RoleArn",request().role_arn)).and(query_param("ExternalId","local-external-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Credentials":{
            "AccessKeyId":"STS-LOCAL-ACCESS-ID","AccessKeySecret":"LOCAL-TEMPORARY-SECRET","SecurityToken":"LOCAL-TOKEN","Expiration":expiry}})))
        .expect(1).mount(&server).await;
    let outcome = assume_role(&server.uri(), source(), &request(), false).await.unwrap();
    assert_eq!(outcome.credential.security_token.as_deref(), Some("LOCAL-TOKEN"));
    assert!(!outcome.long_lived_risk);
    let requests = server.received_requests().await.unwrap();
    let query = requests[0].url.query_pairs().collect::<BTreeMap<_, _>>();
    assert!(query.get("Signature").is_some_and(|signature| !signature.is_empty()));
    assert!(!requests[0].url.as_str().contains("LOCAL-SOURCE-SECRET"));
    assert!(!format!("{outcome:?}").contains("LOCAL-TEMPORARY-SECRET"));
}
#[tokio::test]
async fn sts_mock_and_bad_requests_never_connect_and_expired_results_fail() {
    let server = MockServer::start().await;
    assert!(assume_role(&server.uri(), source(), &request(), true).await.is_err());
    let mut invalid = request();
    invalid.duration_seconds = 100;
    assert!(matches!(assume_role(&server.uri(), source(), &invalid, false).await, Err(DomainError::Validation(_))));
    assert!(server.received_requests().await.unwrap().is_empty());
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Credentials":{
        "AccessKeyId":"STS-LOCAL-ACCESS-ID","AccessKeySecret":"LOCAL-TEMPORARY-SECRET","SecurityToken":"LOCAL-TOKEN",
        "Expiration":"2001-01-01T00:00:00Z"}})))
        .mount(&server)
        .await;
    assert!(matches!(assume_role(&server.uri(), source(), &request(), false).await, Err(DomainError::Forbidden(_))));
    assert!(
        from_secret_json(r#"{"access_key_id":"TEST","access_key_secret":"SECRET","security_token":"TOKEN"}"#).is_err()
    );
    assert!(assume_role("http://remote.example.test", source(), &request(), false).await.is_err());
}
#[tokio::test]
async fn signed_cloud_requests_do_not_follow_redirects_or_expose_tokens_in_debug_summaries() {
    let source_server = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", target.uri()))
        .expect(1)
        .mount(&source_server)
        .await;
    let req = RpcRequest {
        method: "GET".into(),
        url: source_server.uri(),
        style: SignStyle::Rpc,
        query: "SecurityToken=LOCAL-TOKEN&Signature=LOCAL-SIGNATURE".into(),
        headers: BTreeMap::new(),
        body: String::new(),
    };
    assert!(!req.summary().contains("LOCAL-TOKEN") && !req.summary().contains("LOCAL-SIGNATURE"));
    let transport = ReqwestTransport::with_tls_options(3, None, false).unwrap();
    let response = transport.send_async(&req).await.unwrap();
    assert_eq!(response.status, 302);
    assert!(check_response(&response).is_err());
    assert!(target.received_requests().await.unwrap().is_empty());
}
#[test]
fn business_success_codes_are_accepted_and_explicit_failure_is_rejected() {
    for body in [
        json!({"Code":"SUCCESS","Success":true}),
        json!({"Code":"1","Success":true}),
        json!({"Code":1,"Success":true}),
        json!({"Code":200}),
        json!({"Code":"200"}),
        json!({}),
    ] {
        assert!(check_response(&RpcResponse { status: 200, body, raw: String::new() }).is_ok());
    }
    for body in [
        json!({"Success":false}),
        json!({"Code":500}),
        json!({"Code":"1"}),
        json!({"Code":"1","Success":false}),
        json!({"Code":"InvalidParameter"}),
    ] {
        assert!(check_response(&RpcResponse { status: 200, body, raw: String::new() }).is_err());
    }
}

#[tokio::test]
async fn html_empty_and_non_object_success_responses_are_not_reported_as_success() {
    let server = MockServer::start().await;
    let transport = ReqwestTransport::new(3).unwrap();
    let request = RpcRequest {
        method: "GET".into(),
        url: server.uri(),
        style: SignStyle::Rpc,
        query: String::new(),
        headers: BTreeMap::new(),
        body: String::new(),
    };
    for body in ["<html><body>proxy login required</body></html>", "", "[]", "true", "{broken"] {
        server.reset().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_string(body)).mount(&server).await;
        assert!(matches!(transport.send_async(&request).await, Err(DomainError::Parse(_))));
    }
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(403).set_body_string(
                "<?xml version=\"1.0\"?><Error><Code>Forbidden</Code><Message>denied</Message></Error>",
            ),
        )
        .mount(&server)
        .await;
    let response = transport.send_async(&request).await.unwrap();
    assert_eq!(response.code(), Some("Forbidden"));
    assert!(check_response(&response).is_err());
}
