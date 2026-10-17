use super::{client::WireResponse, *};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::json;

pub(super) fn key() -> ConfigKey {
    ConfigKey { namespace_id: "namespace-owned".into(), group: "AGF".into(), data_id: "policy + 中文.json".into() }
}
pub(super) fn credential() -> CloudCredential {
    CloudCredential::long_term("owned-vector-ak", "owned-sdk-vector-secret")
}
fn wire(status: u16, body: serde_json::Value) -> WireResponse {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json; charset=UTF-8"));
    WireResponse { status, headers, body: body.to_string().into_bytes() }
}
fn observation(content: &str) -> WireResponse {
    let mut response = wire(200, json!({"code":0,"message":"success","data":content}));
    response.headers.insert("content-md5", HeaderValue::from_str(&query::content_md5(content)).unwrap());
    response
}

#[test]
fn classic_ram_matches_independently_generated_utf8_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!("fixtures/signing-vectors.json")).unwrap();
    use sha2::{Digest as _, Sha256};
    assert_eq!(
        hex::encode(Sha256::digest(vectors["sourceExcerpt"].as_str().unwrap().as_bytes())).to_ascii_uppercase(),
        vectors["sourceExcerptSha256"].as_str().unwrap()
    );
    for vector in vectors["vectors"].as_array().unwrap() {
        let identity = ConfigKey {
            namespace_id: vector["namespaceId"].as_str().unwrap().into(),
            group: vector["group"].as_str().unwrap().into(),
            data_id: "driver-owned.json".into(),
        };
        assert_eq!(
            signing::signature(&identity, "owned-sdk-vector-secret", 1_760_000_000_000).unwrap(),
            vector["signature"].as_str().unwrap()
        );
    }
}

#[test]
fn sts_token_is_sensitive_and_never_changes_the_classic_signature() {
    let mut sts = credential();
    sts.security_token = Some("owned-test-sts-secret".into());
    let headers = signing::headers(&key(), &sts, 1_760_000_000_000).unwrap();
    assert_eq!(headers["spas-signature"], "wk7XGH5/2vKSEXtqCxfcysaMh4U=");
    assert_eq!(headers["spas-securitytoken"], "owned-test-sts-secret");
    assert!(headers["spas-accesskey"].is_sensitive());
    assert!(headers["spas-signature"].is_sensitive());
    assert!(headers["spas-securitytoken"].is_sensitive());
    assert!(!format!("{headers:?}").contains("owned-test-sts-secret"));
    sts.security_token = Some("bad\r\ninjected: yes".into());
    assert!(signing::headers(&key(), &sts, 1_760_000_000_000).is_err());
}

#[test]
fn origins_are_explicit_and_cannot_override_path_or_credentials() {
    assert!(EngineEndpoint::https("https://engine.example:8848").is_ok());
    assert!(EngineEndpoint::literal_loopback_for_test("http://127.0.0.1:8848").is_ok());
    assert!(EngineEndpoint::literal_loopback_for_test("http://[::1]:8848").is_ok());
    for origin in [
        "http://engine.example",
        "https://ak:secret@engine.example",
        "https://engine.example/nacos",
        "https://engine.example/?token=secret",
        "https://engine.example/#fragment",
        " https://engine.example",
        "https://engine.example\n",
        "https:\\engine.example",
    ] {
        assert!(EngineEndpoint::https(origin).is_err(), "unexpected accepted origin {origin}");
    }
    for origin in ["http://localhost:8848", "http://192.168.1.2:8848", "https://127.0.0.1:8848"] {
        assert!(EngineEndpoint::literal_loopback_for_test(origin).is_err());
    }
}

#[test]
fn empty_and_unicode_content_are_verified_without_normalizing_line_endings() {
    assert_eq!(query::content_md5(""), "d41d8cd98f00b204e9800998ecf8427e");
    for content in ["", "{\"说明\":\"值 + & =\"}\r\n", "\n"] {
        let result = query::parse(&key(), observation(content), 256 * 1024).unwrap();
        assert_eq!(result.content, content);
        assert_eq!(result.md5, query::content_md5(content));
        assert!(!format!("{result:?}").contains("说明"));
    }
    let mut mismatch = observation("exact\r\n");
    mismatch.headers.insert("content-md5", HeaderValue::from_str(&query::content_md5("exact\n")).unwrap());
    assert!(query::parse(&key(), mismatch, 256 * 1024).is_err());
}

#[test]
fn query_requires_one_valid_md5_and_rejects_special_configuration_headers() {
    let mut missing = observation("data");
    missing.headers.remove("content-md5");
    assert!(query::parse(&key(), missing, 10).is_err());
    let mut duplicate = observation("data");
    duplicate.headers.append("content-md5", HeaderValue::from_static("8d777f385d3dfec8815d20f7496026dc"));
    assert!(query::parse(&key(), duplicate, 10).is_err());
    for (name, value) in [("encrypted-data-key", "cipher-key"), ("vipserver-tag", "tag-a"), ("isbeta", "true")] {
        let mut special = observation("data");
        special.headers.insert(
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        assert!(matches!(query::parse(&key(), special, 10), Err(DomainError::PreconditionFailed(_))));
    }
    assert!(query::parse(&key(), observation("long content"), 4).is_err());
}

#[test]
fn query_does_not_turn_html_or_unstructured_absence_into_not_found() {
    let absent = wire(404, json!({"code":20004,"message":"not found"}));
    assert!(matches!(query::parse(&key(), absent, 10), Err(DomainError::NotFound { .. })));
    for response in [
        wire(404, json!({"code":30000,"message":"proxy error"})),
        wire(404, json!({"code":20004,"message":"not found","data":{"exists":false}})),
        wire(200, json!({"code":0,"message":"success","data":{"content":"data"}})),
    ] {
        assert!(query::parse(&key(), response, 10).is_err());
    }
}

#[test]
fn only_the_pinned_cas_error_is_a_conflict() {
    assert_eq!(publish::classify(&wire(500, json!({"code":20005,"message":"conflict"}))), PublishOutcome::Conflict);
    for (status, body) in [
        (500, json!({"code":30000,"message":"ordinary failure"})),
        (409, json!({"code":20005,"message":"not the pinned CAS protocol"})),
        (500, json!({"code":0,"message":"CAS fail"})),
        (200, json!({"code":20005,"message":"conflict"})),
    ] {
        assert_eq!(publish::classify(&wire(status, body)), PublishOutcome::Uncertain(UncertainReason::Protocol));
    }
}

#[test]
fn accepted_and_rejected_envelopes_do_not_guess_success_from_status_or_messages() {
    assert_eq!(
        publish::classify(&wire(200, json!({"code":0,"message":"success","data":true}))),
        PublishOutcome::Accepted
    );
    assert_eq!(
        publish::classify(&wire(403, json!({"code":10001,"message":"denied"}))),
        PublishOutcome::Rejected { http_status: 403, provider_code: 10001 }
    );
    for body in [
        json!({"code":0,"message":"success","data":false}),
        json!({"code":0,"message":"success","data":"true"}),
        json!({"code":0,"message":"success"}),
        json!({"code":0,"message":"success","data":true,"extra":true}),
    ] {
        assert_eq!(publish::classify(&wire(200, body)), PublishOutcome::Uncertain(UncertainReason::Protocol));
    }
    let mut duplicate = wire(200, json!({}));
    duplicate.body = br#"{"code":30000,"code":0,"message":"success","data":true}"#.to_vec();
    assert_eq!(publish::classify(&duplicate), PublishOutcome::Uncertain(UncertainReason::Protocol));
}

#[test]
fn identity_and_call_budget_validation_are_bounded() {
    assert!(key().validate().is_ok());
    let mut invalid = key();
    invalid.namespace_id = "public".into();
    assert!(invalid.validate().is_err());
    invalid.namespace_id.clear();
    invalid.group = "AGF\nother".into();
    assert!(invalid.validate().is_err());
    assert!(Limits { timeout: Duration::from_secs(31), ..Limits::default() }.validate().is_err());
    assert!(Limits { max_response_bytes: 0, ..Limits::default() }.validate().is_err());
    assert!(Limits { max_content_bytes: 256 * 1024 + 1, ..Limits::default() }.validate().is_err());
}
