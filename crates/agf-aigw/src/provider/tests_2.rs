//! 由 `provider.rs` 拆分：`sigv4_signature_is_deterministic_and_well_formed` 等 11 个函数（纯搬移，逻辑不变）。
use super::*;

#[test]
pub(crate) fn sigv4_signature_is_deterministic_and_well_formed() {
    let creds = AwsCredentials {
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    };
    let body = br#"{"messages":[]}"#;
    let now = Timestamp::from_unix_secs(1_700_000_000).unwrap_or_else(|e| panic!("{e}"));
    let input = SigV4Input {
        method: "POST",
        url: "https://bedrock-runtime.us-east-1.amazonaws.com/model/m/converse",
        body,
        region: "us-east-1",
        service: "bedrock",
        credentials: &creds,
        now,
    };
    let headers = sign_sigv4(&input).unwrap_or_else(|e| panic!("{e}"));
    let auth = headers.get("authorization").cloned().unwrap_or_default();
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"), "{auth}");
    assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"), "{auth}");
    assert!(auth.contains("Signature="));
    eq!(headers.get("x-amz-date").map(String::as_str), Some("20231114T221320Z"));
    eq!(headers.get("x-amz-content-sha256").map(String::as_str), Some(hex::encode(Sha256::digest(body)).as_str()));
    let again = sign_sigv4(&input).unwrap_or_else(|e| panic!("{e}"));
    eq!(again, headers, "同一输入必须产生同一签名");
}

#[test]
pub(crate) fn sigv4_signature_changes_with_body_and_includes_sts_token() {
    let creds = AwsCredentials {
        access_key_id: "AK".into(),
        secret_access_key: "SK".into(),
        session_token: Some("STS-TOKEN".into()),
    };
    let now = Timestamp::from_unix_secs(1_700_000_000).unwrap_or_else(|e| panic!("{e}"));
    let h1 = sign_sigv4(&SigV4Input {
        method: "POST",
        url: "https://a.example.com/x",
        body: b"{\"a\":1}",
        region: "cn-north-1",
        service: "bedrock",
        credentials: &creds,
        now,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let h2 = sign_sigv4(&SigV4Input {
        method: "POST",
        url: "https://a.example.com/x",
        body: b"{\"a\":2}",
        region: "cn-north-1",
        service: "bedrock",
        credentials: &creds,
        now,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(h1.get("authorization"), h2.get("authorization"), "请求体变化必须改变签名");
    eq!(h1.get("x-amz-security-token").map(String::as_str), Some("STS-TOKEN"));
    assert!(h1.get("authorization").cloned().unwrap_or_default().contains("Credential=AK/"));
}

#[test]
pub(crate) fn sigv4_rejects_url_without_host() {
    let creds = AwsCredentials { access_key_id: "a".into(), secret_access_key: "b".into(), session_token: None };
    let err = sign_sigv4(&SigV4Input {
        method: "POST",
        url: "https:///path",
        body: b"",
        region: "r",
        service: "s",
        credentials: &creds,
        now: Timestamp::now(),
    })
    .err();
    assert!(err.is_some());
}

#[test]
pub(crate) fn url_helpers() {
    eq!(
        host_of("https://bedrock-runtime.us-east-1.amazonaws.com/model/x/converse").as_deref(),
        Some("bedrock-runtime.us-east-1.amazonaws.com")
    );
    eq!(path_of("https://h/model/x/converse"), "/model/x/converse");
    eq!(path_of("https://h"), "/");
    eq!(path_of("https://h?a=1"), "/");
    assert!(host_of("https://").is_none());
}

#[test]
pub(crate) fn data_uri_split_and_decode() {
    let (mime, data) = split_data_uri("data:image/png;base64,aGVsbG8=").unwrap_or_else(|| panic!("应解析成功"));
    eq!(mime, "image/png");
    eq!(data, "aGVsbG8=");
    let bytes = decode_data_uri("data:image/png;base64,aGVsbG8=").unwrap_or_else(|e| panic!("{e}"));
    eq!(String::from_utf8_lossy(&bytes), "hello");
    assert!(split_data_uri("https://x/y.png").is_none());
    assert!(decode_data_uri("not-a-data-uri").is_err());
    assert!(split_data_uri("data:image/png;base64,").is_none());
}

#[test]
pub(crate) fn endpoint_gate_helper() {
    let ep = endpoint(LlmProvider::OpenAi, None);
    assert!(endpoint_allows(&ep, DataClass::Public));
    assert!(!endpoint_allows(&ep, DataClass::Restricted), "云端端点不得承接受限数据");
    let mut disabled = endpoint(LlmProvider::OpenAi, None);
    disabled.enabled = false;
    assert!(!endpoint_allows(&disabled, DataClass::Public));
}

#[test]
pub(crate) fn unconfigured_error_is_degradable() {
    assert!(unconfigured_error("x").is_degradable());
}

#[test]
pub(crate) fn http_status_mapping() {
    let e = http_status_error("p", reqwest::StatusCode::TOO_MANY_REQUESTS, "rate limited");
    assert!(e.is_degradable(), "429 应可重试");
    let e = http_status_error("p", reqwest::StatusCode::BAD_REQUEST, "bad request");
    assert!(matches!(e, DomainError::Config(_)), "400 是配置/参数问题，不重试");
    let e = http_status_error("p", reqwest::StatusCode::BAD_GATEWAY, "upstream");
    assert!(e.is_degradable());
}

#[test]
pub(crate) fn upstream_error_body_does_not_escape_in_diagnostics() {
    let secret = "private-prompt-and-api-key";
    for status in
        [reqwest::StatusCode::BAD_REQUEST, reqwest::StatusCode::TOO_MANY_REQUESTS, reqwest::StatusCode::BAD_GATEWAY]
    {
        let error = http_status_error("fixture", status, secret);
        assert!(!error.to_string().contains(secret));
        assert!(error.to_string().contains(&status.as_u16().to_string()));
    }
}

#[test]
pub(crate) fn anthropic_and_gemini_urls() {
    let a = AnthropicProvider::new("claude-3-5-sonnet-20241022", "", None);
    eq!(a.messages_url(), "https://api.anthropic.com/v1/messages");
    eq!(a.api_version, "2023-06-01");
    let g = GeminiProvider::new("gemini-1.5-pro", "", None);
    assert!(g.generate_url().ends_with("/models/gemini-1.5-pro:generateContent"));
    assert!(g.stream_url().ends_with(":streamGenerateContent?alt=sse"));
}

#[test]
pub(crate) fn anthropic_version_header_can_be_overridden() {
    let mut ep = endpoint(LlmProvider::Anthropic, None);
    ep.extra_headers.insert("anthropic-version".into(), "2024-01-01".into());
    let p = AnthropicProvider::from_endpoint(&ep, &MockCredentialResolver);
    eq!(p.api_version, "2024-01-01");
}

#[test]
pub(crate) fn default_max_tokens_constant_is_positive() {
    assert!(matches!(ANTHROPIC_DEFAULT_MAX_TOKENS, 1..=u32::MAX));
}
