//! Authenticated HTTP ingestion must preserve the bytes later offered for replay.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use agf_api::source_ingest;
use agf_core::ids::Id;
use agf_ingest::{
    pipeline::InMemorySink,
    receiver::{HttpPullReceiver, WebhookReceiver},
};
use base64::Engine as _;
use common::*;

async fn push_bytes(h: &Harness, uri: &str, bytes: &[u8], token: Option<&str>, tenant: Option<TenantId>) -> Resp {
    let mut request = Request::builder().method("POST").uri(uri).header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(tenant) = tenant {
        request = request.header("x-agf-tenant", tenant.to_string());
    }
    send(&h.app, request.body(Body::from(bytes.to_vec())).unwrap()).await
}

#[tokio::test]
async fn authenticated_http_push_retains_single_json_ndjson_and_array_lexical_bytes() {
    let mut h = setup().await;
    let sink = Arc::new(InMemorySink::new());
    h.state.ingest_sink = sink.clone();
    h.app = build_router(h.state.clone());
    let created = h.post("/api/v1/ingest/sources", json!({"name":"forensic bytes","protocol":"http-webhook"})).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let source = Id::parse(created.json()["id"].as_str().unwrap()).unwrap();
    let uri = format!("/api/v1/ingest/sources/{source}/events");
    let single = b" \t{\r\n  \"original_lexeme\":1e+02, \"escaped\":\"\\u0061\"\r\n}\r\n ";
    assert_eq!(push_bytes(&h, &uri, single, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(push_bytes(&h, &uri, single, Some(&h.viewer), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(push_bytes(&h, &uri, single, Some(&h.admin), Some(h.other_tenant)).await.status, StatusCode::NOT_FOUND,);
    assert!(sink.raws().unwrap().is_empty(), "denied HTTP requests cannot persist raw bytes");
    let cases: &[(&[u8], &[&[u8]])] = &[
        (single, &[single]),
        (
            b"  {\"original_line\":1} \t\r\n\t{\"original_line\":2}  \r\n",
            &[b"  {\"original_line\":1} \t\r\n", b"\t{\"original_line\":2}  \r\n"],
        ),
        (
            br#"[ { "original_number":1e+03, "escaped":"\u0061" }, "\u0062" ]"#,
            &[br#"{ "original_number":1e+03, "escaped":"\u0061" }"#, br#""\u0062""#],
        ),
    ];
    let mut expected_count = 0;
    for (body, originals) in cases {
        let previous = sink.raws().unwrap().len();
        let response = push_bytes(&h, &uri, body, Some(&h.admin), None).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        assert_eq!(response.json()["received"], originals.len());
        assert_eq!(response.json()["accepted"], originals.len());
        let raws = sink.raws().unwrap();
        assert_eq!(raws.len(), previous + originals.len());
        for original in *originals {
            let raw = raws
                .iter()
                .find(|raw| base64::engine::general_purpose::STANDARD.decode(&raw.payload_b64).unwrap() == *original)
                .expect("the actual HTTP pipeline must store each exact record");
            assert_eq!(raw.tenant_id, h.tenant);
            assert_eq!(raw.source_id, source);
            assert_eq!(raw.bytes, original.len());
            assert_eq!(raw.payload_hash, agf_core::secret::content_hash(std::str::from_utf8(original).unwrap()));
        }
        expected_count += originals.len();
    }
    assert_eq!(h.state.ingest_sink.raw_count(h.tenant).await.unwrap(), expected_count as u64);
    assert_eq!(h.state.ingest_sink.raw_count(h.other_tenant).await.unwrap(), 0);
}

#[test]
fn framing_keeps_pretty_json_string_array_and_batch_contracts() {
    let pretty = b"{\r\n  \"original\": 1.00\r\n}\r\n";
    assert_eq!(source_ingest::records(pretty).unwrap(), [pretty.to_vec()]);
    let lines = vec![b"{\r\n".to_vec(), b"  \"original\": 1.00\r\n".to_vec(), b"}\r\n".to_vec()];
    assert_eq!(WebhookReceiver::split_payloads(pretty, 10), lines);
    assert_eq!(HttpPullReceiver::split_records(pretty, 10), lines);
    let strings = br#"["  <34>syslog\r\n", "\u0061"]"#;
    assert_eq!(WebhookReceiver::split_payloads(strings, 1), [b"  <34>syslog\r\n".to_vec()]);
    assert_eq!(HttpPullReceiver::split_records(strings, 1), [br#""  <34>syslog\r\n""#.to_vec()]);
    assert_eq!(source_ingest::records(strings).unwrap()[1], br#""\u0061""#);
    let array = br#"[ { "n":1e+02, "s":"\u0061" }, { "n":2.00 } ]"#;
    let expected = vec![br#"{ "n":1e+02, "s":"\u0061" }"#.to_vec(), br#"{ "n":2.00 }"#.to_vec()];
    assert_eq!(source_ingest::records(array).unwrap(), expected);
    assert_eq!(WebhookReceiver::split_payloads(array, 2), expected);
    assert_eq!(HttpPullReceiver::split_records(array, 2), expected);
    let too_many = format!("[{}]", vec!["{}"; 1001].join(","));
    assert!(source_ingest::records(too_many.as_bytes()).is_err());
    assert!(source_ingest::records(&vec![b'x'; 2 * 1024 * 1024 + 1]).is_err());
    assert!(source_ingest::records(b"\xff").is_err(), "API UTF-8 validation stays unchanged");
}
