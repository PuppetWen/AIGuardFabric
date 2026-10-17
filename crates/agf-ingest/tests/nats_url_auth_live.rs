//! Real authentication against the already owned loopback broker; no publications or stream changes.
#![cfg(feature = "nats")]
#![allow(clippy::expect_used, clippy::unwrap_used)]
use agf_ingest::bus::{NatsEventBus, connect_nats};
use agf_ingest::jetstream::AsyncNatsJetStream;
use std::time::Duration;
use url::Url;

#[tokio::test]
#[ignore = "Requires AGF_NATS_AUTH_TEST_URL for the owned authenticated 127.0.0.1:14222 broker"]
async fn owned_nats_url_authentication_accepts_only_correct_credentials() {
    let raw = std::env::var("AGF_NATS_AUTH_TEST_URL").expect("Owned broker credential must be supplied privately");
    let mut url = Url::parse(&raw).expect("Valid private owned broker URL required");
    assert!(url.scheme() == "nats" && url.host_str() == Some("127.0.0.1") && url.port() == Some(14222));
    assert!(url.username() == "agf_phase2" && url.password().is_some_and(|p| !p.is_empty()));
    let timeout = Duration::from_secs(3);
    let client = connect_nats(std::slice::from_ref(&raw), timeout).await.expect("Correct owned broker credentials must authenticate");
    tokio::time::timeout(timeout, client.flush()).await.expect("Owned broker PONG deadline").expect("Authenticated connection must receive broker PONG");
    let subject = format!("agf.auth.check.{}", uuid::Uuid::new_v4().simple());
    let bus = NatsEventBus::connect(&raw, &subject).await.expect("Core event caller must use shared authentication");
    assert_eq!(bus.subject(), subject);
    let inbound = AsyncNatsJetStream::connect(vec![raw.clone()]).await.expect("Inbound caller must use shared authentication");
    let public_debug = format!("{inbound:?}");
    assert!(!public_debug.contains(url.username()) && !public_debug.contains(url.password().unwrap()));
    url.set_password(Some("wrong-agf-owned-test-credential")).unwrap();
    let wrong = connect_nats(&[url.to_string()], timeout).await;
    assert!(wrong.is_err(), "Wrong credentials must fail against the authenticated broker");
    let error = wrong.err().unwrap().to_string();
    assert!(error.contains("authentication failed") && !error.contains("wrong-agf-owned-test-credential"));
    url.set_password(None).unwrap();
    url.set_username("").unwrap();
    let anonymous = connect_nats(&[url.to_string()], timeout).await;
    assert!(anonymous.is_err(), "Anonymous connection must fail while broker authentication remains enabled");
    assert!(anonymous.err().unwrap().to_string().contains("authentication failed"));
    // This test never subscribes, publishes, creates/deletes streams or consumers,
    // or modifies the owned broker or any formal container/configuration.
}
