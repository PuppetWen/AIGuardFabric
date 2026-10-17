//! Connection policy rejects untrusted transport metadata before any evidence is stored.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_core::{
    enums::{HealthState, IngestProtocol},
    ids::{Id, TenantId},
    source::{CollectionMode, LogSource, SourceConnection},
    time::Timestamp,
};
use agf_ingest::{
    otlp::{OtlpLogsReceiver, OtlpMetricsReceiver, OtlpTracesReceiver, signal_router},
    pipeline::{InMemorySink, IngestPipeline, TransportPeer},
};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use std::sync::Arc;
use tower::ServiceExt;
fn log_source(name: &str) -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: name.to_string(),
        protocol: IngestProtocol::Otlp,
        vendor: "generic".to_string(),
        product: "otlp".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Push,
        poll_interval_secs: None,
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 8 * 1_048_576,
        max_eps: 0,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn ipv4_ipv6_and_verified_certificate_are_enforced_before_persistence() {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::in_memory(sink.clone());
    let mut source = log_source("policy");
    source.allowed_cidrs = vec!["192.0.2.0/24".into(), "2001:db8::/32".into()];
    source.require_mtls = true;
    let items = vec![(b"forged origin".to_vec(), "192.0.2.1".to_string())];
    assert!(pipeline.ingest_batch(&source, IngestProtocol::Syslog, &items).await.is_err());
    for (ip, mutual_tls) in [(Some("203.0.113.1"), true), (Some("192.0.2.1"), false), (None, true)] {
        let peer = TransportPeer { ip: ip.map(|ip| ip.parse().unwrap()), mutual_tls };
        assert!(pipeline.ingest_raw_from(&source, IngestProtocol::Syslog, b"raw", "192.0.2.1", peer).await.is_err());
        assert!(pipeline.ingest_batch_from(&source, IngestProtocol::Syslog, &[], peer).await.is_err());
    }
    assert!(sink.raws().unwrap().is_empty());
    for ip in ["192.0.2.1", "2001:db8::9", "::ffff:192.0.2.5"] {
        let peer = TransportPeer { ip: Some(ip.parse().unwrap()), mutual_tls: true };
        pipeline.ingest_raw_from(&source, IngestProtocol::Syslog, ip.as_bytes(), "test", peer).await.unwrap();
    }
    assert_eq!(sink.raws().unwrap().len(), 3);
    source.allowed_cidrs.push("invalid-cidr".into());
    let peer = TransportPeer { ip: Some("192.0.2.1".parse().unwrap()), mutual_tls: true };
    assert!(pipeline.ingest_batch_from(&source, IngestProtocol::Syslog, &items, peer).await.is_err());
    source.allowed_cidrs.clear();
    source.enabled = false;
    assert!(pipeline.ingest_batch_from(&source, IngestProtocol::Syslog, &[], peer).await.is_err());
    assert_eq!(sink.raws().unwrap().len(), 3);
}

#[tokio::test]
async fn http_all_three_signals_ignore_forged_headers_and_use_socket_connect_info() {
    for require_mtls in [false, true] {
        let sink = Arc::new(InMemorySink::new());
        let pipeline = Arc::new(IngestPipeline::in_memory(sink.clone()));
        let mut source = log_source("http-policy");
        source.allowed_cidrs = vec!["192.0.2.0/24".into()];
        source.require_mtls = require_mtls;
        let (app, _) = signal_router(
            Some(Arc::new(OtlpLogsReceiver::new(pipeline.clone(), source.clone()))),
            Some(Arc::new(OtlpTracesReceiver::new(pipeline.clone(), source.clone()))),
            Some(Arc::new(OtlpMetricsReceiver::new(pipeline, source))),
        );
        for path in ["/v1/logs", "/v1/traces", "/v1/metrics"] {
            for ip in [None, Some("203.0.113.1:1234"), Some("192.0.2.1:1234")] {
                let mut request = Request::post(path)
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "192.0.2.1")
                    .header("x-real-ip", "192.0.2.1")
                    .header("x-ssl-client-verify", "SUCCESS")
                    .body(Body::from("{}"))
                    .unwrap();
                if let Some(ip) = ip {
                    request.extensions_mut().insert(ConnectInfo(ip.parse::<std::net::SocketAddr>().unwrap()));
                }
                let status = app.clone().oneshot(request).await.unwrap().status();
                let allowed = !require_mtls && ip == Some("192.0.2.1:1234");
                assert_eq!(
                    status,
                    if allowed { StatusCode::OK } else { StatusCode::FORBIDDEN },
                    "{path}, {ip:?}, mtls={require_mtls}"
                );
            }
        }
        assert!(sink.raws().unwrap().is_empty());
    }
}
