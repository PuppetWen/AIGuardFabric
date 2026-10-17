//! 采集器上行用例：指纹归一与匹配、授权拒绝、信封解码与原始日志落库（末尾附 Webhook 非轮询语义断言）。

use super::*;

fn registration() -> CollectorRegistration {
    CollectorRegistration {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        collector_id: "collector-site-a-01".to_string(),
        name: "site-a".to_string(),
        site: "site-a".to_string(),
        version: "0.3.1".to_string(),
        enabled: true,
        last_heartbeat_at: Some(Timestamp::now()),
        heartbeat_interval_secs: 30,
        uplink_mode: "privatelink".to_string(),
        cert_fingerprint: Some("AB:CD:EF:01:23:45:67:89".to_string()),
        cert_expires_at: Some(Timestamp::now().offset_secs(86_400 * 90)),
        pending_upload: 0,
        bound_source_ids: vec![],
        created_at: Timestamp::now(),
    }
}

fn envelope(fingerprint: Option<&str>) -> UplinkEnvelope {
    let report = agf_core::agent::AgentReport {
        collector_id: "collector-site-a-01".to_string(),
        collected_at: Timestamp::now(),
        hostname: "app-prod-01".to_string(),
        os: "linux".to_string(),
        os_user: Some("root".to_string()),
        agents: vec![],
        mcp_configs: vec![],
        credential_hits: vec![],
        scan_scope: vec!["/home".to_string()],
        agent_version: "0.3.1".to_string(),
    };
    UplinkEnvelope {
        collector_id: "collector-site-a-01".to_string(),
        cert_fingerprint: fingerprint.map(ToString::to_string),
        report,
        raw_logs: vec![UplinkRawLog {
            payload_b64: B64.encode(SYSLOG),
            origin: "/var/log/auth.log".to_string(),
            protocol: Some("file".to_string()),
        }],
    }
}

#[test]
fn fingerprint_normalization_and_matching() {
    assert_eq!(CollectorUplinkAuth::normalize("AB:cd:EF"), "abcdef");
    assert_eq!(CollectorUplinkAuth::normalize("ab cd-ef"), "abcdef");
    assert!(CollectorUplinkAuth::matches("ab:cd:ef:01:23:45:67:89", "ABCDEF0123456789"));
    assert!(!CollectorUplinkAuth::matches("ab:cd:ef:01:23:45:67:88", "ABCDEF0123456789"));
    assert!(!CollectorUplinkAuth::matches("", "ABCDEF0123456789"));
    assert!(!CollectorUplinkAuth::matches("abc", ""));
}

#[test]
fn collector_authorization_accepts_and_rejects() {
    let now = Timestamp::now();
    let reg = registration();
    assert!(CollectorUplinkAuth::authorize(&reg, "abcdef0123456789", now).is_ok());

    let mut disabled = reg.clone();
    disabled.enabled = false;
    assert!(matches!(
        CollectorUplinkAuth::authorize(&disabled, "abcdef0123456789", now),
        Err(DomainError::Forbidden(_))
    ));

    let mut no_fp = reg.clone();
    no_fp.cert_fingerprint = None;
    assert!(matches!(
        CollectorUplinkAuth::authorize(&no_fp, "abcdef0123456789", now),
        Err(DomainError::Unauthenticated(_))
    ));

    assert!(matches!(
        CollectorUplinkAuth::authorize(&reg, "ffffffffffffffff", now),
        Err(DomainError::Unauthenticated(_))
    ));

    let mut expired = reg.clone();
    expired.cert_expires_at = Some(now.offset_secs(-60));
    let err = CollectorUplinkAuth::authorize(&expired, "abcdef0123456789", now);
    assert!(matches!(err, Err(DomainError::Unauthenticated(_))), "{err:?}");
}

#[test]
fn uplink_envelope_decoding() {
    let payload = serde_json::to_string(&envelope(Some("abcdef0123456789"))).unwrap_or_default();
    let decoded = decode_uplink(payload.as_bytes());
    assert!(decoded.is_ok(), "{decoded:?}");
    let Ok(decoded) = decoded else { return };
    assert_eq!(decoded.collector_id, "collector-site-a-01");
    assert_eq!(decoded.raw_logs.len(), 1);
    let raw = decoded.raw_logs.first();
    assert_eq!(raw.map(UplinkRawLog::decode).and_then(Result::ok), Some(SYSLOG.to_vec()));
    assert_eq!(raw.map(UplinkRawLog::protocol), Some(IngestProtocol::File));
    assert!(decode_uplink(b"not json").is_err());
    assert!(decode_agent_report(b"{}").is_err(), "缺少必填字段应报错");
    let report = serde_json::to_string(&envelope(None).report).unwrap_or_default();
    assert!(decode_agent_report(report.as_bytes()).is_ok());
}

#[test]
fn uplink_raw_log_protocol_fallback() {
    let raw = UplinkRawLog { payload_b64: B64.encode(b"x"), origin: String::new(), protocol: None };
    assert_eq!(raw.protocol(), IngestProtocol::File);
    let syslog =
        UplinkRawLog { payload_b64: B64.encode(b"x"), origin: String::new(), protocol: Some("syslog".to_string()) };
    assert_eq!(syslog.protocol(), IngestProtocol::Syslog);
    let unknown =
        UplinkRawLog { payload_b64: B64.encode(b"x"), origin: String::new(), protocol: Some("bogus".to_string()) };
    assert_eq!(unknown.protocol(), IngestProtocol::File);
    let bad = UplinkRawLog { payload_b64: "!!!".to_string(), origin: String::new(), protocol: None };
    assert!(bad.decode().is_err());
}

#[tokio::test]
async fn collector_uplink_ingests_raw_logs_after_authorization() {
    let (pipeline, sink) = pipeline_and_sink();
    let source = log_source(IngestProtocol::File);
    let receiver = UplinkReceiver::new(registration());
    assert_eq!(receiver.protocol(), IngestProtocol::Mcp);
    let report = receiver.ingest_envelope(&envelope(Some("ABCDEF0123456789")), &pipeline, &source).await;
    assert!(report.is_ok(), "{report:?}");
    let Ok(report) = report else { return };
    assert_eq!(report.raw_logs, 1);
    assert_eq!(report.events, 1);
    assert_eq!(report.rejected, 0);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
}

#[tokio::test]
async fn collector_uplink_rejects_wrong_fingerprint_and_wrong_id() {
    let (pipeline, sink) = pipeline_and_sink();
    let source = log_source(IngestProtocol::File);
    let receiver = UplinkReceiver::new(registration());

    let bad_fp = receiver.ingest_envelope(&envelope(Some("deadbeefdeadbeef")), &pipeline, &source).await;
    assert!(matches!(bad_fp, Err(DomainError::Unauthenticated(_))), "{bad_fp:?}");
    let missing_fp = receiver.ingest_envelope(&envelope(None), &pipeline, &source).await;
    assert!(matches!(missing_fp, Err(DomainError::Unauthenticated(_))));

    let mut other = envelope(Some("abcdef0123456789"));
    other.collector_id = "someone-else".to_string();
    let wrong_id = receiver.ingest_envelope(&other, &pipeline, &source).await;
    assert!(matches!(wrong_id, Err(DomainError::Forbidden(_))), "{wrong_id:?}");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(0), "被拒的上行不得落库");
}

#[tokio::test]
async fn collector_uplink_bytes_path_uses_served_fingerprint() {
    let (pipeline, sink) = pipeline_and_sink();
    let source = log_source(IngestProtocol::File);
    let receiver = UplinkReceiver::new(registration());
    let mut env = envelope(None);
    env.cert_fingerprint = None;
    let payload = serde_json::to_vec(&env).unwrap_or_default();
    let report = receiver.ingest_bytes(&payload, Some("ab:cd:ef:01:23:45:67:89"), &pipeline, &source).await;
    assert!(report.is_ok(), "{report:?}");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(1));
    assert!(receiver.describe().note.contains("mTLS"));

    let rejected = receiver.ingest_bytes(&payload, Some("00:00:00:00:00:00:00:00"), &pipeline, &source).await;
    assert!(matches!(rejected, Err(DomainError::Unauthenticated(_))));
}

#[tokio::test]
async fn webhook_poll_once_is_explicitly_unsupported() {
    let (pipeline, _sink) = pipeline_and_sink();
    let receiver = WebhookReceiver::new(pipeline, log_source(IngestProtocol::Webhook), "/w");
    let result = receiver
        .poll_once(
            Arc::new(IngestPipeline::in_memory(Arc::new(InMemorySink::new()))),
            log_source(IngestProtocol::Webhook),
            1,
        )
        .await;
    assert!(matches!(result, Err(DomainError::NotImplemented(_))));
}
