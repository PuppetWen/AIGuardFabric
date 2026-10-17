//! Real tonic clients exercise three signals, tenant/source separation and retryable failures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use base64::Engine as _;
use std::sync::Arc;

use agf_core::{
    enums::{HealthState, IngestProtocol},
    error::{DomainError, DomainResult},
    event::Event,
    ids::{Id, TenantId},
    source::{CollectionMode, LogSource, SourceConnection},
    time::Timestamp,
};
use agf_ingest::{
    bus::NoopEventBus,
    otlp::{OtlpLogsReceiver, OtlpMetricsReceiver, OtlpTracesReceiver},
    otlp_grpc::{OtlpGrpcConfig, OtlpGrpcServer},
    pipeline::{InMemorySink, IngestConfig, IngestPipeline, Sink},
    registry::ParserRegistry,
};
use opentelemetry_proto::tonic::collector::{logs::v1 as logs, metrics::v1 as metrics, trace::v1 as traces};
use serde_json::json;
use tonic::codec::CompressionEncoding;

fn source(name: &str) -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: name.into(),
        protocol: IngestProtocol::Otlp,
        vendor: "generic".into(),
        product: name.into(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection::default(),
        mode: CollectionMode::Push,
        poll_interval_secs: None,
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
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

async fn start(
    sink: Arc<dyn Sink>,
    batch_limit: usize,
    all_signals: bool,
) -> (String, tokio::task::JoinHandle<DomainResult<()>>) {
    let pipeline = Arc::new(IngestPipeline::new(
        ParserRegistry::with_builtins(),
        sink,
        Arc::new(NoopEventBus),
        IngestConfig { batch_limit, emit_to_bus: false, dedup_window_secs: 0, ..Default::default() },
    ));
    let logs = Arc::new(OtlpLogsReceiver::new(pipeline.clone(), source("otlp-grpc")));
    let mut server = OtlpGrpcServer::bind("127.0.0.1:0", &OtlpGrpcConfig::default(), logs).await.unwrap();
    if all_signals {
        server = server.with_signals(
            Arc::new(OtlpTracesReceiver::new(pipeline.clone(), source("otlp-grpc-traces"))),
            Arc::new(OtlpMetricsReceiver::new(pipeline, source("otlp-grpc-metrics"))),
        );
    }
    let address = format!("http://{}", server.local_addr().unwrap());
    (address, tokio::spawn(server.serve()))
}

fn trace_request() -> traces::ExportTraceServiceRequest {
    serde_json::from_value(json!({"resourceSpans":[{"resource":{"attributes":[
        {"key":"service.name","value":{"stringValue":"checkout"}}
    ]},"scopeSpans":[{"spans":[
        {"name":"first","traceId":"0123456789abcdef0123456789abcdef", "spanId":"0123456789abcdef",
         "startTimeUnixNano":"1770985425000000000","endTimeUnixNano":"1770985425000000010"},
        {"name":"second","traceId":"0123456789abcdef0123456789abcdef", "spanId":"1123456789abcdef"}
    ]}]}]}))
    .unwrap()
}

fn metric_request() -> metrics::ExportMetricsServiceRequest {
    serde_json::from_value(json!({"resourceMetrics":[{"scopeMetrics":[{"metrics":[
        {"name":"requests","sum":{"aggregationTemporality":2,"isMonotonic":true,
         "dataPoints":[{"asInt":"42"},{"asInt":"43"}]}}
    ]}]}]}))
    .unwrap()
}

fn log_request() -> logs::ExportLogsServiceRequest {
    serde_json::from_value(json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[
        {"body":{"stringValue":"first log"}},{"body":{"stringValue":"second log"}}
    ]}]}]}))
    .unwrap()
}

#[tokio::test]
async fn three_services_accept_gzip_and_keep_distinct_sources() {
    let sink = Arc::new(InMemorySink::new());
    let (address, serving) = start(sink.clone(), 100, true).await;
    let mut traces = traces::trace_service_client::TraceServiceClient::connect(address.clone())
        .await
        .unwrap()
        .send_compressed(CompressionEncoding::Gzip);
    let mut metrics = metrics::metrics_service_client::MetricsServiceClient::connect(address.clone())
        .await
        .unwrap()
        .send_compressed(CompressionEncoding::Gzip);
    let mut logs = logs::logs_service_client::LogsServiceClient::connect(address)
        .await
        .unwrap()
        .send_compressed(CompressionEncoding::Gzip);
    assert!(traces.export(trace_request()).await.unwrap().into_inner().partial_success.is_none());
    assert!(metrics.export(metric_request()).await.unwrap().into_inner().partial_success.is_none());
    assert!(logs.export(log_request()).await.unwrap().into_inner().partial_success.is_none());
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.unwrap(), 6);
    let raws = sink.raws().unwrap();
    let sources: std::collections::BTreeSet<_> = raws.iter().map(|raw| raw.source_id).collect();
    assert_eq!(sources.len(), 3);
    let payload = raws
        .iter()
        .map(|raw| {
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(&raw.payload_b64).unwrap()).unwrap()
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(payload.contains("0123456789abcdef0123456789abcdef"));
    assert!(payload.contains("requests"));
    assert!(payload.contains("first log"));
    serving.abort();
}

#[tokio::test]
async fn three_services_report_pipeline_rejections() {
    let sink = Arc::new(InMemorySink::new());
    let (address, serving) = start(sink.clone(), 1, true).await;
    let mut traces = traces::trace_service_client::TraceServiceClient::connect(address.clone()).await.unwrap();
    let mut metrics = metrics::metrics_service_client::MetricsServiceClient::connect(address.clone()).await.unwrap();
    let mut logs = logs::logs_service_client::LogsServiceClient::connect(address).await.unwrap();
    assert_eq!(traces.export(trace_request()).await.unwrap().into_inner().partial_success.unwrap().rejected_spans, 1);
    assert_eq!(
        metrics.export(metric_request()).await.unwrap().into_inner().partial_success.unwrap().rejected_data_points,
        1
    );
    assert_eq!(logs.export(log_request()).await.unwrap().into_inner().partial_success.unwrap().rejected_log_records, 1);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.unwrap(), 3);
    serving.abort();
}

#[tokio::test]
async fn absent_receivers_return_unimplemented_instead_of_accepting_data() {
    let sink = Arc::new(InMemorySink::new());
    let (address, serving) = start(sink.clone(), 100, false).await;
    let mut traces = traces::trace_service_client::TraceServiceClient::connect(address.clone()).await.unwrap();
    let mut metrics = metrics::metrics_service_client::MetricsServiceClient::connect(address).await.unwrap();
    assert_eq!(traces.export(trace_request()).await.unwrap_err().code(), tonic::Code::Unimplemented);
    assert_eq!(metrics.export(metric_request()).await.unwrap_err().code(), tonic::Code::Unimplemented);
    assert_eq!(sink.raw_count(TenantId::default_tenant()).await.unwrap(), 0);
    serving.abort();
}

#[derive(Debug)]
struct OfflineSink;
fn offline<T>() -> DomainResult<T> {
    Err(DomainError::DependencyUnavailable { dependency: "test-storage".into(), cause: "offline".into() })
}
#[async_trait::async_trait]
impl Sink for OfflineSink {
    fn backend(&self) -> &'static str {
        "test-offline"
    }
    async fn put_raw(&self, _: &agf_core::event::RawLog) -> DomainResult<()> {
        offline()
    }
    async fn mark_raw(&self, _: TenantId, _: Id, _: bool, _: Option<Id>, _: Option<&str>) -> DomainResult<()> {
        offline()
    }
    async fn put_event(&self, _: &Event) -> DomainResult<()> {
        offline()
    }
    async fn put_events(&self, _: &[Event]) -> DomainResult<usize> {
        offline()
    }
    async fn get_event(&self, _: TenantId, _: Id) -> DomainResult<Option<Event>> {
        offline()
    }
    async fn unparsed_raw(&self, _: TenantId, _: i64) -> DomainResult<Vec<agf_core::event::RawLog>> {
        offline()
    }
    async fn event_count(&self, _: TenantId) -> DomainResult<u64> {
        offline()
    }
    async fn raw_count(&self, _: TenantId) -> DomainResult<u64> {
        offline()
    }
}

#[tokio::test]
async fn storage_failure_is_retryable_for_every_signal() {
    let (address, serving) = start(Arc::new(OfflineSink), 100, true).await;
    let mut traces = traces::trace_service_client::TraceServiceClient::connect(address.clone()).await.unwrap();
    let mut metrics = metrics::metrics_service_client::MetricsServiceClient::connect(address.clone()).await.unwrap();
    let mut logs = logs::logs_service_client::LogsServiceClient::connect(address).await.unwrap();
    assert_eq!(traces.export(trace_request()).await.unwrap_err().code(), tonic::Code::Unavailable);
    assert_eq!(metrics.export(metric_request()).await.unwrap_err().code(), tonic::Code::Unavailable);
    assert_eq!(logs.export(log_request()).await.unwrap_err().code(), tonic::Code::Unavailable);
    serving.abort();
}
