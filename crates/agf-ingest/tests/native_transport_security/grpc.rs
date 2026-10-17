//! Real TCP/TLS verifies all signal paths; SQL policy edits apply to existing channels.
use super::*;
use agf_core::source::SourceRecord;
use agf_ingest::{
    otlp::{OtlpMetricsReceiver, OtlpTracesReceiver},
    pipeline::{NativeSourceControl, SqlSink},
};
use agf_storage::{Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};
use opentelemetry_proto::tonic::collector::{metrics::v1 as metrics, trace::v1 as traces};

async fn server(
    pipeline: Arc<IngestPipeline>,
    sources: &[LogSource],
    tls: OtlpGrpcTlsConfig,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let config = OtlpGrpcConfig { listen: "127.0.0.1:0".into(), tls, ..Default::default() };
    let server = OtlpGrpcServer::bind(
        &config.listen,
        &config,
        Arc::new(OtlpLogsReceiver::new(pipeline.clone(), sources[0].clone())),
    )
    .await
    .unwrap()
    .with_signals(
        Arc::new(OtlpTracesReceiver::new(pipeline.clone(), sources[1].clone())),
        Arc::new(OtlpMetricsReceiver::new(pipeline, sources[2].clone())),
    );
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        server.serve().await.unwrap();
    });
    (address, task)
}

fn sources() -> Vec<LogSource> {
    ["otlp-grpc", "otlp-grpc-traces", "otlp-grpc-metrics"]
        .into_iter()
        .map(|receiver| {
            let mut source = log_source();
            source.product = receiver.into();
            source.name = receiver.into();
            source.allowed_cidrs = vec!["127.0.0.1/32".into()];
            source.require_mtls = true;
            source
        })
        .collect()
}

async fn exports(channel: Channel, allowed: bool, tag: &str) {
    let mut logs = LogsServiceClient::new(channel.clone());
    let mut traces = traces::trace_service_client::TraceServiceClient::new(channel.clone());
    let mut metrics = metrics::metrics_service_client::MetricsServiceClient::new(channel);
    let mut request = tonic::Request::new(request_with(1, tag));
    request.metadata_mut().insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
    request.metadata_mut().insert("x-ssl-client-verify", "SUCCESS".parse().unwrap());
    let results = [
        logs.export(request).await.map(|_| ()),
        traces.export(serde_json::from_value::<traces::ExportTraceServiceRequest>(serde_json::json!({
            "resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"01010101010101010101010101010101", "spanId":"0202020202020202", "name":tag, "startTimeUnixNano":"1770985425000000000", "endTimeUnixNano":"1770985425001000000"}]}]}]
        })).unwrap()).await.map(|_| ()),
        metrics.export(serde_json::from_value::<metrics::ExportMetricsServiceRequest>(serde_json::json!({
            "resourceMetrics":[{"scopeMetrics":[{"metrics":[{"name":tag, "gauge":{"dataPoints":[{"asDouble":1.0,"timeUnixNano":"1770985425000000000"}]}}]}]}]
        })).unwrap()).await.map(|_| ()),
    ];
    for result in results {
        if allowed {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
        }
    }
}

#[tokio::test]
async fn plaintext_cannot_forge_mtls_for_any_grpc_signal() {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = Arc::new(IngestPipeline::in_memory(sink.clone()));
    let (address, task) = server(pipeline, &sources(), OtlpGrpcTlsConfig::default()).await;
    let channel = Endpoint::from_shared(format!("http://{address}")).unwrap().connect().await.unwrap();
    exports(channel, false, "forged-client-certificate").await;
    assert!(sink.raws().unwrap().is_empty());
    task.abort();
    let _ = task.await;
}

async fn secure_channel(pki: &Pki, address: SocketAddr) -> Channel {
    let tls = ClientTlsConfig::new()
        .domain_name("127.0.0.1")
        .ca_certificate(Certificate::from_pem(std::fs::read(&pki.ca).unwrap()))
        .identity(Identity::from_pem(
            std::fs::read(&pki.client_cert).unwrap(),
            std::fs::read(&pki.client_key).unwrap(),
        ));
    Endpoint::from_shared(format!("https://{address}")).unwrap().tls_config(tls).unwrap().connect().await.unwrap()
}

fn tls(pki: &Pki) -> OtlpGrpcTlsConfig {
    OtlpGrpcTlsConfig {
        enabled: true,
        cert_pem: Some(pki.server_cert.clone()),
        key_pem: Some(pki.server_key.clone()),
        client_ca_pem: Some(pki.ca.clone()),
    }
}

#[tokio::test]
async fn verified_mtls_reaches_all_grpc_pipelines_with_the_real_peer() {
    let pki = make_pki("source-policy");
    let sink = Arc::new(InMemorySink::new());
    let pipeline = Arc::new(IngestPipeline::in_memory(sink.clone()));
    let (address, task) = server(pipeline, &sources(), tls(&pki)).await;
    exports(secure_channel(&pki, address).await, true, "verified").await;
    assert_eq!(sink.raws().unwrap().len(), 3);
    task.abort();
    let _ = task.await;
}

#[tokio::test]
#[ignore = "requires AGF_TEST_DATABASE_URL for an isolated agf_requirements_test_ database"]
async fn sql_edits_restrict_existing_grpc_channels_and_survive_receiver_restart() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let sources = sources();
    let configurations = ConfigStore::new(Some(store.clone()));
    let build = || {
        Arc::new(
            IngestPipeline::new(
                ParserRegistry::with_builtins(),
                Arc::new(SqlSink::new(store.clone())),
                Arc::new(NoopEventBus),
                IngestConfig { emit_to_bus: false, ..Default::default() },
            )
            .with_source_control(Arc::new(NativeSourceControl::new(
                Some(store.clone()),
                ParserRegistry::with_builtins(),
            ))),
        )
    };
    let pki = make_pki("sql-policy");
    let (address, task) = server(build(), &sources, tls(&pki)).await;
    let channel = secure_channel(&pki, address).await;
    exports(channel.clone(), true, "before-edit").await;
    for source in &sources {
        configurations
            .mutate::<SourceRecord, _>(source.tenant_id, "log-source", source.id, |row| {
                row.source.as_mut().unwrap().allowed_cidrs = vec!["192.0.2.0/24".into()];
                Ok(())
            })
            .await
            .unwrap();
    }
    exports(channel.clone(), false, "denied-live-update").await;
    // Empty exports cannot conceal a blocked source either.
    assert_eq!(
        LogsServiceClient::new(channel).export(ExportLogsServiceRequest::default()).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    task.abort();
    let _ = task.await;
    let (address, task) = server(build(), &sources, tls(&pki)).await;
    let channel = secure_channel(&pki, address).await;
    exports(channel.clone(), false, "denied-after-restart").await;
    for source in &sources {
        configurations
            .mutate::<SourceRecord, _>(source.tenant_id, "log-source", source.id, |row| {
                row.source.as_mut().unwrap().allowed_cidrs = vec!["127.0.0.1/32".into()];
                Ok(())
            })
            .await
            .unwrap();
    }
    exports(channel, true, "restored").await;
    for source in &sources {
        let mut tx = store.db().begin_tenant(source.tenant_id).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM raw_logs WHERE source_id=$1")
            .bind(source.id.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 2);
        tx.commit().await.unwrap();
    }
    task.abort();
    let _ = task.await;
}
