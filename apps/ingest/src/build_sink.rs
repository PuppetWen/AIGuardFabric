//! Requested durable storage must never silently fall back to volatile acknowledgements.
use super::*;

/// Explicit offline demonstrations may use memory. A configured SQL receiver starts only
/// after storage is available; supervisors can retry startup without losing acknowledged logs.
pub(crate) async fn build_sink() -> anyhow::Result<Arc<dyn Sink>> {
    if !env_flag("AGF_INGEST_SQL_SINK") {
        anyhow::ensure!(
            env_or("AGF_MOCK_MODE", "1") == "1",
            "Real ingestion requires AGF_INGEST_SQL_SINK=1; memory storage is only available in mock mode"
        );
        tracing::warn!("Mock ingestion uses memory; data is not retained after restart");
        return Ok(Arc::new(InMemorySink::new()));
    }
    let env_map: BTreeMap<String, String> = std::env::vars().collect();
    let config = agf_storage::StorageConfig::from(&agf_core::config::from_env_map(&env_map)?);
    let (store, notes) = tokio::time::timeout(std::time::Duration::from_secs(15), agf_storage::build_store(&config))
        .await
        .map_err(|_| anyhow::anyhow!("SQL sink startup timed out; ingestion was not started"))??;
    for note in notes {
        tracing::warn!(note = %note, "Optional storage dependency is degraded");
    }
    tracing::info!("Ingestion stores raw logs and events in PostgreSQL with tenant RLS");
    Ok(Arc::new(SqlSink::new(Arc::new(store)).with_event_outbox(env_flag("AGF_NATS_ENABLED"))))
}
