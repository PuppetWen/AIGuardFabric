//! 每个应用实例按租户维护去重流水线，共用可持久化的接入仓储。
use agf_core::{error::DomainResult, ids::TenantId};
use agf_ingest::pipeline::{IngestConfig, IngestPipeline, Sink};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub(crate) struct PipelineHandle {
    pub pipeline: IngestPipeline,
    pub sink: Arc<dyn Sink>,
}
impl std::fmt::Debug for PipelineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineHandle").field("sink", &self.sink.backend()).finish_non_exhaustive()
    }
}
#[derive(Debug, Default)]
pub(crate) struct Registry {
    entries: Mutex<BTreeMap<TenantId, Arc<PipelineHandle>>>,
}
impl Registry {
    pub(crate) fn get(
        &self,
        tenant: TenantId,
        sink: Arc<dyn Sink>,
        parsers: &agf_ingest::registry::ParserRegistry,
    ) -> DomainResult<Arc<PipelineHandle>> {
        let mut entries = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = entries
            .entry(tenant)
            .or_insert_with(|| {
                Arc::new(PipelineHandle {
                    pipeline: IngestPipeline::new(
                        parsers.clone(),
                        sink.clone(),
                        Arc::new(agf_ingest::bus::NoopEventBus),
                        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
                    ),
                    sink,
                })
            })
            .clone();
        handle.pipeline.with_registry(|live| live.refresh_catalog(parsers))?;
        Ok(handle)
    }
}
