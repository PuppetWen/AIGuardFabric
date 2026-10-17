//! Tenant-isolated pipelines use the full loaded parser registry and the configured SQL/memory sink.

use std::sync::Arc;

use agf_core::enums::IngestProtocol;
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, LogSource, SourceConnection};

use super::AgentUplinkBody;

pub(super) use crate::ingest_pipelines::PipelineHandle;

pub(super) async fn pipeline_for(
    state: &crate::state::AppState,
    tenant: TenantId,
) -> agf_core::error::DomainResult<Arc<PipelineHandle>> {
    let parsers = crate::parser_store::registry(state, tenant).await?;
    state.ingest_pipelines.get(tenant, state.ingest_sink.clone(), &parsers)
}

/// 由租户 + 采集器派生**确定性**的日志源（同一采集器跨请求复用同一 source id）。
pub(super) fn collector_source(tenant: TenantId, body: &AgentUplinkBody) -> LogSource {
    let name = format!("agent-uplink:{}", body.origin_label());
    let id = deterministic_id(&name);
    LogSource {
        id,
        tenant_id: tenant,
        name,
        protocol: IngestProtocol::Mcp,
        vendor: "aiguardfabric".to_string(),
        product: "agf-agent".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection { endpoint: body.hostname.clone(), ..SourceConnection::default() },
        mode: CollectionMode::Push,
        poll_interval_secs: None,
        // Bearer ingestion remains supported unless deployment policy requires certificates.
        require_mtls: super::agent_mtls::required_from_env(),
        allowed_cidrs: Vec::new(),
        max_message_bytes: 4 * 1024 * 1024,
        // 不限速：速率保护由 API 侧的三级限流承担，这里再限会叠加成双重拒绝
        max_eps: 0,
        tags: vec!["collector-uplink".to_string()],
        health: agf_core::enums::HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: agf_core::time::Timestamp::now(),
        updated_at: agf_core::time::Timestamp::now(),
    }
}

/// 名称 → 确定性 Id（同一名字跨进程/跨请求恒定）。
fn deterministic_id(name: &str) -> Id {
    let digest = agf_core::secret::content_hash(name);
    let mut bytes = [0_u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let pair = digest.get(index * 2..index * 2 + 2).unwrap_or("00");
        *slot = u8::from_str_radix(pair, 16).unwrap_or(0);
    }
    Id::from_uuid(uuid::Uuid::new_v5(&uuid::Uuid::nil(), &bytes))
}
