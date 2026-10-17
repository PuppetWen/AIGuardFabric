//! Normalize a whole batch before atomic ledger + raw + Event + outbox persistence.
use super::{
    binding,
    contract::{self, Batch, Input, Kind},
};
use crate::{source_ingest::ResultSummary, state::AppState};
use agf_core::{
    enums::IngestProtocol,
    error::{DomainError, DomainResult},
    event::{Event, EventCategory, RawLog},
    ids::{Id, TenantId, deterministic_id},
    redact::{RedactionMap, RedactionMode, redact_json, redact_text},
    time::Timestamp,
};
use agf_ingest::pipeline::{AgentTeamsAuditRecord, AgentTeamsIngestItem, IngestWrite};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub async fn accept(
    state: &AppState,
    tenant: TenantId,
    source_id: agf_core::ids::Id,
    bytes: &[u8],
) -> DomainResult<Value> {
    if bytes.len() > crate::source_store::MAX_BYTES {
        return Err(contract::invalid());
    }
    let batch: Batch = serde_json::from_slice(bytes).map_err(|_| contract::invalid())?;
    if batch.events.is_empty() || batch.events.len() > crate::source_store::MAX_BATCH {
        return Err(contract::invalid());
    }
    let (binding, source, guard) = binding::verified(state, tenant, source_id, batch.binding_id).await?;
    let received_at = Timestamp::from_unix_millis(Timestamp::now().unix_millis()).map_err(|_| contract::invalid())?;
    let mut items = Vec::with_capacity(batch.events.len());
    for mut input in batch.events {
        let raw = serde_json::to_vec(&input)?;
        if raw.len() > source.max_message_bytes {
            return Err(DomainError::Validation("单条事件超过日志源消息长度限制".into()));
        }
        let (from_asset, to_asset) = contract::validate(&mut input, &binding, received_at)?;
        let (audit, write) =
            normalized(&binding, tenant, &source.name, input, &raw, received_at, (from_asset, to_asset))?;
        items.push(AgentTeamsIngestItem { write, audit });
    }
    // Recheck after validation; SQL sink repeats lifecycle/revision checks while holding row locks.
    let (_, _, checked) = binding::verified(state, tenant, source_id, batch.binding_id).await?;
    if checked.binding_version != guard.binding_version {
        return Err(super::stale());
    }
    let pipeline = state.ingest_pipelines.get(tenant, state.ingest_sink.clone(), &state.parsers)?;
    pipeline.pipeline.admit_batch(&source, items.len())?;
    let result = state.ingest_sink.persist_agentteams(&guard, &items).await?;
    let summary = ResultSummary {
        received: u64::try_from(items.len()).unwrap_or(u64::MAX),
        accepted: u64::try_from(result.accepted).unwrap_or(u64::MAX),
        matched: u64::try_from(result.accepted).unwrap_or(u64::MAX),
        deduped: u64::try_from(result.deduped).unwrap_or(u64::MAX),
        ..ResultSummary::default()
    };
    // Projection counters are best effort after the atomic commit: a retry remains safely deduplicated.
    if let Err(error) = crate::source_ingest::record_result(state, tenant, source_id, &summary, None).await {
        tracing::warn!(%error, "Committed AgentTeams audit source counter refresh failed");
    }
    Ok(json!({"accepted":result.accepted,"deduped":result.deduped,"received":items.len(),"scopeId":binding.scope_id,
        "mocked":binding.mocked,"durable":state.ingest_sink.database().is_some(),"authorizationStatus":"unknown"}))
}

fn normalized(
    binding: &binding::Binding,
    tenant: TenantId,
    source_name: &str,
    input: Input,
    raw_bytes: &[u8],
    received_at: Timestamp,
    assets: (Option<Id>, Option<Id>),
) -> DomainResult<(AgentTeamsAuditRecord, IngestWrite)> {
    // Hash normalized content, including the full original message, never collector/source revisions.
    let content_hash = hash(&serde_json::to_vec(&json!({"event":&input,"from_asset":assets.0,"to_asset":assets.1}))?);
    let id = deterministic_id("agf.agentteams.event", &format!("{tenant}:{}:{}", binding.scope_id, input.event_id));
    let raw_id = deterministic_id("agf.agentteams.raw", &id.to_string());
    let outcome = redact_text(
        input.message.as_deref().unwrap_or_default(),
        RedactionMode::CredentialsAndPii,
        &mut RedactionMap::default(),
    );
    let preview: String = outcome.text.chars().take(512).collect();
    let mut event = Event::new(tenant, binding.source_id, IngestProtocol::Webhook);
    event.id = id;
    event.time = input.event_time;
    event.ingested_at = received_at;
    event.category = match input.kind {
        Kind::Call => EventCategory::AiToolCall,
        Kind::Message => EventCategory::AiSession,
        Kind::Task | Kind::Heartbeat => EventCategory::CloudControl,
    };
    event.action_raw = format!("agentteams.{}", input.kind.as_str());
    event.source_name = source_name.into();
    event.vendor = "AGF".into();
    event.product = "AgentTeams audit webhook".into();
    event.message = preview.clone();
    event.ai.agent_flavor = Some("alicloud-agentteams".into());
    event.ai.agent_id = assets.0.or(assets.1);
    event.ai.mocked = binding.mocked;
    event.ai.session_id.clone_from(&input.trace_id);
    event.raw =
        redact_json(&serde_json::to_value(&input)?, RedactionMode::CredentialsAndPii, &mut RedactionMap::default());
    event.raw_hash = hash(raw_bytes);
    event.raw_ref = Some(raw_id.to_string());
    event.redacted = event.raw != serde_json::to_value(&input)?;
    event.tags = vec!["agentteams-audit".into(), if binding.mocked { "mock" } else { "collector" }.into()];
    event.extra.insert("trace_id".into(), json!(input.trace_id));
    event.extra.insert("span_id".into(), json!(input.span_id));
    event.extra.insert("parent_span_id".into(), json!(input.parent_span_id));
    event.extra.insert("scope_id".into(), json!(binding.scope_id));
    event.extra.insert("from_asset_id".into(), json!(assets.0));
    event.extra.insert("to_asset_id".into(), json!(assets.1));
    event.extra.insert("identity_assurance".into(), json!("authenticated-collector"));
    let audit = AgentTeamsAuditRecord {
        id,
        tenant_id: tenant,
        scope_id: binding.scope_id,
        source_id: binding.source_id,
        binding_id: binding.binding_id,
        external_event_id: input.event_id,
        content_hash,
        event_time: input.event_time,
        received_at,
        kind: input.kind.as_str().into(),
        from_team: input.from_team,
        from_worker: input.from_worker,
        from_asset: assets.0,
        to_team: input.to_team,
        to_worker: input.to_worker,
        to_asset: assets.1,
        task_id: input.task_id,
        trace_id: input.trace_id,
        span_id: input.span_id,
        parent_span_id: input.parent_span_id,
        status: input.status.as_str().into(),
        duration_ms: input.duration_ms,
        message_preview: preview,
        mocked: binding.mocked,
    };
    let raw = RawLog {
        id: raw_id,
        tenant_id: tenant,
        source_id: binding.source_id,
        received_at,
        protocol: IngestProtocol::Webhook,
        payload_b64: STANDARD.encode(raw_bytes),
        payload_hash: hash(raw_bytes),
        bytes: raw_bytes.len(),
        origin: "authenticated-agentteams-webhook".into(),
        parsed: true,
        parse_error: None,
        event_id: Some(id),
    };
    Ok((audit, IngestWrite { raw, event: Some(event) }))
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
