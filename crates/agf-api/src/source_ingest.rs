//! Bounded payload ingestion shared by authenticated push and the pull scheduler.
use crate::{
    source_store::{KIND, MAX_BATCH, MAX_BYTES, Record},
    state::AppState,
};
use agf_core::{
    enums::HealthState,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    source::LogSource,
    time::Timestamp,
};
use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct ResultSummary {
    pub received: u64,
    pub accepted: u64,
    pub matched: u64,
    pub deduped: u64,
    pub failed: u64,
    pub errors: Vec<String>,
}

pub async fn ingest(state: &AppState, source: &LogSource, bytes: &[u8]) -> DomainResult<ResultSummary> {
    if !source.enabled || !crate::tenant_directory::get(state, source.tenant_id).await?.enabled {
        return Err(DomainError::Forbidden("日志源或所属租户已停用".into()));
    }
    let records = records(bytes)?;
    let items: Vec<_> = records.into_iter().map(|bytes| (bytes, source.id.to_string())).collect();
    let parsers = crate::parser_store::registry(state, source.tenant_id).await?;
    if source.parser_id.is_some_and(|id| parsers.find_id(id).is_none_or(|p| !p.enabled)) {
        return Err(DomainError::PreconditionFailed("日志源绑定的模板已删除或停用，请重新选择解析器".into()));
    }
    let handle = state.ingest_pipelines.get(source.tenant_id, state.ingest_sink.clone(), &parsers)?;
    let outcomes = handle.pipeline.ingest_batch(source, source.protocol, &items).await?;
    let mut result = ResultSummary::default();
    for outcome in outcomes {
        result.received += 1;
        result.accepted += u64::from(outcome.persisted);
        result.matched += u64::from(outcome.matched);
        result.deduped += u64::from(outcome.deduped);
        // An unmatched parser still saves the raw log for replay. It must not stall the pull cursor.
        result.failed += u64::from(!outcome.persisted);
        if result.errors.len() < 10 {
            if let Some(error) = outcome.error {
                result.errors.push(error);
            }
        }
    }
    Ok(result)
}

/// Reject an oversized batch instead of silently discarding its tail.
pub fn records(bytes: &[u8]) -> DomainResult<Vec<Vec<u8>>> {
    if bytes.len() > MAX_BYTES {
        return Err(DomainError::Validation("单次接入载荷不得超过 2 MiB".into()));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| DomainError::Validation("接入载荷必须为 UTF-8".into()))?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let records = if let Some(records) =
        agf_ingest::payload::json_array_records(bytes, agf_ingest::payload::ArrayStrings::Preserve)
    {
        records
    } else if serde_json::from_str::<&serde_json::value::RawValue>(text.trim()).is_ok() {
        // This API already accepts a complete pretty-printed JSON value as one record.
        vec![bytes.to_vec()]
    } else {
        agf_ingest::payload::line_records(bytes).map(<[u8]>::to_vec).collect()
    };
    if records.len() > MAX_BATCH {
        return Err(DomainError::Validation("每批最多接入 1000 条，请拆分批次".into()));
    }
    Ok(records)
}

pub async fn record_result(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    result: &ResultSummary,
    lease: Option<(Id, Option<String>)>,
) -> DomainResult<()> {
    state
        .configurations
        .mutate::<Record, _>(tenant, KIND, id, |row| {
            let Some(source) = row.source.as_mut() else {
                return Ok(());
            };
            if let Some((lease_id, cursor)) = lease {
                if row.lease_id != Some(lease_id) {
                    return Ok(());
                }
                row.lease_id = None;
                row.lease_until = 0;
                row.next_poll_at = Timestamp::now().unix_secs() + source.poll_interval_secs.unwrap_or(60);
                // Never advance a cursor past data that failed to persist.
                if result.failed == 0 {
                    row.cursor = cursor.or_else(|| row.cursor.clone());
                }
            }
            row.received = row.received.saturating_add(result.received);
            row.matched = row.matched.saturating_add(result.matched);
            row.failed = row.failed.saturating_add(result.failed);
            source.total_events = source.total_events.saturating_add(result.accepted);
            source.health = if result.failed > 0 || result.matched < result.accepted {
                HealthState::Degraded
            } else {
                HealthState::Healthy
            };
            source.last_error = result.errors.first().cloned();
            if result.accepted > 0 {
                source.last_event_at = Some(Timestamp::now());
            }
            Ok(())
        })
        .await?;
    Ok(())
}
