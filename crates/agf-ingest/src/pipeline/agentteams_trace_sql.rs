//! One SQL statement supplies an independent total and bounded trace records.
use super::{agentteams_trace::*, *};
use agf_storage::{Store, map_sqlx_err};

pub(super) async fn snapshot(store: &Store, query: &AgentTeamsTraceQuery) -> DomainResult<AgentTeamsTraceSnapshot> {
    validate(query)?;
    let query = query.clone();
    store
        .with_tenant(query.tenant_id, move |tx| {
            Box::pin(async move {
                let (total, records): (i64, Value) = sqlx::query_as(SNAPSHOT)
                    .bind(query.tenant_id.as_uuid())
                    .bind(query.scope_id.as_uuid())
                    .bind(&query.trace_id)
                    .bind(query.from.as_datetime())
                    .bind(query.until.as_datetime())
                    .bind(query.received_until.as_datetime())
                    .bind(i64::try_from(query.limit).map_err(|error| DomainError::Internal(error.to_string()))?)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|error| map_sqlx_err("agentteams_trace_snapshot", &error))?;
                Ok(AgentTeamsTraceSnapshot {
                    total: u64::try_from(total).map_err(|error| DomainError::Internal(error.to_string()))?,
                    records: serde_json::from_value(records)?,
                })
            })
        })
        .await
}

const SNAPSHOT: &str = "WITH matching AS NOT MATERIALIZED (
    SELECT id,event_time,payload FROM agentteams_audit
    WHERE tenant_id=$1 AND scope_id=$2 AND payload->>'trace_id'=$3
      AND event_time >= $4 AND event_time < $5 AND received_at <= $6
), bounded AS (
    SELECT id,event_time,payload FROM matching ORDER BY event_time DESC,id DESC LIMIT $7
)
SELECT (SELECT count(*) FROM matching),
    COALESCE((SELECT jsonb_agg(payload ORDER BY event_time DESC,id DESC) FROM bounded),'[]'::jsonb)";
