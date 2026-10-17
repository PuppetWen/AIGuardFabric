//! A single MVCC statement returns full count and column-validated bounded original evidence.
use super::{agentteams_failure::*, *};
use agf_storage::{Store, map_sqlx_err};

pub(super) async fn snapshot(store: &Store, query: &AgentTeamsFailureQuery) -> DomainResult<AgentTeamsFailureSnapshot> {
    super::agentteams_failure::validate_query(query)?;
    let query = query.clone();
    store
        .with_tenant(query.tenant_id, move |tx| {
            Box::pin(async move {
                let (total, rows): (i64, Value) = sqlx::query_as(SNAPSHOT)
                    .bind(query.tenant_id.as_uuid())
                    .bind(query.source_id.map(|id| id.as_uuid()))
                    .bind(query.scope_id.map(|id| id.as_uuid()))
                    .bind(query.from.as_datetime())
                    .bind(query.until.as_datetime())
                    .bind(query.received_until.as_datetime())
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|error| map_sqlx_err("agentteams_failure_snapshot", &error))?;
                let total = u64::try_from(total).map_err(|_| corrupt())?;
                let rows = rows.as_array().ok_or_else(corrupt)?;
                if rows.len() > AGENTTEAMS_FAILURE_LIMIT {
                    return Err(corrupt());
                }
                let records = rows
                    .iter()
                    .cloned()
                    .map(|value| agentteams_failure_from_envelope(value, query.tenant_id))
                    .collect::<DomainResult<Vec<_>>>()?;
                Ok(AgentTeamsFailureSnapshot { total, records, truncated: total > AGENTTEAMS_FAILURE_LIMIT as u64 })
            })
        })
        .await
}

pub(super) async fn record(store: &Store, tenant: TenantId, id: Id) -> DomainResult<Option<AgentTeamsAuditRecord>> {
    if tenant.as_uuid().is_nil() || id.is_nil() {
        return Err(corrupt());
    }
    store
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                let values: Vec<Value> = sqlx::query_scalar(RECORD)
                    .bind(tenant.as_uuid())
                    .bind(id.as_uuid())
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(|error| map_sqlx_err("agentteams_failure_record", &error))?;
                if values.len() > 1 {
                    return Err(corrupt());
                }
                values.into_iter().next().map(|value| agentteams_failure_from_envelope(value, tenant)).transpose()
            })
        })
        .await
}

const SNAPSHOT: &str = "WITH matching AS NOT MATERIALIZED (
 SELECT id,event_time,tenant_id,source_id,scope_id,binding_id,external_event_id,content_hash,received_at,kind,payload
 FROM agentteams_audit WHERE tenant_id=$1 AND kind='task' AND payload->>'status'='error'
 AND ($2::uuid IS NULL OR source_id=$2) AND ($3::uuid IS NULL OR scope_id=$3)
 AND event_time >= $4 AND event_time < $5 AND received_at <= $6
), bounded AS (SELECT * FROM matching ORDER BY event_time DESC,id DESC LIMIT 2000)
SELECT (SELECT count(*) FROM matching), COALESCE(
 (SELECT jsonb_agg(to_jsonb(b) ORDER BY event_time DESC,id DESC) FROM bounded b),'[]'::jsonb)";

const RECORD: &str = "SELECT jsonb_build_object('id',id,'tenant_id',tenant_id,'source_id',source_id,
 'scope_id',scope_id,'binding_id',binding_id,'external_event_id',external_event_id,'content_hash',content_hash,
 'event_time',event_time,'received_at',received_at,'kind',kind,'payload',payload)
 FROM agentteams_audit WHERE tenant_id=$1 AND id=$2 AND kind='task' AND payload->>'status'='error' LIMIT 2";
