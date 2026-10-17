//! Safe audit pages and whole-window aggregates; counts never depend on page size.
use super::{agentteams_audit::*, *};
use agf_storage::{Store, map_sqlx_err};

pub(super) async fn records(store: &Store, query: &AgentTeamsAuditQuery) -> DomainResult<Vec<AgentTeamsAuditRecord>> {
    validate_query(query)?;
    let query = query.clone();
    store
        .with_tenant(query.tenant_id, move |tx| {
            Box::pin(async move {
                let values: Vec<Value> = sqlx::query_scalar(
                    "SELECT payload FROM agentteams_audit
            WHERE tenant_id=$1 AND scope_id=$2 AND event_time >= $3 AND event_time < $4
            AND ($5::timestamptz IS NULL OR (event_time,id) < ($5,$6::uuid))
            ORDER BY event_time DESC,id DESC LIMIT $7",
                )
                .bind(query.tenant_id.as_uuid())
                .bind(query.scope_id.as_uuid())
                .bind(query.from.as_datetime())
                .bind(query.until.as_datetime())
                .bind(query.before.map(|cursor| cursor.event_time.as_datetime()))
                .bind(query.before.map(|cursor| cursor.id.as_uuid()))
                .bind(query.limit as i64)
                .fetch_all(&mut **tx)
                .await
                .map_err(|error| map_sqlx_err("agentteams_audit_page", &error))?;
                values.into_iter().map(|value| serde_json::from_value(value).map_err(Into::into)).collect()
            })
        })
        .await
}

pub(super) async fn aggregate(
    store: &Store,
    tenant: TenantId,
    scope: Id,
    from: Timestamp,
    until: Timestamp,
) -> DomainResult<AgentTeamsAuditAggregate> {
    validate_window(from, until)?;
    if scope.is_nil() {
        return Err(DomainError::Validation("Audit aggregate requires a scope".into()));
    }
    store
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                let value: Value = sqlx::query_scalar(AGGREGATE)
                    .bind(tenant.as_uuid())
                    .bind(scope.as_uuid())
                    .bind(from.as_datetime())
                    .bind(until.as_datetime())
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|error| map_sqlx_err("agentteams_audit_aggregate", &error))?;
                serde_json::from_value(value).map_err(Into::into)
            })
        })
        .await
}

const AGGREGATE: &str = "WITH window_rows AS (
    SELECT payload,kind,received_at,source_id,binding_id FROM agentteams_audit
    WHERE tenant_id=$1 AND scope_id=$2 AND event_time >= $3 AND event_time < $4
), worker_counts AS (
    SELECT COALESCE(payload->>'to_worker',payload->>'from_worker') AS worker,count(*) AS invocations
    FROM window_rows WHERE kind='call'
    AND COALESCE(payload->>'to_worker',payload->>'from_worker') IS NOT NULL GROUP BY 1
), cross_counts AS (
    SELECT payload->>'from_team' AS from_team,payload->>'to_team' AS to_team,
           payload->>'to_worker' AS to_worker,count(*) AS count
    FROM window_rows WHERE kind='call' AND payload->>'from_team' IS NOT NULL
    AND payload->>'to_team' IS NOT NULL AND payload->>'from_team' <> payload->>'to_team'
    GROUP BY 1,2,3
), source_observations AS (
    SELECT source_id,binding_id,min(received_at) AS first_received_at,
           max(received_at) AS last_received_at,
           max(received_at) FILTER (WHERE kind='heartbeat') AS last_heartbeat_at
    FROM window_rows GROUP BY source_id,binding_id
) SELECT jsonb_build_object(
    'invocations',count(*) FILTER (WHERE kind='call'),
    'messages',count(*) FILTER (WHERE kind='message'),
    'tasks',count(*) FILTER (WHERE kind='task'),
    'heartbeats',count(*) FILTER (WHERE kind='heartbeat'),
    'last_received_at',max(received_at),
    'last_heartbeat_at',max(received_at) FILTER (WHERE kind='heartbeat'),
    'sources',COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY s.source_id,s.binding_id) FROM source_observations s),'[]'::jsonb),
    'workers',COALESCE((SELECT jsonb_agg(to_jsonb(w) ORDER BY w.worker) FROM worker_counts w),'[]'::jsonb),
    'cross_team_calls',COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c.from_team,c.to_team,c.to_worker) FROM cross_counts c),'[]'::jsonb)
) FROM window_rows";
