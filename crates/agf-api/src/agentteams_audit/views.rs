//! Read only safe audit projections; counts cover the whole window, independently of event pages.
use super::binding::{self, Binding, Context};
use crate::{source_store, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};
use agf_ingest::pipeline::{
    AgentTeamsAuditAggregate, AgentTeamsAuditCursor, AgentTeamsAuditQuery, AgentTeamsAuditRecord,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const WINDOW: i64 = 86_400;
const FRESH: i64 = 300;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    tenant: TenantId,
    scope: agf_core::ids::Id,
    until: Timestamp,
    before: AgentTeamsAuditCursor,
}

pub async fn list_bindings(state: &AppState, principal: &crate::Principal) -> DomainResult<Value> {
    let tenant = principal.tenant;
    let records: Vec<source_store::Record> = state.configurations.list(tenant, source_store::KIND).await?;
    let bindings: Vec<Binding> = state.configurations.list(tenant, binding::KIND).await?;
    let context = binding::context(state, tenant).await?;
    let now = Timestamp::now();
    let aggregate =
        if let Some(context) = &context { Some(aggregate(state, tenant, context, now).await?) } else { None };
    let sources: Vec<_> = records
        .iter()
        .filter(|row| binding::eligible(row))
        .filter_map(|row| row.source.as_ref())
        .map(|source| json!({"id":source.id,"name":source.name,"enabled":source.enabled}))
        .collect();
    let items: Vec<_> = bindings
        .iter()
        .map(|binding| {
            let source = records.iter().filter_map(|row| row.source.as_ref()).find(|row| row.id == binding.source_id);
            let valid =
                source.zip(context.as_ref()).is_some_and(|(source, ctx)| binding::current(binding, ctx, source));
            let observation = aggregate.as_ref().and_then(|totals| {
                totals
                    .sources
                    .iter()
                    .find(|row| row.source_id == binding.source_id && row.binding_id == binding.binding_id)
            });
            let state = if !binding.enabled || source.is_none_or(|source| !source.enabled) {
                "disabled"
            } else if !valid {
                "stale"
            } else if let Some(observed) = observation {
                if now.since_secs(&observed.last_received_at) <= FRESH { "active" } else { "stale" }
            } else {
                "waiting"
            };
            json!({"sourceId":binding.source_id,"sourceName":source.map(|s|s.name.as_str()).unwrap_or("已删除日志源"),
            "version":binding.version,"bindingId":binding.binding_id,"cloudVersion":binding.cloud_version,
            "scopeId":binding.scope_id,"mocked":binding.mocked,"state":state,"boundAt":binding.bound_at,
            "lastEventAt":observation.map(|row|row.last_received_at),
            "coverageStart":observation.map(|row|row.first_received_at),"completeWindow":false,"acceptsEvents":valid})
        })
        .collect();
    Ok(json!({"items":items,"sources":sources,"cloudVersion":context.as_ref().map_or(0,|ctx|ctx.cloud.version),
        "inventoryAvailable":context.is_some(),"canWrite":principal.require(state,"alicloud","write").is_ok()
            && principal.require(state,"sources","write").is_ok()}))
}

pub async fn events(state: &AppState, tenant: TenantId, query: EventQuery) -> DomainResult<Value> {
    let limit = query.limit.unwrap_or(50);
    if !(1..=199).contains(&limit) {
        return Err(DomainError::Validation("每页审计事件须为 1 至 199 条".into()));
    }
    let now = Timestamp::now();
    let Some(context) = binding::context(state, tenant).await? else {
        if query.cursor.is_some() {
            return Err(super::stale());
        }
        return Ok(json!({"items":[],"nextCursor":null,"windowFrom":now.offset_secs(-WINDOW),"windowTo":now}));
    };
    let cursor = query.cursor.as_ref().map(|value| decode_cursor(value, tenant, &context, now)).transpose()?;
    let until = cursor.as_ref().map_or(now, |cursor| cursor.until);
    let from = until.offset_secs(-WINDOW);
    let mut records = state
        .ingest_sink
        .agentteams_audit_records(&AgentTeamsAuditQuery {
            tenant_id: tenant,
            scope_id: context.scope_id,
            from,
            until,
            before: cursor.map(|cursor| cursor.before),
            limit: limit + 1,
        })
        .await?;
    let has_more = records.len() > limit;
    records.truncate(limit);
    let next_cursor = if has_more {
        records
            .last()
            .map(|last| {
                serde_json::to_vec(&Cursor {
                    tenant,
                    scope: context.scope_id,
                    until,
                    before: AgentTeamsAuditCursor { event_time: last.event_time, id: last.id },
                })
                .map(|value| URL_SAFE_NO_PAD.encode(value))
            })
            .transpose()?
    } else {
        None
    };
    let source_records: Vec<source_store::Record> = state.configurations.list(tenant, source_store::KIND).await?;
    let items: Vec<_> = records
        .iter()
        .map(|record| {
            let source = source_records
                .iter()
                .filter_map(|row| row.source.as_ref())
                .find(|source| source.id == record.source_id);
            event(record, source.map(|source| source.name.as_str()))
        })
        .collect();
    Ok(json!({"items":items,"nextCursor":next_cursor,"windowFrom":from,"windowTo":until}))
}

fn decode_cursor(raw: &str, tenant: TenantId, context: &Context, now: Timestamp) -> DomainResult<Cursor> {
    let invalid = || DomainError::Validation("审计游标无效或已过期，请刷新列表".into());
    if raw.len() > 2048 {
        return Err(invalid());
    }
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| invalid())?;
    let value: Cursor = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if value.tenant != tenant
        || value.scope != context.scope_id
        || value.until > now
        || now.since_secs(&value.until) > 1800
        || value.before.event_time >= value.until
        || value.before.event_time < value.until.offset_secs(-WINDOW)
    {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn event(row: &AgentTeamsAuditRecord, source: Option<&str>) -> Value {
    json!({"id":row.id,"eventId":row.external_event_id,"eventTime":row.event_time,"receivedAt":row.received_at,
        "kind":row.kind,"sourceId":row.source_id,"sourceName":source,"fromTeam":row.from_team,"fromWorker":row.from_worker,
        "fromAssetId":row.from_asset,"toTeam":row.to_team,"toWorker":row.to_worker,"toAssetId":row.to_asset,
        "taskId":row.task_id,"traceId":row.trace_id,"spanId":row.span_id,"parentSpanId":row.parent_span_id,
        "status":row.status,"durationMs":row.duration_ms,"messagePreview":row.message_preview,"mocked":row.mocked,
        "authorizationStatus":"unknown","authorized":null})
}

async fn aggregate(
    state: &AppState,
    tenant: TenantId,
    context: &Context,
    until: Timestamp,
) -> DomainResult<AgentTeamsAuditAggregate> {
    state.ingest_sink.agentteams_audit_aggregate(tenant, context.scope_id, until.offset_secs(-WINDOW), until).await
}

pub async fn teams(state: &AppState, tenant: TenantId, context: &Context) -> DomainResult<Vec<Value>> {
    let now = Timestamp::now();
    let totals = aggregate(state, tenant, context, now).await?;
    let fresh = totals.last_received_at.is_some_and(|at| now.since_secs(&at) <= FRESH);
    let mut teams = crate::cloud_inventory_views::teams(tenant, &context.snapshot);
    for team in &mut teams {
        let name = team["name"].as_str().unwrap_or_default().to_owned();
        team["crossTeamCalls24h"] = json!(
            totals.cross_team_calls.iter().filter(|call| call.from_team == name).map(|call| call.count).sum::<u64>()
        );
        let cross_observed = totals.cross_team_calls.iter().any(|call| call.from_team == name);
        let member_observed = team["members"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|member| totals.workers.iter().any(|worker| member["id"] == worker.worker));
        team["metricsAvailable"] = json!(cross_observed || member_observed);
        team["telemetryFresh"] = json!(fresh);
        team["completeWindow"] = json!(false);
        team["windowFrom"] = json!(now.offset_secs(-WINDOW));
        team["windowTo"] = json!(now);
        if let Some(members) = team["members"].as_array_mut() {
            for member in members {
                let observation = totals.workers.iter().find(|worker| member["id"] == worker.worker);
                member["invocations24h"] = json!(observation.map_or(0, |row| row.invocations));
                member["metricsAvailable"] = json!(observation.is_some());
            }
        }
    }
    Ok(teams)
}

pub async fn cross_calls(state: &AppState, tenant: TenantId, context: &Context) -> DomainResult<Vec<Value>> {
    let now = Timestamp::now();
    let totals = aggregate(state, tenant, context, now).await?;
    Ok(totals.cross_team_calls.into_iter().map(|row| json!({
        "id":format!("{}:{}:{}:{}",context.scope_id,row.from_team,row.to_team,row.to_worker.as_deref().unwrap_or("")),
        "callerTeam":row.from_team,"calleeTeam":row.to_team,"calleeAgent":row.to_worker.unwrap_or_default(),
        "count24h":row.count,"authorized":null,"authorizationStatus":"unknown","sensitiveData":null,
        "mocked":context.snapshot.mocked,"completeWindow":false,"windowFrom":now.offset_secs(-WINDOW),"windowTo":now,
    })).collect())
}
