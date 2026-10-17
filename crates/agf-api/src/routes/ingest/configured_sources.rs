//! Log source configuration and authenticated push/pull controls.
use super::*;
use crate::{
    routes::ApiJson,
    source_store::{self as store, Input, KIND, Record},
};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    time::Timestamp,
};

pub async fn list_sources(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "sources", "read")?;
    let records: Vec<Record> = state.configurations.list(principal.tenant, KIND).await?;
    let rows: Vec<_> = records
        .iter()
        .filter(|row| {
            row.source.as_ref().is_some_and(|source| {
                query.filter("protocol").is_none_or(|raw| {
                    raw == source.protocol.as_str()
                        || (raw == "http-webhook" && source.protocol == IngestProtocol::Webhook)
                }) && query.filter("enabled").is_none_or(|raw| raw == source.enabled.to_string())
            })
        })
        .map(store::public)
        .collect();
    let page = query.paginate_vec(
        &rows,
        |row| format!("{} {} {}", row["name"], row["protocol"], row["connection"]["endpoint"]),
        |row| row["created_at"].as_str().unwrap_or_default().to_string(),
    );
    let mut value = query.render_page(&page)?;
    value["can_write"] = principal.require(&state, "sources", "write").is_ok().into();
    Ok(Json(value))
}

pub async fn get_source(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "sources", "read")?;
    let record = store::load(&state, principal.tenant, parse_id(&id, "log-source")?).await?;
    Ok(Json(serde_json::json!({"source":store::public(&record)})))
}

pub async fn create_source(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<Input>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "sources", "write")?;
    let id = Id::new();
    let record = store::build(&state, principal.tenant, id, input).await?;
    audited_mutate(&state, &principal, id, AuditAction::Create, |row| {
        *row = record.clone();
        Ok(())
    })
    .await?;
    Ok((axum::http::StatusCode::CREATED, Json(store::public(&record))))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toggle {
    enabled: bool,
}

pub async fn toggle_source(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<Toggle>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "sources", "write")?;
    let id = parse_id(&id, "log-source")?;
    let record = audited_mutate(&state, &principal, id, AuditAction::Configure, |row| {
        idle(row)?;
        let source = row.source.as_mut().ok_or_else(|| missing(id))?;
        source.enabled = input.enabled;
        source.updated_at = Timestamp::now();
        row.next_poll_at = 0;
        Ok(())
    })
    .await?;
    Ok(Json(store::public(&record)))
}

pub async fn update_source(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<Input>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "sources", "write")?;
    let id = parse_id(&id, "log-source")?;
    let preserve_cidrs = input.allowed_cidrs.is_none();
    let preserve_mtls = input.require_mtls.is_none();
    let replacement = store::build(&state, principal.tenant, id, input).await?;
    let record = audited_mutate(&state, &principal, id, AuditAction::Configure, |row| {
        idle(row)?;
        let previous = row.source.as_ref().ok_or_else(|| missing(id))?;
        let mut next = replacement.clone();
        let source = next.source.as_mut().ok_or_else(|| missing(id))?;
        if previous.protocol != source.protocol || row.native_receiver != next.native_receiver {
            return Err(DomainError::Validation("更换协议请新建日志源，以免混淆历史日志".into()));
        }
        if previous.connection.endpoint == source.connection.endpoint {
            next.headers = next.headers.or_else(|| row.headers.clone());
            next.cursor.clone_from(&row.cursor);
        }
        source.created_at = previous.created_at;
        source.total_events = previous.total_events;
        source.last_event_at = previous.last_event_at;
        if source.parser_id == previous.parser_id {
            source.health = previous.health;
            source.last_error.clone_from(&previous.last_error);
        }
        if row.native_receiver.is_some() {
            source.max_message_bytes = previous.max_message_bytes;
            source.max_eps = previous.max_eps;
            if preserve_mtls {
                source.require_mtls = previous.require_mtls;
            }
            if preserve_cidrs {
                source.allowed_cidrs.clone_from(&previous.allowed_cidrs);
            }
            source.tags.clone_from(&previous.tags);
            source.vendor.clone_from(&previous.vendor);
        }
        next.received = row.received;
        next.matched = row.matched;
        next.failed = row.failed;
        *row = next;
        Ok(())
    })
    .await?;
    Ok(Json(store::public(&record)))
}

pub async fn delete_source(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "sources", "write")?;
    let id = parse_id(&id, "log-source")?;
    audited_mutate(&state, &principal, id, AuditAction::Delete, |row| {
        idle(row)?;
        row.source.as_ref().ok_or_else(|| missing(id))?;
        // Retain a tombstone: an old in-flight request must never recreate this source.
        *row = Record::default();
        Ok(())
    })
    .await?;
    Ok(Json(serde_json::json!({"deleted":true})))
}

pub async fn push_events(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "sources", "write")?;
    let id = parse_id(&id, "log-source")?;
    let record = store::load(&state, principal.tenant, id).await?;
    let source = record.source.as_ref().ok_or_else(|| missing(id))?;
    if record.native_receiver.is_some() {
        return Err(DomainError::Validation("此源绑定独立协议接收器，请按接入指南投递至对应监听器".into()).into());
    }
    if source.is_pull() {
        return Err(DomainError::Validation("拉取源请使用立即拉取操作".into()).into());
    }
    let result = crate::source_ingest::ingest(&state, source, &body).await?;
    crate::source_ingest::record_result(&state, principal.tenant, id, &result, None).await?;
    Ok(Json(serde_json::to_value(result)?))
}

pub async fn poll_source(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "sources", "write")?;
    let id = parse_id(&id, "log-source")?;
    let manual = match query.filter("manual") {
        None | Some("true") => true,
        Some("false") => false,
        _ => return Err(DomainError::Validation("manual 须为 true/false".into()).into()),
    };
    let result = crate::source_worker::poll(&state, principal.tenant, id, manual).await?;
    let Some(result) = result else {
        if manual {
            return Err(DomainError::Conflict("日志源已有拉取任务正在运行".into()).into());
        }
        return Ok(Json(serde_json::json!({"skipped":true,"reason":"已有任务运行或尚未到拉取时间"})));
    };
    audit(&state, &principal, id, AuditAction::Execute).await?;
    Ok(Json(serde_json::to_value(result)?))
}

fn idle(row: &Record) -> DomainResult<()> {
    if row.lease_until > Timestamp::now().unix_secs() {
        return Err(DomainError::Conflict("日志源正在拉取，请稍后重试".into()));
    }
    Ok(())
}
fn missing(id: Id) -> DomainError {
    DomainError::NotFound { entity: "log-source", id: id.to_string() }
}
async fn audited_mutate<F>(
    state: &AppState,
    principal: &Principal,
    id: Id,
    action: AuditAction,
    apply: F,
) -> DomainResult<Record>
where
    F: FnOnce(&mut Record) -> DomainResult<()> + Send,
{
    let entry = AuditLog {
        id: Id::new(),
        tenant_id: principal.tenant,
        sequence: 0,
        action,
        outcome: AuditOutcome::Success,
        actor: AppState::audit_actor(principal, "log-source"),
        target: AuditTarget::new("log-source", Some(id.to_string()), None),
        before: None,
        after: None,
        changed_fields: Vec::new(),
        request_id: crate::error::current_request_id(),
        error: None,
        note: "更新日志接入源".into(),
        prev_hash: String::new(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    };
    let (record, sealed) =
        state.configurations.mutate_audited(principal.tenant, KIND, id, entry.clone(), apply).await?;
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的日志源审计内存投影刷新失败");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(record)
}
async fn audit(state: &AppState, principal: &Principal, id: Id, action: AuditAction) -> DomainResult<()> {
    state
        .audit(
            principal.tenant,
            action,
            AuditOutcome::Success,
            AppState::audit_actor(principal, "log-source"),
            AuditTarget::new("log-source", Some(id.to_string()), None),
            "更新日志接入源",
        )
        .await
        .map(|_| ())
}
