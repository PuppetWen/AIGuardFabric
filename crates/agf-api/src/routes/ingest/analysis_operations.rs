//! Failure inspection and versioned recovery; history commits with the action.
use super::*;
use crate::routes::ApiJson;
use serde_json::{Value, json};

fn database(state: &AppState) -> DomainResult<Arc<agf_storage::Store>> {
    state
        .ingest_sink
        .database()
        .ok_or_else(|| DomainError::PreconditionFailed("Event recovery requires SQL storage".into()))
}

pub(super) async fn list(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "sources", "read")?;
    let filter = query.filters.get("state").cloned().unwrap_or_else(|| "open".into());
    if !["all", "open", "retrying", "paused", "quarantined", "resolved"].contains(&filter.as_str()) {
        return Err(DomainError::Validation("Unknown analysis queue state".into()).into());
    }
    let keyword = query.q.unwrap_or_default();
    if keyword.len() > 128 {
        return Err(DomainError::Validation("Search is limited to 128 bytes".into()).into());
    }
    let offset = i64::from(query.page - 1) * i64::from(query.page_size);
    let limit = i64::from(query.page_size);
    let result: Value = database(&state)?
        .with_tenant(principal.tenant, move |tx| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "WITH classified AS (
            SELECT r.*, CASE WHEN resolved_at IS NOT NULL THEN 'resolved' WHEN paused THEN 'paused'
            WHEN attempts>=8 THEN 'quarantined' ELSE 'retrying' END AS state
            FROM event_analysis_retries r), filtered AS (
            SELECT * FROM classified WHERE ($1='all' OR ($1='open' AND resolved_at IS NULL) OR state=$1)
            AND ($2='' OR position(lower($2) in lower(event_id::text || ' ' || error_code))>0)), selected AS (
            SELECT event_id,attempts,total_attempts,version,error_code,last_error,state,first_failed_at,
            updated_at,resolved_at,CASE WHEN state='retrying' THEN available_at ELSE NULL END AS available_at
            FROM filtered ORDER BY updated_at DESC,event_id LIMIT $3 OFFSET $4)
            SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY s.updated_at DESC,s.event_id) FROM selected s),'[]'::jsonb),
            'total',(SELECT count(*) FROM filtered))",
                )
                .bind(filter)
                .bind(keyword)
                .bind(limit)
                .bind(offset)
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("analysis_failure_list", &e))
            })
        })
        .await?;
    let mut result = result;
    result["can_manage"] = json!(principal.require(&state, "sources", "write").is_ok());
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionInput {
    expected_version: i64,
}

pub(super) async fn act(
    State(state): State<AppState>,
    principal: Principal,
    Path((id, action)): Path<(Id, String)>,
    ApiJson(input): ApiJson<ActionInput>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "sources", "write")?;
    if !["retry", "pause"].contains(&action.as_str()) || input.expected_version < 1 {
        return Err(DomainError::Validation("A valid action and current expected_version are required".into()).into());
    }
    let tenant = principal.tenant;
    let actor = principal.subject_id.map(|id| id.to_string()).unwrap_or_else(|| "authenticated-service".into());
    let paused = action == "pause";
    let result = database(&state)?
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                let current: Option<(i64, bool)> = sqlx::query_as(
                    "SELECT version,resolved_at IS NOT NULL
            FROM event_analysis_retries WHERE event_id=$1 FOR UPDATE",
                )
                .bind(id.as_uuid())
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("analysis_failure_lock", &e))?;
                let (version, resolved) =
                    current.ok_or_else(|| DomainError::NotFound { entity: "analysis-failure", id: id.to_string() })?;
                if version != input.expected_version || resolved {
                    return Err(DomainError::Conflict(
                        "The failure changed or was resolved; refresh before choosing an action".into(),
                    ));
                }
                let result: Value = sqlx::query_scalar(
                    "UPDATE event_analysis_retries SET paused=$2,
            attempts=CASE WHEN $2 THEN attempts ELSE 0 END,available_at=now(),updated_at=now(),version=version+1
            WHERE event_id=$1 RETURNING jsonb_build_object('event_id',event_id,'version',version,'paused',paused)",
                )
                .bind(id.as_uuid())
                .bind(paused)
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("analysis_failure_action", &e))?;
                sqlx::query(
                    "INSERT INTO event_analysis_actions(tenant_id,id,event_id,action,actor_id,previous_version)
            VALUES ($1,$2,$3,$4,$5,$6)",
                )
                .bind(tenant.as_uuid())
                .bind(Id::new().as_uuid())
                .bind(id.as_uuid())
                .bind(action)
                .bind(actor)
                .bind(version)
                .execute(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("analysis_action_history", &e))?;
                Ok(result)
            })
        })
        .await?;
    Ok(Json(result))
}

pub(super) async fn history(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    query: ListQuery,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "sources", "read")?;
    let offset = i64::from(query.page - 1) * i64::from(query.page_size);
    let limit = i64::from(query.page_size);
    let result = database(&state)?
        .with_tenant(principal.tenant, move |tx| {
            Box::pin(async move {
                let exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM event_analysis_retries WHERE event_id=$1)")
                        .bind(id.as_uuid())
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(|e| agf_storage::map_sqlx_err("analysis_history_owner", &e))?;
                if !exists {
                    return Err(DomainError::NotFound { entity: "analysis-failure", id: id.to_string() });
                }
                sqlx::query_scalar(
                    "WITH items AS (SELECT id,action,actor_id,previous_version,created_at
            FROM event_analysis_actions WHERE event_id=$1 ORDER BY created_at DESC,id LIMIT $2 OFFSET $3)
            SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(to_jsonb(i) ORDER BY i.created_at DESC,i.id) FROM items i),'[]'::jsonb),
            'total',(SELECT count(*) FROM event_analysis_actions WHERE event_id=$1))",
                )
                .bind(id.as_uuid())
                .bind(limit)
                .bind(offset)
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("analysis_action_history", &e))
            })
        })
        .await?;
    Ok(Json(result))
}
