//! The envelope cannot prove tenant ownership; only a platform administrator may inspect it.
use super::*;
use crate::{event_analysis::broker_quarantine as queue, routes::ApiJson};
use agf_core::rbac::SubjectKind;
use serde_json::{Value, json};

pub(super) fn can_inspect(state: &AppState, principal: &Principal) -> bool {
    principal.superadmin
        && principal.subject_kind == SubjectKind::User
        && principal.require(state, "sources", "read").is_ok()
}

fn require(state: &AppState, principal: &Principal, action: &str) -> ApiResult<()> {
    principal.require(state, "sources", action)?;
    if !principal.superadmin || principal.subject_kind != SubjectKind::User {
        return Err(DomainError::Forbidden("Broker quarantine requires a platform administrator session".into()).into());
    }
    Ok(())
}

pub(super) async fn list(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<Value>> {
    require(&state, &principal, "read")?;
    queue::recover_expired(&state).await?;
    let mut result = queue::list(
        &state,
        query.filters.get("state").cloned().unwrap_or_else(|| "quarantined".into()),
        query.q.unwrap_or_default(),
        i64::from(query.page_size),
        i64::from(query.page - 1) * i64::from(query.page_size),
    )
    .await?;
    result["can_manage"] = json!(principal.require(&state, "sources", "write").is_ok());
    Ok(Json(result))
}

pub(super) async fn detail(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    require(&state, &principal, "read")?;
    Ok(Json(queue::detail(&state, id, principal.display()).await?))
}

pub(super) async fn history(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    query: ListQuery,
) -> ApiResult<Json<Value>> {
    require(&state, &principal, "read")?;
    Ok(Json(
        queue::history(&state, id, i64::from(query.page_size), i64::from(query.page - 1) * i64::from(query.page_size))
            .await?,
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionInput {
    expected_version: i64,
    reason: String,
}

pub(super) async fn act(
    State(state): State<AppState>,
    principal: Principal,
    Path((id, action)): Path<(Id, String)>,
    ApiJson(input): ApiJson<ActionInput>,
) -> ApiResult<Json<Value>> {
    require(&state, &principal, "write")?;
    Ok(Json(queue::act(&state, id, input.expected_version, action, input.reason, principal.display()).await?))
}
