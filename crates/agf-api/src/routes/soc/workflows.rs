//! Queue, inspect and review tenant-scoped durable playbooks.
use super::*;
use crate::soar_workflow::{self as workflow, Actor};

#[derive(Debug, Deserialize)]
pub(super) struct Submit {
    #[serde(flatten)]
    book: CasePlaybookBody,
    #[serde(default)]
    separate_approver: bool,
}

async fn case(state: &AppState, tenant: TenantId, id: &str) -> ApiResult<Case> {
    state
        .store
        .case_get_durable(tenant, parse_id(id, "case")?)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "case", id: id.into() }.into())
}

pub(super) async fn submit(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Submit>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "cases", "write")?;
    if body.book.dry_run == Some(true) || body.book.approve == Some(true) {
        return Err(
            DomainError::Validation("演练请使用 /playbook；真实执行先提交，再在执行记录中单独审批".into()).into()
        );
    }
    let case = case(&state, principal.tenant, &id).await?;
    let book = select_playbook_with_timeout(&body.book, 604_800)?;
    let (trigger, context) = super::playbook_context::context(&state, principal.tenant, &case).await?;
    let matches = workflow::matches(&book, &trigger, &context)?;
    let run = workflow::prepare(workflow::Submission {
        id: Id::new(),
        case_id: case.id,
        actor: Actor::from_principal(&principal)?,
        book,
        context,
        separate_approver: body.separate_approver,
        matches,
        mock_mode: state.config.mock_mode,
    })?;
    state.configurations.put(principal.tenant, workflow::KIND, run.id, &run).await?;
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(serde_json::json!({"run":run,"durable":state.store.database().is_some()})),
    ))
}

pub(super) async fn list(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let case = case(&state, principal.tenant, &id).await?;
    let page = workflow::page(&state, principal.tenant, case.id, &query).await?;
    let mut response = query.render_page(&page)?;
    response["can_write"] = serde_json::json!(principal.require(&state, "cases", "write").is_ok());
    response["can_approve"] = serde_json::json!(workflow::can_approve(&state, &principal));
    response["actor_id"] = serde_json::json!(principal.subject_id);
    response["durable"] = serde_json::json!(state.store.database().is_some());
    Ok(Json(response))
}

pub(super) async fn get(
    State(state): State<AppState>,
    principal: Principal,
    Path((id, run)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let case = case(&state, principal.tenant, &id).await?;
    let run = workflow::get(&state, principal.tenant, parse_id(&run, "soar-run")?).await?;
    if run.case_id != case.id {
        return Err(DomainError::NotFound { entity: "soar-run", id: run.id.to_string() }.into());
    }
    Ok(Json(serde_json::json!({"run":run})))
}

pub(super) async fn decision(
    State(state): State<AppState>,
    principal: Principal,
    Path((id, run)): Path<(String, String)>,
    ApiJson(body): ApiJson<workflow::Decision>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let case = case(&state, principal.tenant, &id).await?;
    let run = workflow::get(&state, principal.tenant, parse_id(&run, "soar-run")?).await?;
    if run.case_id != case.id {
        return Err(DomainError::NotFound { entity: "soar-run", id: run.id.to_string() }.into());
    }
    let updated = workflow::decide(&state, &principal, run.id, body).await?;
    Ok(Json(serde_json::json!({"run":updated})))
}
