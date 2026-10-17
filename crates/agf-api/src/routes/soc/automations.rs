//! User-owned automatic response templates and side-effect-free trigger previews.
use super::*;
use crate::soar_automation as automation;

#[derive(Deserialize)]
pub(super) struct Body {
    #[serde(flatten)]
    book: CasePlaybookBody,
    #[serde(default)]
    expected_version: u64,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    separate_approver: bool,
    reason: String,
}

#[derive(Deserialize)]
pub(super) struct PreviewBody {
    #[serde(flatten)]
    book: CasePlaybookBody,
    alert_id: String,
}

pub(super) async fn list(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let rows = automation::summaries(&state, principal.tenant).await?;
    let page = query.paginate_vec(
        &rows,
        |row| format!("{} {}", row.playbook.name, row.playbook.key),
        |row| row.updated_at.to_rfc3339(),
    );
    let mut result = query.render_page(&page)?;
    result["can_manage"] = serde_json::json!(automation::can_manage(&state, &principal));
    result["durable"] = serde_json::json!(state.store.database().is_some());
    Ok(Json(result))
}

pub(super) async fn get(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let row = automation::get(&state, principal.tenant, parse_id(&id, "soar-automation")?).await?;
    Ok(Json(serde_json::json!({"automation":row})))
}

pub(super) async fn create(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<Body>,
) -> ApiResult<Json<serde_json::Value>> {
    if body.expected_version != 0 {
        return Err(DomainError::Validation("新配置 expected_version 应为 0".into()).into());
    }
    save(&state, &principal, Id::new(), body).await
}

pub(super) async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Body>,
) -> ApiResult<Json<serde_json::Value>> {
    let id = parse_id(&id, "soar-automation")?;
    automation::get(&state, principal.tenant, id).await?;
    save(&state, &principal, id, body).await
}

async fn save(state: &AppState, principal: &Principal, id: Id, body: Body) -> ApiResult<Json<serde_json::Value>> {
    let playbook = select_playbook_with_timeout(&body.book, 604_800)?;
    if body.enabled {
        validate_targets(&playbook)?;
    }
    let row = automation::save(
        state,
        principal,
        id,
        automation::Change {
            expected_version: body.expected_version,
            playbook,
            enabled: body.enabled,
            separate_approver: body.separate_approver,
            reason: body.reason,
        },
    )
    .await?;
    Ok(Json(serde_json::json!({"automation":row})))
}

fn validate_targets(book: &Playbook) -> ApiResult<()> {
    use agf_core::case::ContainmentAction as Action;
    for step in &book.steps {
        let required = match step.action {
            Some(Action::BlockDomain) => Some("domain"),
            Some(Action::BlockIp) => Some("ip"),
            Some(Action::RevokeCredential) => Some("api_key_id"),
            Some(Action::KillSession) => Some("session_id"),
            Some(Action::ForceLocalModel) => Some("endpoint_id"),
            Some(Action::Archive) => Some("reason"),
            _ => None,
        };
        if let Some(key) = required {
            if step.params.get(key).and_then(serde_json::Value::as_str).is_none_or(|value| value.trim().is_empty()) {
                return Err(DomainError::Validation(format!("启用前请填写步骤 {} 的 params.{key}", step.name)).into());
            }
        }
    }
    Ok(())
}

pub(super) async fn preview(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<PreviewBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    principal.require(&state, "alerts", "read")?;
    let id = parse_id(&body.alert_id, "alert")?;
    let alert = state
        .store
        .alert_get_durable(principal.tenant, id)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "alert", id: id.to_string() })?;
    let book = select_playbook_with_timeout(&body.book, 604_800)?;
    Ok(Json(serde_json::to_value(automation::preview(&state, principal.tenant, &alert, &book).await?)?))
}

pub(super) async fn deliveries(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let id = parse_id(&id, "soar-automation")?;
    automation::get(&state, principal.tenant, id).await?;
    let page = automation::deliveries(&state, principal.tenant, id, &query).await?;
    Ok(Json(query.render_page(&page)?))
}

#[derive(Deserialize)]
pub(super) struct Retry {
    expected_version: u64,
}
pub(super) async fn retry(
    State(state): State<AppState>,
    principal: Principal,
    Path((id, delivery)): Path<(String, String)>,
    ApiJson(body): ApiJson<Retry>,
) -> ApiResult<Json<serde_json::Value>> {
    let row = automation::retry(
        &state,
        &principal,
        parse_id(&id, "soar-automation")?,
        parse_id(&delivery, "soar-delivery")?,
        body.expected_version,
    )
    .await?;
    Ok(Json(serde_json::json!({"delivery":row})))
}

pub(super) async fn templates(
    principal: Principal,
    State(state): State<AppState>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let items = [
        (
            "case-review-only",
            "Create a case for human triage",
            "只建待研判案件（不执行处置）",
            None,
            serde_json::json!({"condition":"true"}),
        ),
        (
            "review-agent-isolation",
            "Review and isolate affected Agent",
            "审批后隔离关联 Agent",
            Some("isolate-agent"),
            serde_json::json!({}),
        ),
        (
            "review-domain-block",
            "Review and block a domain",
            "审批后封禁指定域名",
            Some("block-domain"),
            serde_json::json!({"domain":""}),
        ),
        (
            "review-key-revocation",
            "Review and revoke a platform API key",
            "审批后吊销平台 API Key",
            Some("revoke-credential"),
            serde_json::json!({"api_key_id":""}),
        ),
        (
            "review-edr-isolation",
            "Review EDR host isolation",
            "审批后隔离 EDR 主机",
            Some("isolate-host"),
            serde_json::json!({
                "asset_id":"","host_id":"","configuration_version":0,"reason":""
            }),
        ),
        (
            "review-scim-deactivation",
            "Review SCIM user deactivation",
            "审批后停用 SCIM 用户",
            Some("deactivate-external-user"),
            serde_json::json!({
                "asset_id":"","user_id":"","configuration_version":0,"reason":""
            }),
        ),
    ]
    .into_iter()
    .map(|(key, en, zh, action, params)| {
        serde_json::json!({"key":key,"name_zh":zh,"name_en":en,
        "playbook":{"key":key,"name":en,"description":if action.is_some() {
            "Review targets before enabling; applies only to newly created alerts."
        } else { "Creates a linked case without a response action; applies only to newly created alerts." },
        "trigger":{"min_severity":"high","asset_kinds":match action {
            Some("isolate-agent") => vec!["agent"], Some("deactivate-external-user") => vec!["credential"],
            _ => Vec::<&str>::new(),
        }},"enabled":true,"require_approval":action.is_some(),"timeout_secs":300,"version":1,
        "steps":if let Some(action) = action { serde_json::json!([{"name":en,"action":action,"params":params}]) }
            else { serde_json::json!([{"name":en,"params":params}]) }}})
    })
    .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({"items":items})))
}
