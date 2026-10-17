//! 通知渠道设置、显式测试与投递历史。
use crate::{
    error::ApiResult,
    middleware::Principal,
    notification_config::{self as config, StoredChannel, Update},
    routes::ApiJson,
    state::AppState,
};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    enums::Severity,
    error::DomainError,
    ids::Id,
    notify::ChannelKind,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post, put},
};
use serde_json::{Value, json};
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/settings/notifications", get(list))
        .route("/settings/notifications/{kind}", put(save))
        .route("/settings/notifications/{kind}/test", post(test))
        .route("/notifications/history", get(history))
        .route("/notifications/{id}/retry", post(retry))
        .route("/notifications/inbox", get(inbox))
        .route("/notifications/inbox/read", post(mark_read))
}
async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "read")?;
    let rows = state.configurations.list::<StoredChannel>(principal.tenant, config::KIND).await?;
    let mut views = Vec::new();
    for kind in ChannelKind::all() {
        if let Some(row) = rows.iter().find(|row| row.channel == kind) {
            views.push(config::view(row, &config::decrypt(&state, principal.tenant, row)?, state.config.mock_mode));
        } else {
            views.push(json!({"channel":kind,"version":0,"enabled":false,"target":"","configured":false,
            "settingsJson":"{}","secretKeys":[],"minSeverity":"low","mocked":state.config.mock_mode && kind != ChannelKind::InApp}));
        }
    }
    Ok(Json(json!(views)))
}
async fn save(
    State(state): State<AppState>,
    principal: Principal,
    Path(kind): Path<String>,
    ApiJson(body): ApiJson<Update>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "write")?;
    let channel = config::parse(&kind)?;
    let entry = AppState::audit_entry(
        principal.tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "notifications"),
        AuditTarget::new("notification-channel", Some(kind), None),
        "保存加密通知配置",
    );
    let result = config::save_audited(&state, principal.tenant, channel, body, entry).await?;
    Ok(Json(result))
}
async fn test(State(state): State<AppState>, principal: Principal, Path(kind): Path<String>) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "write")?;
    let kind = config::parse(&kind)?;
    let row = state
        .configurations
        .get::<StoredChannel>(principal.tenant, config::KIND, config::id(principal.tenant, kind))
        .await?
        .filter(|row| row.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("请先保存并启用渠道，再发送测试通知".into()))?;
    let result = crate::notification_delivery::dispatch(
        &state,
        principal.tenant,
        vec![row],
        "test",
        Id::new(),
        "AIGuardFabric 渠道连接测试",
        "这是一条由管理员在通知设置页面主动发送的测试通知。",
        Severity::Critical,
    )
    .await?;
    state
        .audit(
            principal.tenant,
            AuditAction::Execute,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "notification-test"),
            AuditTarget::new("notification-channel", Some(kind.as_str().into()), None),
            "测试通知已处理，请查看投递回执",
        )
        .await?;
    Ok(Json(result))
}
async fn history(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "read")?;
    let mut history = crate::notification_outbox::history(&state, principal.tenant).await?;
    history.extend(state.configurations.list::<Value>(principal.tenant, "notification-delivery").await?);
    Ok(Json(json!(history)))
}
async fn retry(State(state): State<AppState>, principal: Principal, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    principal.require(&state, "settings", "write")?;
    let id = Id::parse(&id).map_err(|_| DomainError::Validation("通知编号无效".into()))?;
    let result = crate::notification_outbox::retry(&state, principal.tenant, id).await?;
    state
        .audit(
            principal.tenant,
            AuditAction::Execute,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "notification-retry"),
            AuditTarget::new("notification", Some(id.to_string()), None),
            "管理员重试通知投递",
        )
        .await?;
    Ok(Json(result))
}
async fn inbox(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    Ok(Json(json!(crate::notification_inbox::list(&state, &principal).await?)))
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadBody {
    ids: Vec<Id>,
}
async fn mark_read(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<ReadBody>,
) -> ApiResult<Json<Value>> {
    let count = crate::notification_inbox::mark(&state, &principal, body.ids).await?;
    Ok(Json(json!({"marked":count})))
}
