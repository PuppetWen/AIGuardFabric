//! 超管租户管理：创建后通过现有账号管理为目标租户分配管理员。
use crate::{
    error::ApiResult,
    middleware::Principal,
    routes::ApiJson,
    state::AppState,
    tenant_directory::{self, Entry},
};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    error::DomainError,
    ids::TenantId,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{patch, post},
};
use serde::Deserialize;

pub fn router() -> Router<AppState> {
    Router::new().route("/tenants", post(create)).route("/tenants/{id}", patch(update))
}
#[derive(Deserialize)]
struct Create {
    slug: String,
    name: String,
}
#[derive(Deserialize)]
struct Update {
    name: String,
    enabled: bool,
    expected_version: u64,
}
fn authorize(state: &AppState, principal: &Principal) -> ApiResult<()> {
    principal.require(state, "platform", "admin")?;
    if !principal.superadmin {
        return Err(DomainError::Forbidden("仅平台超级管理员可管理租户".into()).into());
    }
    Ok(())
}
async fn create(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<Create>,
) -> ApiResult<(axum::http::StatusCode, Json<Entry>)> {
    authorize(&state, &principal)?;
    let entry = tenant_directory::new(body.slug, body.name);
    let audit = audit_entry(&principal, &entry);
    let entry = tenant_directory::save_audited(&state, entry, true, audit).await?;
    Ok((axum::http::StatusCode::CREATED, Json(entry)))
}
async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Update>,
) -> ApiResult<Json<Entry>> {
    authorize(&state, &principal)?;
    let tenant = TenantId::parse(&id).map_err(|_| DomainError::Validation("无效的租户 ID".into()))?;
    let mut entry = tenant_directory::get(&state, tenant).await?;
    entry.name = body.name;
    entry.enabled = body.enabled;
    entry.version = body.expected_version;
    let audit = audit_entry(&principal, &entry);
    let entry = tenant_directory::save_audited(&state, entry, false, audit).await?;
    Ok(Json(entry))
}
fn audit_entry(principal: &Principal, entry: &Entry) -> AuditLog {
    AppState::audit_entry(
        principal.tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(principal, "tenant-management"),
        AuditTarget::new("tenant", Some(entry.id.to_string()), Some(entry.slug.clone())),
        if entry.enabled { "创建或启用租户" } else { "停用租户" },
    )
}
