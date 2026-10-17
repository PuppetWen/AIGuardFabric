//! 审计链、报表、设置与 OpenAPI 路由。

use agf_auth::api_key::ApiKeyIssueRequest;
use agf_core::audit::{AuditAction, AuditOutcome, AuditTarget};
use agf_core::error::DomainError;
use agf_core::ids::Id;
use agf_core::report::{ReportFormat, ReportKind, ReportSchedule, ReportState};
use agf_core::time::{TimeRange, Timestamp};
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::query::ListQuery;
use crate::routes::{ApiJson, parse_id};
use crate::state::AppState;

/// 审计 / 报表 / 设置 / OpenAPI 路由。
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/audit", get(list_audit))
        .route("/audit/verify", get(verify_audit_chain))
        .route("/audit/stats", get(audit_stats))
        .route("/reports", get(list_reports).post(generate_report))
        .route("/reports/channels", get(report_channels))
        .route("/reports/schedules", get(report_schedules).post(create_report_schedule))
        .route("/reports/schedules/{id}", axum::routing::patch(update_report_schedule).delete(delete_report_schedule))
        .route("/reports/schedules/{id}/run", axum::routing::post(run_report_schedule))
        .route("/reports/{id}", get(get_report))
        .route("/reports/{id}/download", get(download_report))
        .route("/settings", get(settings_snapshot))
        .route("/settings/api-keys", get(list_api_keys).post(create_api_key))
        .route("/settings/api-keys/{id}", axum::routing::delete(revoke_api_key))
        .route("/openapi.json", get(openapi_spec))
}

pub use audit::*;
pub use labels::*;
pub use openapi::*;
pub use report_render::*;
pub use report_schedules::*;
pub use reports::*;
pub use settings::*;

mod asset_contract;
mod audit;
mod campaign_contract;
mod labels;
mod openapi;
mod report_details;
mod report_render;
mod report_schedules;
mod reports;
mod rule_contract;
mod scan_contract;
mod search_alert_contract;
mod settings;
