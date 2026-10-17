//! 规则库、扫描任务与策略路由。

use agf_core::audit::{AuditAction, AuditOutcome, AuditTarget};
use agf_core::enums::{DataClass, InterceptPoint, PolicyAction, RiskDomain, Severity};
use agf_core::error::DomainError;
use agf_core::ids::Id;
use agf_core::policy::{Policy, PolicyContext, PolicyLanguage, StructuredCondition};
use agf_core::rule::RuleDefinition;
use agf_core::time::Timestamp;
use agf_runtime::engine::{EngineConfig, RuntimeEngine};
use agf_scan::engine::{ScanRequest, ScanTarget, ScanTargetKind};
use agf_scan::samples::SampleRegression;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::query::ListQuery;
use crate::routes::{ApiJson, parse_id, todo_endpoint};
use crate::state::AppState;
use crate::store::{ScanJob, ScanJobState};

/// 规则 / 扫描 / 策略路由。
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/rules", get(list_rules).post(rule_mutations::publish))
        .route("/rules/summary", get(rules_summary))
        .route("/rules/{key}", get(get_rule).patch(rule_mutations::patch))
        .route("/rules/{key}/versions", get(rule_mutations::history))
        .route("/rules/{key}/versions/{version}/restore", post(rule_mutations::restore))
        .route("/rules/{key}/regression", post(run_regression))
        .route(
            "/scans",
            get(list_scans).post(create_scan).layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route("/scans/{task_id}", get(get_scan))
        .route("/scans/{task_id}/cancel", post(cancel_scan))
        .route("/policies", get(list_policies).post(create_policy))
        .route("/policies/dry-run", post(dry_run_adhoc))
        .route("/policies/reload", post(reload_policies))
        .route("/policies/{id}", get(get_policy).put(update_policy).delete(delete_policy))
        .route("/policies/{id}/dry-run", post(dry_run_policy))
        .route("/policies/{id}/versions", get(policy_versions::history))
        .route("/policies/{id}/versions/{version}/restore", post(policy_versions::rollback))
}

pub use policies::*;
pub use rules::*;
pub use scans::*;

mod policies;
mod policy_versions;
mod rule_mutations;
mod rules;
mod scan_execution;
mod scan_judge;
mod scans;
