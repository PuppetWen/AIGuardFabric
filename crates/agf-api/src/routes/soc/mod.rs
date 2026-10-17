//! 告警、案件、通知、配额与 SOAR 路由。
//!
//! 案件剧本使用持久化处置执行器；人工审批检查登录用户的 cases:admin 权限。
//! 通知按租户已配置渠道派发；仅 mock_mode 的旧演示通知路径使用 MockChannel。
//! 聚合为实时计算；SLA 派生字段写回台账，暂停窗口及工作日历仍待实现。

use std::collections::BTreeMap;

use agf_core::audit::{AuditAction, AuditOutcome, AuditTarget};
use agf_core::case::{Case, CaseEvent, CaseEventKind, Playbook};
use agf_core::enums::{AlertState, CaseState, PolicyAction, QuotaDimension, QuotaScope, Severity};
use agf_core::error::DomainError;
use agf_core::ids::{Id, TenantId};
use agf_core::notify::{ChannelKind, NotificationChannel as ChannelConfig};
use agf_core::quota::{Quota, QuotaWindow};
use agf_core::time::Timestamp;
use agf_correlate::aggregate::{AggregationConfig, AlertAggregator, AlertInput, SimilarityPolicy, SuppressionRule};
use agf_correlate::entity::{EntityKind, entity_alignment_key};
use agf_correlate::notify::{MockChannel, NotifyError};
use agf_correlate::playbook::{PlaybookEngine, PlaybookError, RunContext, TriggerInput};
use agf_correlate::sla::{EscalationStep, SlaClock, SlaTarget};
use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::query::ListQuery;
use crate::routes::{ApiJson, parse_id};
use crate::state::AppState;
use crate::store::SoarRunRecord;

/// 告警 / 案件 / 配额路由。
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/alerts", get(list_alerts).post(create_alert))
        .route("/alerts/aggregate", post(alert_aggregate))
        .route("/alerts/sla-refresh", post(alert_sla_refresh))
        .route("/alerts/{id}", get(get_alert))
        .route("/alerts/{id}/analysis", get(ai_analysis::alert_analysis).post(ai_analysis::analyze_alert))
        .route("/alerts/{id}/state", post(set_alert_state))
        .route("/alerts/{id}/escalate", post(escalate_alert))
        .route("/cases", get(list_cases).post(create_case))
        .route("/cases/{id}", get(get_case))
        .route("/cases/{id}/analysis", get(ai_analysis::case_analysis).post(ai_analysis::analyze_case))
        .route("/cases/{id}/state", post(set_case_state))
        .route("/cases/{id}/timeline", get(case_timeline).post(append_case_timeline))
        .route("/cases/{id}/sla", get(case_sla))
        .route("/cases/{id}/playbook", post(case_playbook))
        .route("/cases/{id}/playbook-runs", get(workflows::list).post(workflows::submit))
        .route("/cases/{id}/playbook-runs/{run}", get(workflows::get))
        .route("/cases/{id}/playbook-runs/{run}/decision", post(workflows::decision))
        .route("/cases/{id}/containments", get(containment_routes::list))
        .route("/cases/{id}/containments/{control}/release", post(containment_routes::release))
        .route("/soar/automations", get(automations::list).post(automations::create))
        .route("/soar/automations/templates", get(automations::templates))
        .route("/soar/automations/preview", post(automations::preview))
        .route("/soar/automations/{id}", get(automations::get).put(automations::update))
        .route("/soar/automations/{id}/deliveries", get(automations::deliveries))
        .route("/soar/automations/{id}/deliveries/{delivery}/retry", post(automations::retry))
        .route("/notifications/send", post(notify_send))
        .route("/quotas", get(list_quotas).post(upsert_quota))
        .route("/quotas/snapshot", get(quota_snapshot))
}

pub use alert_ops::*;
pub use alerts::*;
pub use cases::*;
pub use playbooks::*;
mod automations;
mod containment_routes;
mod playbook_context;
mod playbooks;
mod workflows;
pub use notify::*;
pub use parsers::*;
pub use quotas::*;

mod ai_analysis;
mod alert_ops;
mod alerts;
mod cases;
mod notify;
mod parsers;
mod quotas;
mod support;

use support::*;

pub fn analysis_endpoint_specs() -> Vec<super::platform::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        ("/api/v1/alerts/{id}/analysis", Get, "getAlertModelAnalysis", "读取告警模型证据研判", "alerts"),
        ("/api/v1/alerts/{id}/analysis", Post, "analyzeAlertEvidence", "调用当前租户网关研判告警证据", "alerts"),
        ("/api/v1/cases/{id}/analysis", Get, "getCaseModelAnalysis", "读取案件模型链路解释", "cases"),
        ("/api/v1/cases/{id}/analysis", Post, "analyzeCaseEvidence", "调用当前租户网关解释案件证据", "cases"),
    ]
    .into_iter()
    .map(|(path, method, id, summary, tag)| super::platform::EndpointSpec {
        path,
        method,
        id,
        summary,
        tag,
        implemented: true,
    })
    .collect()
}
