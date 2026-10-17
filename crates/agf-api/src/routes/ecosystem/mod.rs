//! 红队、集成适配器与阿里云自检路由。

use agf_core::audit::{AuditAction, AuditOutcome, AuditTarget};
use agf_core::enums::LlmProvider;
use agf_core::error::DomainError;
use agf_core::redteam::{AttackCategory, CampaignState};
use agf_core::time::Timestamp;
use agf_scan::redteam::{CampaignRunner, RedteamSimulator, render_markdown};
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::query::ListQuery;
use crate::routes::{ApiJson, parse_id};
use crate::state::AppState;

/// 红队 / 集成 / 阿里云路由。
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(multi_target::router())
        .route("/redteam/cases", get(list_redteam_cases))
        .route("/redteam/cases/{key}", get(get_redteam_case))
        .route("/redteam/stats", get(redteam_stats))
        .route("/redteam/campaigns", get(list_campaigns).post(launch_campaign))
        .route("/redteam/campaigns/{id}", get(get_campaign))
        .route("/redteam/campaigns/{id}/report", get(campaign_report))
        .route("/redteam/campaigns/{id}/evidence", get(campaign_evidence))
        .route("/redteam/campaigns/{id}/cancel", post(cancel_campaign))
        .route("/redteam/campaigns/{id}/retest", post(retest_campaign))
        .route("/redteam/agent-targets", get(agent_targets::list).post(agent_targets::save))
        .route("/redteam/agent-targets/{id}", get(agent_targets::get).delete(agent_targets::remove))
        .route("/redteam/mcp-targets", get(mcp_targets::list).post(mcp_targets::save))
        .route("/redteam/mcp-targets/{id}", get(mcp_targets::get).delete(mcp_targets::remove))
        .route("/redteam/mcp-targets/{id}/usage", get(mcp_targets::usage))
        .route("/integrations", get(list_integrations))
        .route("/integrations/health", get(integrations_health))
        .route("/integrations/{name}", get(get_integration))
        .route("/alicloud/services", get(alicloud_services))
        .route("/alicloud/selfcheck", get(alicloud_selfcheck))
        .route("/alicloud/selfcheck/markdown", get(alicloud_selfcheck_markdown))
}

pub use alicloud::*;
pub use integrations::*;
pub use redteam::*;

mod agent_live_execution;
mod agent_targets;
mod alicloud;
mod campaign_execution;
mod campaign_requests;
mod campaign_submission;
mod campaigns;
mod integrations;
mod mcp_live_execution;
mod mcp_targets;
mod mcp_tool_meter;
pub(crate) mod multi_target;
mod redteam;
pub use campaign_requests::{CampaignBody, CampaignPartition};
pub use campaigns::*;
