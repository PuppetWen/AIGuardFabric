//! Console projections and action endpoints.
//!
//! Skill review and allowlists share the durable asset transaction and lifecycle checks.
//! Model routes are stored per tenant and consumed by the gateway on each request.
//! Usage reads deduplicated durable/meter records; mock and real aggregates stay separate.
//! Monetary values are CNY estimates derived from configured endpoint prices, not supplier bills.
//! cost_usd and budget_usd_per_day are deprecated compatibility spellings of the same CNY value.
//! Rule, SOC and integration handlers keep their resource-specific permissions and storage.
//! Collection responses are either explicit pagination envelopes or documented arrays; failures
//! are returned as errors, never generated demonstration records.

use std::collections::BTreeMap;

use agf_adapters::contract::{AdapterCategory, AdapterMetadata};
use agf_adapters::health::AdapterHealthRecord;
use agf_core::asset::{Asset, AssetChange, ChangeKind};
use agf_core::enums::{AliCloudService, AssetKind, LifecycleState, LlmProvider, Severity};
use agf_core::error::DomainError;
use agf_core::ids::{Id, TenantId};
use agf_core::mcp::ToolTraits;
use agf_core::model::UsageRecord;
use agf_core::redteam::RedteamResult;
use agf_core::time::Timestamp;
use agf_correlate::playbook::{PlaybookRun, RunOutcome, StepOutcome, StepTrace};
use agf_scan::loader::{RulePackLoader, RulesDir};
use agf_scan::samples::SampleRegression;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::query::ListQuery;
use crate::routes::platform::EndpointSpec;
use crate::routes::{ApiJson, parse_id};
use crate::state::AppState;
use crate::store::{ModelRoutePolicy, SoarRunRecord};

/// 前端 `ToolCapability` 允许的取值（与 `domain.ts` 一致）。
pub(super) const TOOL_CAPABILITIES: [&str; 7] =
    ["read", "write", "execute", "network", "filesystem", "credential", "payment"];

/// 前端 `ModelRoutePolicy['strategy']` 的四个取值（`domain.ts` 词表；越界即 400）。
pub(super) const ROUTE_STRATEGIES: [&str; 4] = ["priority", "weighted", "cost-first", "latency-first"];

/// 云服务 → 前端 `AliCloudService` 词表取值（`domain.ts` 不含 `agentteams`）。
///
/// 后端 `AliCloudService::as_str()` 是**适配器注册名**（`alicloud-cms`…），而前端词表是
/// `cms`/`apig`/…，两者不能直接互通，故显式映射；`AgentTeams` 走 `/alicloud/agentteams` 团队视图。
pub(super) const fn binding_service(service: AliCloudService) -> Option<&'static str> {
    match service {
        AliCloudService::Cms => Some("cms"),
        AliCloudService::Apig => Some("apig"),
        AliCloudService::Mse => Some("mse"),
        AliCloudService::Privatelink => Some("privatelink"),
        AliCloudService::SchedulerX3 => Some("schedulerx3"),
        AliCloudService::AgentTeams => None,
    }
}

/// 控制台补齐端点路由。
///
/// 与既有模块**无路径冲突**：静态段（`/alerts/escalation-routes`、`/integrations/adapters`）
/// 优先于既有参数段（`/alerts/{id}`、`/integrations/{name}`），这是 matchit 的既定优先级；
/// 唯一同形冲突是 `/rules/{id}`（与既有 `/rules/{key}` 同形），故不注册，见模块文档。
pub fn router() -> Router<AppState> {
    Router::new()
        // A. 模型网关
        .route("/models/route-policies", get(list_route_policies).post(create_route_policy))
        .route("/models/route-policies/{id}", put(save_route_policy))
        .route("/models/usage", get(list_usage))
        .route("/models/usage/aggregate", get(usage_aggregate))
        .route("/models/usage/projection-status", get(meter_status::meter_projection_status))
        // B. SOC / 生态动作
        .route("/skills/{id}/status", post(set_skill_status))
        .route("/skills/{id}/whitelist", put(set_skill_whitelist))
        .route("/findings/{id}/status", post(set_finding_status))
        .route("/alerts/{id}/status", post(set_alert_status))
        .route("/alerts/escalation-routes", get(list_escalation_routes))
        .route("/cases/{id}/soar-runs", get(list_soar_runs))
        .route("/mcp-servers/{id}/tools", get(list_mcp_tools))
        .route("/redteam/campaigns/{id}/results", get(list_campaign_results))
        .route("/rules/{id}/test", post(test_rule))
        // C. 生态与别名
        .route("/ingest/sources", get(ingest_sources).post(crate::routes::ingest::create_source))
        .route(
            "/ingest/sources/{id}",
            get(crate::routes::ingest::get_source)
                .put(crate::routes::ingest::update_source)
                .patch(crate::routes::ingest::toggle_source)
                .delete(crate::routes::ingest::delete_source),
        )
        .route("/ingest/sources/{id}/events", axum::routing::post(crate::routes::ingest::push_events))
        .route("/ingest/sources/{id}/poll", axum::routing::post(crate::routes::ingest::poll_source))
        .route("/ingest/parsers", get(ingest_parsers))
        .route("/integrations/adapters", get(list_adapters))
        .route("/integrations/adapters/{id}", get(get_adapter))
        // `client.ts` 的 `selfCheck()` 用 POST；清单条目按题目要求登记 GET，两个方法共用处理器。
        .route("/alicloud/self-check", get(alicloud_self_check).post(alicloud_self_check))
        .route("/alicloud/agentteams", get(list_agent_teams))
        .route("/alicloud/cross-team-calls", get(list_cross_team_calls))
        .route("/alicloud/service-bindings", get(list_service_bindings))
}

/// 端点清单（**不带 `/api/v1` 前缀**的相对路径，供父模块统一加前缀后并入
/// [`crate::routes::platform::endpoint_specs`]）。
///
/// `implemented` 与真实行为一致：本模块 22 条端点全部已实现（无 501）。
#[must_use]
pub fn endpoint_specs() -> Vec<EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post, Put};
    vec![
        EndpointSpec {
            path: "/api/v1/models/route-policies",
            method: Get,
            id: "listModelRoutePolicies",
            summary: "模型路由策略列表（控制台裸数组；读演示灌库写入的路由策略记录）",
            tag: "models",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/models/route-policies/{id}",
            method: Put,
            id: "saveModelRoutePolicy",
            summary: "保存模型路由策略（落库并返回更新后的对象；不热更新 ModelRouter）",
            tag: "models",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/models/usage",
            method: Get,
            id: "listModelUsage",
            summary: "模型计量明细（分页信封；读 AppState.meter 里该租户的计量行）",
            tag: "models",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/models/usage/aggregate",
            method: Get,
            id: "modelUsageAggregate",
            summary: "按端点/模型聚合的计费与 token（控制台裸数组）",
            tag: "models",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/models/usage/projection-status",
            method: Get,
            id: "modelMeterProjectionStatus",
            summary: "当前节点累计计量投影健康（纯读；不是租户账本或厂商账单）",
            tag: "models",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/skills/{id}/status",
            method: Post,
            id: "setSkillStatus",
            summary: "Skill 审批状态流转（返回更新后的 Skill）",
            tag: "skills",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/skills/{id}/whitelist",
            method: Put,
            id: "setSkillWhitelist",
            summary: "更新 Skill 白名单（domains/paths，返回更新后的 Skill）",
            tag: "skills",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/findings/{id}/status",
            method: Post,
            id: "setFindingStatusAlias",
            summary: "发现状态流转（/findings/{id}/state 的控制台别名）",
            tag: "findings",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/alerts/{id}/status",
            method: Post,
            id: "setAlertStatusAlias",
            summary: "告警状态流转（/alerts/{id}/state 的控制台别名）",
            tag: "alerts",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/alerts/escalation-routes",
            method: Get,
            id: "listEscalationRoutes",
            summary: "告警升级路由（控制台裸数组；来源为 SLA 策略升级阶梯）",
            tag: "alerts",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/cases/{id}/soar-runs",
            method: Get,
            id: "listCaseSoarRuns",
            summary: "案件剧本执行轨迹（控制台裸数组；行由 PlaybookEngine 真实执行产出）",
            tag: "cases",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/mcp-servers/{id}/tools",
            method: Get,
            id: "listMcpServerTools",
            summary: "MCP Server 工具清单（控制台裸数组；台账未登记工具时为空）",
            tag: "mcps",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/redteam/campaigns/{id}/results",
            method: Get,
            id: "listCampaignResults",
            summary: "战役逐用例结果（控制台裸数组）",
            tag: "redteam",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/rules/{id}",
            method: Get,
            id: "getRuleByIdAlias",
            summary: "规则详情（与既有 /rules/{key} 同形路由，别名无需二次注册）",
            tag: "rules",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/rules/{id}/test",
            method: Post,
            id: "testRule",
            summary: "规则回归测试（返回 RuleTestResult；样本不通过也是 200）",
            tag: "rules",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/ingest/sources",
            method: Get,
            id: "listIngestSources",
            summary: "接入面清单（既有 /sources 的控制台别名，同一处理器）",
            tag: "sources",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/ingest/parsers",
            method: Get,
            id: "listIngestParsers",
            summary: "解析器列表（既有 /parsers 的控制台别名，同一处理器）",
            tag: "parsers",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/integrations/adapters",
            method: Get,
            id: "listIntegrationAdapters",
            summary: "集成适配器注册表（控制台裸数组；字段对齐前端 Adapter）",
            tag: "integrations",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/integrations/adapters/{id}",
            method: Get,
            id: "getIntegrationAdapter",
            summary: "单个集成适配器详情（同一注册表）",
            tag: "integrations",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/alicloud/self-check",
            method: Get,
            id: "alicloudSelfCheckAlias",
            summary: "云环境自检项（控制台裸数组；同 /alicloud/selfcheck 数据源，POST 亦已注册）",
            tag: "alicloud",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/alicloud/agentteams",
            method: Get,
            id: "listAlicloudAgentTeams",
            summary: "阿里云 AgentTeams 团队（控制台裸数组）",
            tag: "alicloud",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/alicloud/cross-team-calls",
            method: Get,
            id: "listAlicloudCrossTeamCalls",
            summary: "跨 Team 调用链（控制台裸数组）",
            tag: "alicloud",
            implemented: true,
        },
        EndpointSpec {
            path: "/api/v1/alicloud/service-bindings",
            method: Get,
            id: "listAlicloudServiceBindings",
            summary: "阿里云服务绑定视图（控制台裸数组；同 /alicloud/services 数据源）",
            tag: "alicloud",
            implemented: true,
        },
    ]
}

mod handlers_ecosystem;
mod handlers_models;
mod handlers_skills;
mod handlers_soc;
mod meter_status;
mod projections;
mod projections_soc;

pub use handlers_ecosystem::*;
pub use handlers_models::*;
pub use handlers_skills::*;
pub use handlers_soc::*;

use projections::*;
use projections_soc::*;
