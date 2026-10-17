//! OpenAPI 3.1 规范组装与全部端点清单。

use super::*;

mod agentteams_contract;
mod agentteams_orchestration_contract;
mod agentteams_orchestration_schemas;
mod agentteams_role_mapping_contract;
mod agentteams_task_handling_contract;
mod agentteams_trace_contract;
mod apig_configuration_publication_contract;
mod apig_policy_publication_contract;
mod audit_anchor_contract;
mod base_specs;
mod cms_queue_contract;
mod cms_queue_schemas;
mod gateway_settlement_contract;
mod identity;
mod integration_completion_contract;
mod mcp_specs;
mod mse_config_publication_contract;
mod mse_inventory_contract;
mod policy_publication_contract;
mod privatelink_inventory_contract;
mod privatelink_provisioning_contract;
mod process_hook_contract;
mod process_hook_schemas;
mod quota_contract;
mod redteam_multi_target_contract;
mod runtime_audit_integrity_contract;
mod scheduler_managed_jobs_contract;
mod scheduler_native_contract;
mod scheduler_native_schemas;
mod semantic_cache_profile_contract;
mod team_management_contract;
mod worker_quota_contract;

/// OpenAPI 3.1 规范（`GET /openapi.json` 与 `/api/v1/openapi.json`）。
///
/// 用 `utoipa` 的 builder 组装：路径/操作/响应结构由本函数声明，
/// schema 由 `utoipa::ToSchema` 派生类型直接注册。Swagger UI 页面因
/// `utoipa-swagger-ui` 的 build script 在本机不可用而缺失（见 `TODO(api-openapi-swagger)`）。
///
/// 同一路径的多个方法（如 `/api/v1/policies` 的 GET/POST/PUT/DELETE、
/// `/api/v1/reports/schedules` 的 GET/POST）**合并进同一个 `PathItem`**：
/// `PathsBuilder::path` 是"插入即替换"，逐个 `path()` 会让后者覆盖同路径的前者
/// （清单里先出现的 GET 会从规范里消失）。
pub async fn openapi_spec() -> Json<serde_json::Value> {
    use std::collections::BTreeMap;

    use utoipa::openapi::path::{PathItem, PathsBuilder};
    let mut items: BTreeMap<&'static str, PathItem> = BTreeMap::new();
    for spec in endpoint_specs() {
        let op = operation(&spec);
        let method = spec.method;
        let path = spec.path;
        items.entry(path).or_default().merge_operations(PathItem::new(method, op));
    }
    let mut paths = PathsBuilder::new();
    for (path, item) in items {
        paths = paths.path(path, item);
    }
    let document = utoipa::openapi::OpenApiBuilder::new()
        .info(
            utoipa::openapi::InfoBuilder::new()
                .title("AIGuardFabric API")
                .version(crate::VERSION)
                .description(Some(
                    "智御矩阵 AI 安全治理平台 HTTP API。错误响应统一为 RFC 9457 application/problem+json；\
                     未实现端点返回 501 并携带 todo 锚点。",
                ))
                .build(),
        )
        .paths(paths.build())
        .components(Some(
            utoipa::openapi::schema::ComponentsBuilder::new()
                .schema_from::<crate::error::ProblemDetails>()
                .schema_from::<crate::routes::auth::LoginBody>()
                .schema_from::<crate::routes::auth::ChangePasswordBody>()
                .schema_from::<crate::routes::auth::RefreshBody>()
                .schema_from::<crate::routes::assets::DiscoveryBody>()
                .schema_from::<crate::routes::assets::DiscoveryItem>()
                .schema_from::<crate::routes::assets::TransitionBody>()
                .schema_from::<crate::routes::asset_deletion::RemoveAssetBody>()
                .schema_from::<crate::routes::asset_edr::BindEdrHost>()
                .schema_from::<crate::routes::asset_iam::BindScimUser>()
                .schema_from::<crate::routes::assets::DriftBody>()
                .schema_from::<crate::asset_inventory::manual::Registration>()
                .schema_from::<crate::routes::assets::FindingStateBody>()
                // §4.11 四组资源的响应视图（字段名以前端类型定义为准，见 routes::ai_assets）
                .schema_from::<crate::routes::ai_assets::AgentView>()
                .schema_from::<crate::routes::ai_assets::McpServerView>()
                .schema_from::<crate::routes::ai_assets::SkillView>()
                .schema_from::<crate::routes::ai_assets::SkillReviewView>()
                .schema_from::<crate::routes::console_ops::SkillStatusBody>()
                .schema_from::<crate::routes::console_ops::SkillWhitelistBody>()
                .schema_from::<crate::routes::ai_assets::SkillWhitelistView>()
                .schema_from::<crate::routes::ai_assets::ModelEndpointView>()
                .schema_from::<crate::routes::soc::CaseBody>()
                .schema_from::<crate::routes::soc::QuotaBody>()
                .schema_from::<crate::routes::governance::ScanBody>()
                // schema_from 不递归注册嵌套类型；扫描目标必须独立进入组件表。
                .schema_from::<crate::routes::governance::ScanTargetBody>()
                .schema_from::<crate::routes::ecosystem::CampaignBody>()
                .schema_from::<crate::routes::ecosystem::CampaignPartition>()
                .schema_from::<crate::routes::platform::ApiKeyBody>()
                .schema_from::<crate::routes::platform::ReportScheduleBody>()
                .schema_from::<crate::runtime_audit::RecordIntegrity>()
                .build(),
        ))
        .build();
    let mut document = serde_json::to_value(document).unwrap_or(serde_json::Value::Null);
    super::asset_contract::describe(&mut document);
    super::search_alert_contract::describe(&mut document);
    super::rule_contract::describe(&mut document);
    super::scan_contract::describe(&mut document);
    super::campaign_contract::describe(&mut document);
    agentteams_contract::describe(&mut document);
    agentteams_orchestration_contract::describe(&mut document);
    agentteams_task_handling_contract::describe(&mut document);
    agentteams_trace_contract::describe(&mut document);
    apig_configuration_publication_contract::describe(&mut document);
    apig_policy_publication_contract::describe(&mut document);
    audit_anchor_contract::describe(&mut document);
    runtime_audit_integrity_contract::describe(&mut document);
    cms_queue_contract::describe(&mut document);
    mse_inventory_contract::describe(&mut document);
    mse_config_publication_contract::describe(&mut document);
    policy_publication_contract::describe(&mut document);
    process_hook_contract::describe(&mut document);
    privatelink_inventory_contract::describe(&mut document);
    privatelink_provisioning_contract::describe(&mut document);
    quota_contract::describe(&mut document);
    redteam_multi_target_contract::describe(&mut document);
    semantic_cache_profile_contract::describe(&mut document);
    agentteams_role_mapping_contract::describe(&mut document);
    gateway_settlement_contract::describe(&mut document);
    scheduler_native_contract::describe(&mut document);
    scheduler_managed_jobs_contract::describe(&mut document);
    worker_quota_contract::describe(&mut document);
    team_management_contract::describe(&mut document);
    integration_completion_contract::describe(&mut document);
    Json(document)
}

/// 端点描述（OpenAPI 生成与文档自查共用）。
#[allow(missing_debug_implementations)]
pub struct EndpointSpec {
    /// 路径。
    pub path: &'static str,
    /// HTTP 方法。
    pub method: utoipa::openapi::path::HttpMethod,
    /// operationId。
    pub id: &'static str,
    /// 摘要。
    pub summary: &'static str,
    /// 标签（资源组）。
    pub tag: &'static str,
    /// 是否已实现。
    pub implemented: bool,
}

fn operation(spec: &EndpointSpec) -> utoipa::openapi::path::OperationBuilder {
    use utoipa::openapi::path::OperationBuilder;
    use utoipa::openapi::response::Response as OaResponse;
    let success = if spec.implemented { "200" } else { "501" };
    let success_desc = if spec.implemented { "成功" } else { "尚未实现（problem+json，含 todo 锚点）" };
    OperationBuilder::new()
        .operation_id(Some(spec.id))
        .summary(Some(spec.summary))
        .description(Some(spec.summary))
        .tag(spec.tag)
        .response(success, OaResponse::new(success_desc))
        .response("401", OaResponse::new("未认证（problem+json）"))
        .response("403", OaResponse::new("权限不足或跨租户（problem+json）"))
        .response("429", OaResponse::new("限流（problem+json）"))
}

/// 全部端点清单（含未实现端点，供 `/openapi.json` 与覆盖对账使用）。
#[must_use]
pub fn endpoint_specs() -> Vec<EndpointSpec> {
    let mut specs = base_specs::endpoint_specs();
    specs.extend(audit_anchor_contract::endpoint_specs());
    specs.extend(agentteams_trace_contract::endpoint_specs());
    specs.extend(agentteams_orchestration_contract::endpoint_specs());
    specs.extend(agentteams_task_handling_contract::endpoint_specs());
    specs.extend(apig_configuration_publication_contract::endpoint_specs());
    specs.extend(apig_policy_publication_contract::endpoint_specs());
    specs.extend(cms_queue_contract::endpoint_specs());
    specs.extend(mse_inventory_contract::endpoint_specs());
    specs.extend(mse_config_publication_contract::endpoint_specs());
    specs.extend(policy_publication_contract::endpoint_specs());
    specs.extend(process_hook_contract::endpoint_specs());
    specs.extend(runtime_audit_integrity_contract::endpoint_specs());
    specs.extend(semantic_cache_profile_contract::endpoint_specs());
    specs.extend(agentteams_role_mapping_contract::endpoint_specs());
    specs.extend(gateway_settlement_contract::endpoint_specs());
    specs.extend(privatelink_inventory_contract::endpoint_specs());
    specs.extend(privatelink_provisioning_contract::endpoint_specs());
    specs.extend(scheduler_native_contract::endpoint_specs());
    specs.extend(redteam_multi_target_contract::endpoint_specs());
    specs.extend(scheduler_managed_jobs_contract::endpoint_specs());
    specs.extend(mcp_specs::endpoint_specs());
    specs.extend(identity::endpoint_specs());
    specs.extend(worker_quota_contract::endpoint_specs());
    specs.extend(team_management_contract::endpoint_specs());
    specs.extend(integration_completion_contract::endpoint_specs());
    specs.extend(crate::routes::console::endpoint_specs());
    specs.extend(crate::routes::console_ops::endpoint_specs());
    // 接入面（`ingest`）中**不便写在本文件历史清单里**的端点由该模块自己导出（本轮新增
    // `/api/v1/ingest/agent`），与 console/console_ops 同一约定：路径必须是完整路径。
    specs.extend(crate::routes::ingest::endpoint_specs());
    specs.extend(crate::routes::correlation::endpoint_specs());
    specs.extend(crate::routes::soc::analysis_endpoint_specs());

    specs
}
