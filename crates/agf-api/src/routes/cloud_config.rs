//! Explicit cloud configuration and operations; list endpoints never contact cloud providers.
use crate::{
    cloud_runtime::{self, Request},
    cloud_store as store,
    error::ApiResult,
    integration_store::Update,
    middleware::Principal,
    routes::ApiJson,
    state::AppState,
};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    enums::AliCloudService,
    ids::Id,
    time::Timestamp,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde_json::{Value, json};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/agentteams/sync", post(sync_inventory))
        .route("/alicloud/connections", get(list))
        .route("/alicloud/connections/{name}", get(view).put(save))
        .route("/alicloud/connections/{name}/operations", get(history).post(execute))
        .route("/alicloud/connections/{name}/operations/{id}", get(receipt))
        .route("/alicloud/connections/{name}/operations/{id}/recover", post(recover))
        .route("/alicloud/connections/{name}/probe", post(probe))
}
async fn sync_inventory(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<crate::cloud_inventory::SyncRequest>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    principal.require(&state, "assets", "write")?;
    let result = crate::cloud_inventory::sync(
        &state,
        principal.tenant,
        actor(&principal),
        AppState::audit_actor(&principal, "cloud-operation"),
        body,
    )
    .await;
    if result.is_err() {
        audit(&state, &principal, "alicloud-agentteams", "完整盘点团队、Worker 和任务；同步本地资产台账", false)
            .await?;
    }
    Ok(Json(result?))
}
async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    let mut items = Vec::new();
    for service in AliCloudService::all() {
        let name = service.as_str();
        let row = store::load(&state, principal.tenant, name).await?;
        items.push(json!({"name":name,"display_name":agf_alicloud::mock::display_name_of(service),
            "configured":row.is_some(),"enabled":row.as_ref().is_some_and(|row|row.enabled),
            "mock":state.config.mock_mode || row.as_ref().is_none_or(|row|row.mock),
            "version":row.as_ref().map_or(0,|row|row.version)}));
    }
    Ok(Json(json!({"items":items})))
}
async fn view(State(state): State<AppState>, principal: Principal, Path(name): Path<String>) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    Ok(Json(store::view(&state, principal.tenant, &name).await?))
}
async fn save(
    State(state): State<AppState>,
    principal: Principal,
    Path(name): Path<String>,
    ApiJson(body): ApiJson<Update>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    let entry = AppState::audit_entry(
        principal.tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "cloud-configuration"),
        AuditTarget::new("cloud-integration", None, Some(name.clone())),
        "保存加密云配置",
    );
    let value = store::save_audited(&state, principal.tenant, &name, body, entry).await?;
    Ok(Json(value))
}
async fn execute(
    State(state): State<AppState>,
    principal: Principal,
    Path(name): Path<String>,
    ApiJson(body): ApiJson<Request>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    let value = cloud_runtime::execute_authorized(&state, &principal, &name, body).await?;
    Ok(Json(value))
}
async fn history(
    State(state): State<AppState>,
    principal: Principal,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    store::service(&name)?;
    Ok(Json(json!({"items":crate::integration_receipts::history(&state,principal.tenant,&name).await?})))
}
async fn receipt(
    State(state): State<AppState>,
    principal: Principal,
    Path((name, id)): Path<(String, Id)>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    store::service(&name)?;
    Ok(Json(crate::integration_receipts::get(&state, principal.tenant, &name, id).await?))
}
async fn recover(
    State(state): State<AppState>,
    principal: Principal,
    Path((name, id)): Path<(String, Id)>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    store::service(&name)?;
    Ok(Json(crate::integration_receipts::recover(&state, principal.tenant, &name, id).await?))
}
#[derive(serde::Deserialize)]
struct ProbeRequest {
    configuration_version: u64,
    #[serde(default)]
    confirm_live: bool,
}
async fn probe(
    State(state): State<AppState>,
    principal: Principal,
    Path(name): Path<String>,
    ApiJson(body): ApiJson<ProbeRequest>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    let service = store::service(&name)?;
    let started_at = Timestamp::now();
    let action = match service {
        AliCloudService::Cms => "DescribeAlertHistoryList",
        AliCloudService::Apig => "ListGateways",
        AliCloudService::Mse => "ListClusters",
        AliCloudService::Privatelink => "ListVpcEndpoints",
        AliCloudService::SchedulerX3 => "ListJobs",
        AliCloudService::AgentTeams => "ListTeams",
    };
    let parameters = match service {
        AliCloudService::Cms => json!({"PageSize":1,"Page":1}),
        AliCloudService::Apig => json!({"pageSize":1,"pageNumber":1}),
        AliCloudService::Mse => json!({"PageSize":1,"PageNum":1}),
        AliCloudService::SchedulerX3 => json!({"PageSize":1,"PageNum":1}),
        _ => json!({"MaxResults":1}),
    };
    let value = cloud_runtime::execute_authorized(
        &state,
        &principal,
        &name,
        Request {
            request_id: Id::new(),
            configuration_version: body.configuration_version,
            action: action.into(),
            parameters,
            confirm_live: body.confirm_live,
        },
    )
    .await?;
    let report = json!({"version":body.configuration_version,"checked_at":Timestamp::now(),"mocked":value["mocked"],
        "status":value["status"],"action":action,"run_id":value["id"],
        "note":if value["mocked"]==true {"模拟样本检查，未验证云端网络、权限或配额"}
            else if value["status"]=="succeeded" {"实际只读接口成功；仅验证该接口权限，其他写权限与配额须按业务回执核对"}
            else {"实际只读接口失败；请查看调用回执，核对地址、凭据、实例及 RAM 权限"}});
    let published = crate::probe_publication::publish(
        &state,
        principal.tenant,
        crate::probe_publication::Publication {
            configuration_kind: store::KIND,
            report_kind: "cloud-probe",
            name: &name,
            version: body.configuration_version,
            mocked: value["mocked"] == true,
            started_at,
            report,
            outcome: if value["status"] == "succeeded" { AuditOutcome::Success } else { AuditOutcome::Failure },
        },
        AppState::audit_actor(&principal, "cloud-probe"),
    )
    .await?;
    Ok(Json(published))
}
fn actor(principal: &Principal) -> String {
    principal.subject_id.map_or_else(|| "system".into(), |id| id.to_string())
}
async fn audit(state: &AppState, principal: &Principal, name: &str, message: &str, ok: bool) -> ApiResult<()> {
    state
        .audit(
            principal.tenant,
            AuditAction::Execute,
            if ok { AuditOutcome::Success } else { AuditOutcome::Failure },
            AppState::audit_actor(principal, "cloud-operation"),
            AuditTarget::new("cloud-integration", None, Some(name.into())),
            message,
        )
        .await?;
    Ok(())
}
