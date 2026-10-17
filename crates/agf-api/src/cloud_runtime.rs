//! Tenant-scoped cloud operations: cached STS sessions, circuit breaking and durable receipts.
use crate::{
    cloud_store as config,
    integration_receipts::{self, Run},
    integration_store::{Private, decrypt},
    state::AppState,
};
use agf_alicloud::{
    AdapterMode,
    credential::CloudCredential,
    http::{ReqwestTransport, RpcClient, RpcClientConfig, SignStyle},
    openapi::{Contract, ResourceObservation, classify_resource_observation, contract, fixture},
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OwnedMutexGuard};

mod apig_barrier;
pub(crate) mod apig_config;
mod apig_policy;
mod cms_queue;
pub(crate) use cms_queue::{Invocation as CmsQueueInvocation, run as execute_cms_queue};
mod dispatch;
mod managed_operations;
pub(crate) use managed_operations::generic_operation_visible;
mod scheduler_barrier;
mod scheduler_management;
mod scheduler_observation;
pub(crate) use apig_policy::{Call, Invocation, Outcome, run as execute_apig_policy};
pub(crate) use scheduler_management::{
    Invocation as SchedulerManagementInvocation, run as execute_scheduler_management,
};
pub(crate) use scheduler_observation::{
    Invocation as SchedulerObservationInvocation, run as execute_scheduler_observation,
};

#[derive(Default)]
pub struct Registry {
    entries: Mutex<BTreeMap<(TenantId, String), Arc<Mutex<Entry>>>>,
}
#[derive(Default)]
struct Entry {
    version: u64,
    credential: Option<CloudCredential>,
    failures: u32,
    retry_at: Option<Instant>,
}
impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudRegistry").finish_non_exhaustive()
    }
}
impl Registry {
    async fn acquire(&self, tenant: TenantId, name: &str) -> OwnedMutexGuard<Entry> {
        let slot = self
            .entries
            .lock()
            .await
            .entry((tenant, name.into()))
            .or_insert_with(|| Arc::new(Mutex::new(Entry::default())))
            .clone();
        slot.lock_owned().await
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Request {
    pub request_id: Id,
    pub configuration_version: u64,
    pub action: String,
    #[serde(default)]
    pub parameters: Value,
    #[serde(default)]
    pub confirm_live: bool,
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudRequest")
            .field("request_id", &self.request_id)
            .field("action", &self.action)
            .field("configuration_version", &self.configuration_version)
            .finish_non_exhaustive()
    }
}
pub fn with_defaults(contract: &Contract, private: &Private, input: &Value) -> DomainResult<Value> {
    let mut values = if input.is_null() { json!({}) } else { input.clone() };
    let fields = values.as_object_mut().ok_or_else(|| DomainError::Validation("云参数必须是 JSON 对象".into()))?;
    for (api_key, setting) in [
        ("InstanceId", "instance_id"),
        ("ClusterId", "cluster_id"),
        ("AppName", "app_name"),
        ("NamespaceId", "namespace_id"),
        ("RegionId", "region_id"),
        ("GroupId", "group_id"),
    ] {
        if contract.parameters.iter().any(|parameter| parameter.name == api_key) && !fields.contains_key(api_key) {
            if api_key == "RegionId" {
                fields.insert(api_key.into(), json!(config::setting(private, "region_id", "cn-hangzhou")));
                continue;
            }
            if let Some(value) =
                private.settings.get(setting).filter(|value| value.as_str().is_some_and(|text| !text.is_empty()))
            {
                fields.insert(api_key.into(), value.clone());
            }
        }
    }
    contract.validate(&values)?;
    Ok(values)
}
pub async fn execute(
    state: &AppState,
    tenant: TenantId,
    name: &str,
    actor: String,
    body: Request,
) -> DomainResult<Value> {
    execute_inner(state, tenant, name, actor, body, Policy::default()).await
}

/// HTTP operations recheck the authenticated identity after asynchronous waits.
pub(crate) async fn execute_authorized(
    state: &AppState,
    principal: &crate::Principal,
    name: &str,
    body: Request,
) -> DomainResult<Value> {
    execute_inner(
        state,
        principal.tenant,
        name,
        principal.display(),
        body,
        Policy { principal: Some(principal), ..Policy::default() },
    )
    .await
}

/// Native Team preparation is explicitly authorized to read and write the cloud connection.
pub(crate) async fn execute_read_authorized(
    state: &AppState,
    principal: &crate::Principal,
    name: &str,
    body: Request,
) -> DomainResult<Value> {
    execute_inner(
        state,
        principal.tenant,
        name,
        principal.display(),
        body,
        Policy { principal: Some(principal), require_read: true, ..Policy::default() },
    )
    .await
}

#[derive(Default)]
struct Policy<'a> {
    business: Option<&'a dyn WritePrecondition>,
    principal: Option<&'a crate::Principal>,
    resource_observation: bool,
    require_read: bool,
}
/// Revalidate durable operation state after queue and credential waits, before dispatch.
#[async_trait::async_trait]
pub(crate) trait WritePrecondition: Send + Sync {
    async fn validate(&self) -> DomainResult<()>;

    /// Live reads share the resolved client and service lock; never re-enter this runtime.
    /// Mock implementations read their local persistent state with no network client.
    async fn preflight(&self, _client: Option<&RpcClient>) -> DomainResult<()> {
        Ok(())
    }
}

pub(crate) async fn execute_guarded_authorized(
    state: &AppState,
    principal: &crate::Principal,
    name: &str,
    body: Request,
    guard: &dyn WritePrecondition,
) -> DomainResult<Value> {
    execute_inner(
        state,
        principal.tenant,
        name,
        principal.display(),
        body,
        Policy { business: Some(guard), principal: Some(principal), ..Policy::default() },
    )
    .await
}

pub(crate) async fn execute_resource_observation(
    state: &AppState,
    principal: &crate::Principal,
    name: &str,
    body: Request,
) -> DomainResult<Value> {
    if name != crate::cloud_inventory::NAME || !matches!(body.action.as_str(), "GetTeam" | "GetUser") {
        return Err(DomainError::Validation("资源存在性观察仅支持 AgentTeams GetTeam/GetUser".into()));
    }
    execute_inner(
        state,
        principal.tenant,
        name,
        principal.display(),
        body,
        Policy { resource_observation: true, principal: Some(principal), require_read: true, ..Policy::default() },
    )
    .await
}
async fn execute_inner(
    state: &AppState,
    tenant: TenantId,
    name: &str,
    actor: String,
    body: Request,
    policy: Policy<'_>,
) -> DomainResult<Value> {
    let issued_at = Timestamp::now();
    let resource_observation = policy.resource_observation;
    let service = config::service(name)?;
    let operation = contract(service, &body.action)?;
    apig_barrier::validate(service, operation.read_only)?;
    scheduler_barrier::validate(service, &body.action)?;
    managed_operations::validate_privatelink(service, &body.action)?;
    if service == AliCloudService::SchedulerX3 && body.action == "GetApp" {
        return Err(DomainError::PreconditionFailed(
            "Scheduler 应用观察必须使用专用脱敏入口；原始 GetApp 响应包含执行凭据".into(),
        ));
    }
    if service == AliCloudService::AgentTeams
        && matches!(body.action.as_str(), "CreateTeam" | "UpdateTeam" | "DeleteTeam")
        && policy.business.is_none()
    {
        return Err(DomainError::PreconditionFailed(
            "团队变更必须从团队维护入口生成预览并确认；不能通过原始云操作绕过一次性确认和删除恢复".into(),
        ));
    }
    if service == AliCloudService::Apig && body.action == "UpdatePolicy" && policy.business.is_none() {
        return Err(DomainError::PreconditionFailed(
            "独立网关策略更新须使用可信观察、预览和永久领取的专用发布入口".into(),
        ));
    }
    let row = config::load(state, tenant, name)
        .await?
        .filter(|row| row.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("请先保存并启用云集成".into()))?;
    if row.version != body.configuration_version {
        return Err(DomainError::Conflict("云配置已改变，请重新加载后确认".into()));
    }
    let mocked = state.config.mock_mode || row.mock;
    if !mocked && !body.confirm_live {
        return Err(DomainError::PreconditionFailed("真实云调用需要 confirm_live=true".into()));
    }
    let private = decrypt(state, tenant, &row)?;
    let input = with_defaults(&operation, &private, &body.parameters)?;
    let hash_input = if resource_observation {
        serde_json::to_vec(&json!({"resourceObservation":true,"request":&body}))?
    } else {
        serde_json::to_vec(&body)?
    };
    let request_hash = format!("{:x}", Sha256::digest(hash_input));
    let id = deterministic_id("agf.integration.run", &format!("{tenant}:{name}:{}", body.request_id));
    let run = Run {
        id,
        request_id: body.request_id,
        adapter: name.into(),
        operation: body.action.clone(),
        configuration_version: row.version,
        request_hash,
        actor,
        started_at: Timestamp::now(),
        finished_at: None,
        status: "started".into(),
        mocked,
        result: None,
    };
    let can_write = !operation.read_only;
    let guard = dispatch::Guard {
        state,
        tenant,
        name,
        version: row.version,
        mocked,
        principal: policy.principal,
        business: policy.business,
        issued_at,
        require_read: policy.require_read,
    };
    let audit_actor = policy.principal.map_or_else(
        || integration_receipts::internal_actor("cloud-runtime"),
        |principal| AppState::audit_actor(principal, "cloud-operation"),
    );
    Box::pin(integration_receipts::execute_audited(
        state,
        tenant,
        run,
        &private.secrets,
        can_write,
        audit_actor,
        async {
            if mocked {
                guard.validate().await?;
                guard.preflight(None).await?;
                guard.validate().await?;
                let response = fixture(service, &body.action)?;
                let response = if service == AliCloudService::AgentTeams {
                    let response =
                        crate::worker_quota::mock::response(state, tenant, &row, &body.action, &input, response)
                            .await?;
                    crate::team_management::mock::response(state, tenant, &row, &body.action, &input, response).await?
                } else if service == AliCloudService::Privatelink && policy.business.is_some() {
                    crate::privatelink_inventory::mock::response(state, tenant, &row, &body.action, &input, response)
                        .await?
                } else {
                    response
                };
                let status = response.get("HttpStatusCode").and_then(Value::as_u64).unwrap_or(200);
                let status = u16::try_from(status).map_err(|_| DomainError::Parse("模拟响应状态无效".into()))?;
                let response = agf_alicloud::http::RpcResponse { status, body: response, raw: String::new() };
                let mut result = if resource_observation {
                    observation_value(classify_resource_observation(&operation, response)?)
                } else {
                    agf_alicloud::http::check_response(&response)?;
                    json!({"response":response.body})
                };
                result["mocked"] = json!(true);
                result["source"] = json!(if service == AliCloudService::AgentTeams
                    && crate::team_management::mock::supports(&body.action)
                {
                    "local-mock-state"
                } else if service == AliCloudService::Privatelink
                    && policy.business.is_some()
                    && crate::privatelink_inventory::mock::supports(&body.action)
                {
                    "local-selected-endpoint-example-fixture"
                } else {
                    "public-api-example-fixture"
                });
                return Ok(result);
            }
            let mut entry = state.cloud_runtime.acquire(tenant, name).await;
            if entry.version != row.version {
                *entry = Entry { version: row.version, ..Entry::default() };
            }
            if entry.retry_at.is_some_and(|at| Instant::now() < at) {
                return Err(DomainError::PreconditionFailed(
                    "云服务连续失败，熔断 30 秒；请检查凭据、网络和回执".into(),
                ));
            }
            let mut local_rejection = false;
            let dispatch = DispatchGuard { check: &guard, rejected: &mut local_rejection, resource_observation };
            let result = invoke(&mut entry, tenant, service, &private, &operation, &input, dispatch).await;
            match &result {
                Ok(_) => {
                    entry.failures = 0;
                    entry.retry_at = None;
                }
                Err(_) if local_rejection => {}
                Err(_) => {
                    entry.failures = entry.failures.saturating_add(1);
                    if entry.failures >= 3 {
                        entry.retry_at = Some(Instant::now() + Duration::from_secs(30));
                    }
                }
            }
            result.map(|mut response| {
                response["mocked"] = json!(false);
                response
            })
        },
    ))
    .await
}
struct DispatchGuard<'a> {
    check: &'a dyn WritePrecondition,
    rejected: &'a mut bool,
    resource_observation: bool,
}
async fn invoke(
    entry: &mut Entry,
    tenant: TenantId,
    service: AliCloudService,
    private: &Private,
    operation: &Contract,
    input: &Value,
    guard: DispatchGuard<'_>,
) -> DomainResult<Value> {
    // Reject stale queued work before resolving or sending any old credentials to STS.
    if let Err(error) = guard.check.validate().await {
        *guard.rejected = true;
        return Err(error);
    }
    let now = Timestamp::now();
    if entry
        .credential
        .as_ref()
        .is_none_or(|credential| credential.expires_at.is_some_and(|expires| expires.since_secs(&now) < 300))
    {
        entry.credential = Some(crate::cloud_credentials::resolve(tenant, private).await?);
    }
    let credential = entry.credential.as_ref().ok_or_else(|| DomainError::Config("云凭据未就绪".into()))?.clone();
    let endpoint = config::endpoint(service, private)?;
    let transport = Arc::new(ReqwestTransport::new(20)?);
    let client = RpcClient::live(
        AdapterMode::Live,
        RpcClientConfig {
            adapter: service.as_str().into(),
            region: endpoint.region.clone(),
            account_id: config::setting(private, "account_id", "").into(),
            style: SignStyle::V3,
            timeout_secs: 20,
        },
        Some(credential.clone()),
        endpoint,
        transport.clone(),
    )?
    .with_async_transport(transport);
    let outcome = async {
        let checked = async {
            guard.check.validate().await?;
            guard.check.preflight(Some(&client)).await?;
            guard.check.validate().await
        }
        .await;
        if let Err(error) = checked {
            *guard.rejected = true;
            return Err(error);
        }
        if guard.resource_observation {
            operation.observe_resource(&client, input).await.map(observation_value)
        } else {
            operation.call(&client, input).await.map(|response| json!({"response":response.body}))
        }
    }
    .await;
    let sensitive = [credential.access_key_secret.as_str(), credential.security_token.as_deref().unwrap_or("")];
    match outcome {
        Ok(response) => {
            let mut response = response;
            let secrets = sensitive.iter().enumerate().map(|(i, value)| (i.to_string(), value.to_string())).collect();
            integration_receipts::redact(&mut response, &secrets);
            Ok(response)
        }
        Err(error) => {
            let clean = |mut value: String| {
                for secret in sensitive.iter().filter(|v| !v.is_empty()) {
                    value = value.replace(secret, "[REDACTED]");
                }
                value
            };
            Err(match error {
                DomainError::Forbidden(value) => DomainError::Forbidden(clean(value)),
                DomainError::Validation(value) => DomainError::Validation(clean(value)),
                DomainError::Parse(value) => DomainError::Parse(clean(value)),
                DomainError::Timeout(value) => DomainError::Timeout(clean(value)),
                DomainError::Conflict(value) => DomainError::Conflict(clean(value)),
                DomainError::PreconditionFailed(value) => DomainError::PreconditionFailed(clean(value)),
                DomainError::DependencyUnavailable { dependency, cause } => {
                    DomainError::DependencyUnavailable { dependency, cause: clean(cause) }
                }
                other => other,
            })
        }
    }
}

fn observation_value(observation: ResourceObservation) -> Value {
    match observation {
        ResourceObservation::Present(response) => json!({"resourceState":"present","response":response.body}),
        ResourceObservation::Absent { http_status, provider_code, provider_request_id } => json!({
            "resourceState":"absent","evidence":{"httpStatus":http_status,
                "providerCode":provider_code,"providerRequestId":provider_request_id}
        }),
    }
}

mod privatelink_provisioning;
pub(crate) use privatelink_provisioning::{
    Call as PrivateLinkProvisioningCall, Invocation as PrivateLinkProvisioningInvocation,
    Outcome as PrivateLinkProvisioningOutcome, run as execute_privatelink_provisioning,
};
