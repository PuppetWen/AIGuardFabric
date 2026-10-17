//! One reviewed Scheduler action under the existing source mutex; no raw receipt is exported.
use super::{Entry, config};
use crate::{
    integration_store::{Stored, decrypt},
    state::AppState,
};
use agf_alicloud::{
    AdapterMode,
    http::{ReqwestTransport, RpcClient, RpcClientConfig, SignStyle},
    schedulerx3::{
        managed_jobs::{self, Change, Selection, WriteEvidence},
        native_observation::{self, CurrentGuard, Scope},
    },
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};
use std::sync::Arc;
use tokio::time::{Instant, timeout_at};

const NAME: &str = "alicloud-schedulerx3";
pub(crate) struct Invocation<'a> {
    pub(crate) tenant: TenantId,
    pub(crate) configuration_version: u64,
    pub(crate) payload_fingerprint: &'a str,
    pub(crate) scope: &'a Scope,
    pub(crate) selection: &'a Selection,
    pub(crate) change: &'a Change,
    pub(crate) guard: &'a dyn CurrentGuard,
    pub(crate) deadline: Instant,
}
pub(crate) async fn run(state: &AppState, input: Invocation<'_>) -> DomainResult<WriteEvidence> {
    run_inner(state, input).await.map_err(safe_error)
}
async fn run_inner(state: &AppState, input: Invocation<'_>) -> DomainResult<WriteEvidence> {
    input.scope.validate()?;
    if input.tenant.as_uuid().is_nil()
        || input.configuration_version == 0
        || input.payload_fingerprint.len() != 64
        || !input.payload_fingerprint.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(DomainError::Validation("受管 Scheduler 调用身份无效".into()));
    }
    let check = SourceCheck {
        state,
        tenant: input.tenant,
        version: input.configuration_version,
        fingerprint: input.payload_fingerprint,
        scope: input.scope,
        business: input.guard,
        deadline: input.deadline,
    };
    let mut entry = timeout_at(input.deadline, async {
        check.validate().await?;
        let entry = state.cloud_runtime.acquire(input.tenant, NAME).await;
        check.validate().await?;
        Ok::<_, DomainError>(entry)
    })
    .await
    .map_err(|_| deadline_error())??;
    if entry.version != input.configuration_version {
        *entry = Entry { version: input.configuration_version, ..Entry::default() };
    }
    if entry.retry_at.is_some_and(|at| std::time::Instant::now() < at) {
        return Err(DomainError::PreconditionFailed("Scheduler 服务断路器暂时开启".into()));
    }
    let client = timeout_at(input.deadline, async {
        let row = check.source().await?;
        let private = decrypt(state, input.tenant, &row)?;
        let endpoint = config::endpoint(AliCloudService::SchedulerX3, &private)?;
        check.validate().await?;
        let now = Timestamp::now();
        if entry
            .credential
            .as_ref()
            .is_none_or(|credential| credential.expires_at.is_some_and(|expires| expires.since_secs(&now) < 300))
        {
            entry.credential = Some(crate::cloud_credentials::resolve(input.tenant, &private).await?);
        }
        check.validate().await?;
        let credential = entry.credential.as_ref().ok_or_else(|| DomainError::Config("Scheduler 凭据缺失".into()))?;
        let transport = Arc::new(ReqwestTransport::new(20)?);
        RpcClient::live(
            AdapterMode::Live,
            RpcClientConfig {
                adapter: NAME.into(),
                region: endpoint.region.clone(),
                account_id: config::setting(&private, "account_id", "").into(),
                style: SignStyle::V3,
                timeout_secs: 20,
            },
            Some(credential.clone()),
            endpoint,
            transport.clone(),
        )
        .map(|client| client.with_async_transport(transport))
    })
    .await
    .map_err(|_| deadline_error())??;
    // The typed complete traversal fences the review before the one-action driver repeats its preflight.
    let observed = native_observation::observe_current(&client, input.scope, &check, input.deadline).await?;
    let plan = managed_jobs::prepare(&observed, input.selection, input.change)?;
    managed_jobs::dispatch_once(&client, &plan, &check, input.deadline).await
}
struct SourceCheck<'a> {
    state: &'a AppState,
    tenant: TenantId,
    version: u64,
    fingerprint: &'a str,
    scope: &'a Scope,
    business: &'a dyn CurrentGuard,
    deadline: Instant,
}
impl SourceCheck<'_> {
    async fn source(&self) -> DomainResult<Stored> {
        deadline(self.deadline)?;
        self.business.validate().await?;
        let row = config::load(self.state, self.tenant, NAME)
            .await?
            .filter(|row| row.enabled)
            .ok_or_else(|| DomainError::PreconditionFailed("Scheduler 来源缺失或停用".into()))?;
        if row.id != crate::integration_store::id(self.tenant, NAME)
            || row.name != NAME
            || row.version != self.version
            || crate::scheduler_native_observation::source_fingerprint(&serde_json::to_value(&row)?)?
                != self.fingerprint
        {
            return Err(DomainError::Conflict("原 Scheduler 来源已变化".into()));
        }
        if self.state.config.mock_mode || row.mock {
            return Err(DomainError::PreconditionFailed("Mock 只能使用本地持久桥".into()));
        }
        let private = decrypt(self.state, self.tenant, &row)?;
        if private.settings.get("cluster_id").and_then(serde_json::Value::as_str)
            != Some(self.scope.cluster_id.as_str())
            || private.settings.get("app_name").and_then(serde_json::Value::as_str)
                != Some(self.scope.app_name.as_str())
            || private.settings.get("region_id").and_then(serde_json::Value::as_str).is_none_or(str::is_empty)
        {
            return Err(DomainError::Conflict("Scheduler 目标与提交来源不一致".into()));
        }
        self.business.validate().await?;
        deadline(self.deadline)?;
        Ok(row)
    }
}
#[async_trait::async_trait]
impl CurrentGuard for SourceCheck<'_> {
    async fn validate(&self) -> DomainResult<()> {
        self.source().await.map(|_| ())
    }
}
fn deadline(at: Instant) -> DomainResult<()> {
    if Instant::now() >= at { Err(deadline_error()) } else { Ok(()) }
}
fn deadline_error() -> DomainError {
    DomainError::Timeout("原 Scheduler 受管提交预算已过期；不会重派".into())
}
fn safe_error(error: DomainError) -> DomainError {
    let fixed = || "Scheduler 受管操作未获得完整结果；请读取原本地回执，不重发原动作".to_owned();
    match error {
        DomainError::Validation(_) => DomainError::Validation(fixed()),
        DomainError::Conflict(_) => DomainError::Conflict(fixed()),
        DomainError::Unauthenticated(_) => DomainError::Unauthenticated(fixed()),
        DomainError::Forbidden(_) => DomainError::Forbidden(fixed()),
        DomainError::PreconditionFailed(_) => DomainError::PreconditionFailed(fixed()),
        DomainError::Timeout(_) => DomainError::Timeout(fixed()),
        _ => DomainError::DependencyUnavailable { dependency: NAME.into(), cause: fixed() },
    }
}
