//! Typed Scheduler reads share the existing service mutex and credential lifecycle.
use super::{Entry, config};
use crate::{
    integration_store::{Stored, decrypt},
    state::AppState,
};
use agf_alicloud::{
    AdapterMode,
    http::{ReqwestTransport, RpcClient, RpcClientConfig, SignStyle},
    schedulerx3::native_observation::{self as driver, CurrentGuard, Observation, Scope},
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};
use async_trait::async_trait;
use std::{fmt, sync::Arc};
use tokio::time::{Instant, timeout_at};

const NAME: &str = "alicloud-schedulerx3";

pub(crate) struct Invocation<'a> {
    pub(crate) tenant: TenantId,
    pub(crate) configuration_version: u64,
    pub(crate) payload_fingerprint: &'a str,
    pub(crate) scope: &'a Scope,
    pub(crate) guard: &'a dyn CurrentGuard,
    pub(crate) deadline: Instant,
}

impl fmt::Debug for Invocation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchedulerObservationInvocation")
            .field("tenant", &self.tenant)
            .field("configuration_version", &self.configuration_version)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// No generic receipt or raw GetApp response is created. Mock uses its separate local bridge.
pub(crate) async fn run(state: &AppState, input: Invocation<'_>) -> DomainResult<Observation> {
    run_inner(state, input).await.map_err(safe_error)
}

async fn run_inner(state: &AppState, input: Invocation<'_>) -> DomainResult<Observation> {
    input.scope.validate()?;
    if input.tenant.as_uuid().is_nil()
        || input.configuration_version == 0
        || input.payload_fingerprint.len() != 64
        || !input.payload_fingerprint.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DomainError::Validation("Invalid trusted Scheduler invocation".into()));
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
    .map_err(|_| DomainError::Timeout("Scheduler service queue deadline expired".into()))??;
    if entry.version != input.configuration_version {
        *entry = Entry { version: input.configuration_version, ..Entry::default() };
    }
    if entry.retry_at.is_some_and(|at| std::time::Instant::now() < at) {
        return Err(DomainError::PreconditionFailed("Scheduler service circuit is temporarily open".into()));
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
        let credential =
            entry.credential.as_ref().ok_or_else(|| DomainError::Config("Scheduler credentials missing".into()))?;
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
    .map_err(|_| DomainError::Timeout("Scheduler credential preparation deadline expired".into()))??;
    check_deadline(input.deadline)?;
    // The entry remains held through GetApp, every ListJobs page and final fresh authority check.
    driver::observe_current(&client, input.scope, &check, input.deadline).await
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
        check_deadline(self.deadline)?;
        self.business.validate().await?;
        let row = config::load(self.state, self.tenant, NAME)
            .await?
            .filter(|row| row.enabled)
            .ok_or_else(|| DomainError::PreconditionFailed("Scheduler source is disabled or missing".into()))?;
        if row.id != crate::integration_store::id(self.tenant, NAME)
            || row.name != NAME
            || row.version != self.version
            || crate::scheduler_native_observation::source_fingerprint(&serde_json::to_value(&row)?)?
                != self.fingerprint
        {
            return Err(DomainError::Conflict("Scheduler source changed since submission".into()));
        }
        if self.state.config.mock_mode || row.mock {
            return Err(DomainError::PreconditionFailed("Mock observations use their local provider bridge".into()));
        }
        let private = decrypt(self.state, self.tenant, &row)?;
        if private.settings.get("cluster_id").and_then(serde_json::Value::as_str)
            != Some(self.scope.cluster_id.as_str())
            || private.settings.get("app_name").and_then(serde_json::Value::as_str)
                != Some(self.scope.app_name.as_str())
            || private.settings.get("region_id").and_then(serde_json::Value::as_str).is_none_or(str::is_empty)
        {
            return Err(DomainError::Conflict("Scheduler configured scope differs from submission".into()));
        }
        self.business.validate().await?;
        check_deadline(self.deadline)?;
        Ok(row)
    }
}

#[async_trait]
impl CurrentGuard for SourceCheck<'_> {
    async fn validate(&self) -> DomainResult<()> {
        self.source().await.map(|_| ())
    }
}

fn check_deadline(deadline: Instant) -> DomainResult<()> {
    if Instant::now() >= deadline {
        Err(DomainError::Timeout("Scheduler original submission deadline expired".into()))
    } else {
        Ok(())
    }
}

// Provider and STS error text must not escape the typed observation boundary.
fn safe_error(error: DomainError) -> DomainError {
    let reason =
        || "Scheduler controlled observation could not be completed; inspect its safe local receipt".to_string();
    match error {
        DomainError::Validation(_) => DomainError::Validation(reason()),
        DomainError::NotFound { entity, .. } => DomainError::NotFound { entity, id: reason() },
        DomainError::Conflict(_) => DomainError::Conflict(reason()),
        DomainError::Unauthenticated(_) => DomainError::Unauthenticated(reason()),
        DomainError::Forbidden(_) => DomainError::Forbidden(reason()),
        DomainError::TenantViolation { .. } => DomainError::TenantViolation { tenant: reason(), resource: reason() },
        DomainError::QuotaExceeded { used, limit, .. } => {
            DomainError::QuotaExceeded { scope: reason(), dimension: reason(), used, limit }
        }
        DomainError::RateLimited(_) => DomainError::RateLimited(reason()),
        DomainError::PreconditionFailed(_) => DomainError::PreconditionFailed(reason()),
        DomainError::DependencyUnavailable { .. } => {
            DomainError::DependencyUnavailable { dependency: NAME.into(), cause: reason() }
        }
        DomainError::Timeout(_) => DomainError::Timeout(reason()),
        DomainError::PolicyDenied { .. } => {
            DomainError::PolicyDenied { policy: reason(), action: reason(), reason: reason() }
        }
        DomainError::Config(_) => DomainError::Config(reason()),
        DomainError::Parse(_) => DomainError::Parse(reason()),
        DomainError::Crypto(_) => DomainError::Crypto(reason()),
        DomainError::NotImplemented(_) => DomainError::NotImplemented(reason()),
        DomainError::Internal(_) => DomainError::Internal(reason()),
    }
}
