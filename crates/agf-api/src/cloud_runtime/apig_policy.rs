//! APIG typed calls hold the existing tenant/service entry through credential resolution and driver completion.
use super::{Entry, config};
use crate::{
    integration_store::{Stored, decrypt},
    state::AppState,
};
use agf_alicloud::{
    AdapterMode,
    apig::policy_driver::{self, Binding, CurrentGuard, MockBridge, Observation, PreparedUpdate, WriteOutcome},
    http::{ReqwestTransport, RpcClient, RpcClientConfig, SignStyle},
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

const NAME: &str = "alicloud-apig";

#[derive(Debug, Clone, Copy)]
pub(crate) enum Call<'a> {
    Observe(&'a Binding),
    Publish(&'a PreparedUpdate),
}

#[derive(Debug)]
pub(crate) enum Outcome {
    Observed(Box<Observation>),
    Published(WriteOutcome),
}

pub(crate) struct Invocation<'a> {
    pub(crate) tenant: TenantId,
    pub(crate) configuration_version: u64,
    pub(crate) payload_fingerprint: &'a str,
    pub(crate) guard: &'a dyn CurrentGuard,
    pub(crate) deadline: Instant,
    pub(crate) call: Call<'a>,
}

impl fmt::Debug for Invocation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApigInvocation")
            .field("tenant", &self.tenant)
            .field("configuration_version", &self.configuration_version)
            .field("deadline", &self.deadline)
            .field("call", &self.call)
            .finish_non_exhaustive()
    }
}

/// Use one resolved live client and the existing service mutex for the complete typed call.
///
/// The owning workflow provides fresh original-submission authority and permanent claims.
/// No generic operation receipt, endpoint override, implicit Mock seed or recursive runtime call occurs.
pub(crate) async fn run(state: &AppState, input: Invocation<'_>) -> DomainResult<Outcome> {
    run_inner(state, input).await.map_err(safe_error)
}

async fn run_inner(state: &AppState, input: Invocation<'_>) -> DomainResult<Outcome> {
    if input.tenant.as_uuid().is_nil()
        || input.configuration_version == 0
        || input.payload_fingerprint.len() != 64
        || !input.payload_fingerprint.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DomainError::Validation("Invalid trusted APIG invocation".into()));
    }
    let check = SourceCheck {
        state,
        tenant: input.tenant,
        version: input.configuration_version,
        fingerprint: input.payload_fingerprint,
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
    .map_err(|_| DomainError::Timeout("APIG service queue deadline expired".into()))??;
    if entry.version != input.configuration_version {
        *entry = Entry { version: input.configuration_version, ..Entry::default() };
    }
    if entry.retry_at.is_some_and(|at| std::time::Instant::now() < at) {
        return Err(DomainError::PreconditionFailed("APIG service circuit is temporarily open".into()));
    }
    let client = timeout_at(input.deadline, async {
        let row = check.source().await?;
        let private = decrypt(state, input.tenant, &row)?;
        let endpoint = config::endpoint(AliCloudService::Apig, &private)?;
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
            entry.credential.as_ref().ok_or_else(|| DomainError::Config("APIG credentials missing".into()))?;
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
    .map_err(|_| DomainError::Timeout("APIG credential preparation deadline expired".into()))??;
    check_deadline(input.deadline)?;
    // Do not wrap publication in another timeout: after its unique PUT starts the driver returns Unknown.
    // Keeping entry in this scope serializes all three reads, preflight and the provider acknowledgement.
    match input.call {
        Call::Observe(binding) => policy_driver::observe_current(&client, binding, &check, input.deadline)
            .await
            .map(|observation| Outcome::Observed(Box::new(observation))),
        Call::Publish(update) => {
            policy_driver::publish_once(&client, update, &check, input.deadline).await.map(Outcome::Published)
        }
    }
}

struct SourceCheck<'a> {
    state: &'a AppState,
    tenant: TenantId,
    version: u64,
    fingerprint: &'a str,
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
            .ok_or_else(|| DomainError::PreconditionFailed("APIG source is disabled or missing".into()))?;
        if row.id != crate::integration_store::id(self.tenant, NAME)
            || row.name != NAME
            || row.version != self.version
            || MockBridge::source_fingerprint(&serde_json::to_value(&row)?) != self.fingerprint
        {
            return Err(DomainError::Conflict("APIG source changed since submission".into()));
        }
        if self.state.config.mock_mode || row.mock {
            return Err(DomainError::PreconditionFailed(
                "Persistent Mock calls use their local provider bridge".into(),
            ));
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
        Err(DomainError::Timeout("APIG original submission deadline expired".into()))
    } else {
        Ok(())
    }
}

// Replace every error text field, including provider/STS causes, while retaining its domain category.
fn safe_error(error: DomainError) -> DomainError {
    let reason = || "APIG controlled call could not be completed; inspect its safe operation receipt".to_string();
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
