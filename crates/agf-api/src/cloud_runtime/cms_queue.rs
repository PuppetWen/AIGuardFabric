//! Resolve the existing CMS service entry once and retain it through the unique typed send.
use super::{Entry, config};
use crate::{
    integration_store::{Stored, decrypt},
    state::AppState,
};
use agf_alicloud::{
    AdapterMode,
    cms::queue_delivery::{self, CurrentGuard, Outcome, Request},
    http::{ReqwestTransport, RpcClient, RpcClientConfig, SignStyle},
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::time::{Instant, timeout_at};

pub(crate) struct Invocation<'a> {
    pub(crate) tenant: TenantId,
    pub(crate) configuration_version: u64,
    pub(crate) payload_fingerprint: &'a str,
    pub(crate) guard: &'a dyn CurrentGuard,
    pub(crate) deadline: Instant,
    pub(crate) request: &'a Request,
}
pub(crate) async fn run(state: &AppState, input: Invocation<'_>) -> DomainResult<Outcome> {
    inner(state, input).await.map_err(safe_error)
}
async fn inner(state: &AppState, input: Invocation<'_>) -> DomainResult<Outcome> {
    let check = Check { state, input: &input };
    let mut entry = timeout_at(input.deadline, async {
        check.validate().await?;
        let entry = state.cloud_runtime.acquire(input.tenant, "alicloud-cms").await;
        check.validate().await?;
        Ok::<_, DomainError>(entry)
    })
    .await
    .map_err(|_| expired())??;
    if entry.version != input.configuration_version {
        *entry = Entry { version: input.configuration_version, ..Entry::default() };
    }
    if entry.retry_at.is_some_and(|at| std::time::Instant::now() < at) {
        return Err(DomainError::PreconditionFailed("CMS provider circuit is temporarily open".into()));
    }
    let client = timeout_at(input.deadline, async {
        let row = check.source().await?;
        let private = decrypt(state, input.tenant, &row)?;
        let endpoint = config::endpoint(AliCloudService::Cms, &private)?;
        state.cms_queue.mode(input.tenant, &endpoint.url("/"))?;
        let now = Timestamp::now();
        check.validate().await?;
        if entry
            .credential
            .as_ref()
            .is_none_or(|credential| credential.expires_at.is_some_and(|at| at.since_secs(&now) < 300))
        {
            entry.credential = Some(crate::cloud_credentials::resolve(input.tenant, &private).await?);
        }
        check.validate().await?;
        let credential = entry
            .credential
            .as_ref()
            .ok_or_else(|| DomainError::Config("CMS provider credential unavailable".into()))?;
        let transport = Arc::new(ReqwestTransport::new(20)?);
        RpcClient::live(
            AdapterMode::Live,
            RpcClientConfig {
                adapter: "alicloud-cms".into(),
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
    .map_err(|_| expired())??;
    // Do not outer-timeout this future: the driver classifies timeout after entering transport as Unknown.
    queue_delivery::send_once(&client, input.request, &check, input.deadline).await
}
struct Check<'a, 'b> {
    state: &'a AppState,
    input: &'a Invocation<'b>,
}
impl Check<'_, '_> {
    async fn source(&self) -> DomainResult<Stored> {
        if Instant::now() >= self.input.deadline {
            return Err(expired());
        }
        self.input.guard.validate().await?;
        let row = config::load(self.state, self.input.tenant, "alicloud-cms")
            .await?
            .filter(|row| row.enabled)
            .ok_or_else(|| DomainError::PreconditionFailed("CMS source disabled or absent".into()))?;
        if row.id != crate::integration_store::id(self.input.tenant, "alicloud-cms")
            || row.name != "alicloud-cms"
            || row.version != self.input.configuration_version
            || crate::cms_queue::source_fingerprint(&serde_json::to_value(&row)?)? != self.input.payload_fingerprint
        {
            return Err(DomainError::Conflict("CMS source changed after the original queue intent".into()));
        }
        if self.state.config.mock_mode || row.mock {
            return Err(DomainError::PreconditionFailed(
                "CMS Mock uses its explicit durable local queue bridge".into(),
            ));
        }
        self.input.guard.validate().await?;
        if Instant::now() >= self.input.deadline {
            return Err(expired());
        }
        Ok(row)
    }
}
#[async_trait]
impl CurrentGuard for Check<'_, '_> {
    async fn validate(&self) -> DomainResult<()> {
        self.source().await.map(|_| ())
    }
}
fn expired() -> DomainError {
    DomainError::Timeout("CMS original queue operation budget expired".into())
}
fn safe_error(error: DomainError) -> DomainError {
    let reason = || "CMS controlled delivery could not be prepared; inspect the safe original receipt".to_string();
    match error {
        DomainError::Validation(_) => DomainError::Validation(reason()),
        DomainError::Conflict(_) => DomainError::Conflict(reason()),
        DomainError::Unauthenticated(_) => DomainError::Unauthenticated(reason()),
        DomainError::Forbidden(_) => DomainError::Forbidden(reason()),
        DomainError::PreconditionFailed(_) => DomainError::PreconditionFailed(reason()),
        DomainError::Timeout(_) => DomainError::Timeout(reason()),
        DomainError::Crypto(_) => DomainError::Crypto(reason()),
        _ => DomainError::DependencyUnavailable { dependency: "alicloud-cms".into(), cause: reason() },
    }
}
