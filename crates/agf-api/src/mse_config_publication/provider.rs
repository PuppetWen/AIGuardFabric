//! Only this adapter can call the pinned Nacos driver; GET state never calls it.
use super::{
    authority::Submission,
    contract::Scope,
    dependencies, mock,
    records::{FACT, Fact, FactOutcome, Fence, Main, STATE, Status},
    util,
};
use crate::{cloud_store, integration_store, state::AppState};
use agf_alicloud::{
    credential::CloudCredential,
    mse::config_cas::{
        ConfigKey, ConfigObservation, Limits, NacosConfigClient, NacosCredentialProvider, NacosSendGuard,
        PublishOutcome,
    },
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    policy::Policy,
    time::Timestamp,
};
use async_trait::async_trait;
use std::sync::Arc;

pub(super) struct Guard {
    pub state: AppState,
    pub submission: Arc<Submission>,
    pub scope: Scope,
    pub fence: Option<Fence>,
    pub source: Vec<Policy>,
    pub operation: Option<Id>,
}
#[async_trait]
impl NacosSendGuard for Guard {
    async fn validate(&self) -> DomainResult<()> {
        self.submission.check_budget()?;
        self.submission.authorize(&self.state).await?;
        let cloud = cloud_store::load(&self.state, self.scope.tenant, super::NAME)
            .await?
            .filter(|row| row.enabled)
            .ok_or_else(util::stale)?;
        if super::scope::from_row(&self.state, self.scope.tenant, &cloud, &self.state.mse_config_publication)?
            != self.scope
        {
            return Err(util::stale());
        }
        if let Some(fence) = &self.fence {
            let (_, current) = dependencies::prepare(&self.state, &self.scope, &fence.policies, &self.source).await?;
            if current.dependencies != fence.dependencies {
                return Err(util::stale());
            }
        }
        if let Some(id) = self.operation {
            let main: Main = self
                .state
                .configurations
                .get(self.scope.tenant, STATE, util::main_id(self.scope.tenant))
                .await?
                .ok_or_else(util::stale)?;
            let fact: Fact = self
                .state
                .configurations
                .get(self.scope.tenant, FACT, util::fact_id(self.scope.tenant, id))
                .await?
                .ok_or_else(util::stale)?;
            let FactOutcome::Operation { receipt } = fact.outcome else {
                return Err(util::corrupt());
            };
            if fact.scope != self.scope
                || receipt.status != Status::Started
                || Timestamp::now() >= receipt.lease_expires_at
                || !main
                    .active
                    .is_some_and(|active| active.request_id == id && active.expires_at == receipt.lease_expires_at)
            {
                return Err(DomainError::Conflict(
                    "发送前领取或租约已失效；原编号不会重派，请仅观察或恢复本地回执".into(),
                ));
            }
        }
        self.submission.authorize(&self.state).await?;
        self.submission.check_budget()?;
        Ok(())
    }
}

struct Credentials {
    state: AppState,
    guard: Arc<Guard>,
}
#[async_trait]
impl NacosCredentialProvider for Credentials {
    async fn credentials(&self) -> DomainResult<CloudCredential> {
        self.guard.validate().await?;
        let tenant = self.guard.scope.tenant;
        let row = cloud_store::load(&self.state, tenant, super::NAME).await?.ok_or_else(util::stale)?;
        if super::scope::from_row(&self.state, tenant, &row, &self.state.mse_config_publication)? != self.guard.scope {
            return Err(util::stale());
        }
        let private = integration_store::decrypt(&self.state, tenant, &row)?;
        crate::cloud_credentials::resolve(tenant, &private).await
    }
}

pub(super) async fn query(guard: Arc<Guard>) -> DomainResult<ConfigObservation> {
    guard.validate().await?;
    if guard.scope.target.mocked {
        let observation = mock::query(&guard.state, &guard.scope).await?;
        guard.validate().await?;
        return Ok(observation);
    }
    let client = client(&guard)?;
    let observation = Box::pin(client.query(&key(&guard.scope), guard.as_ref())).await?;
    guard.validate().await?;
    Ok(observation)
}

pub(super) async fn publish(guard: Arc<Guard>, md5: &str, desired: &str) -> DomainResult<PublishOutcome> {
    guard.validate().await?;
    if guard.scope.target.mocked {
        // Mock has its own provider transaction. A later workflow rollback cannot undo it.
        return mock::publish(&guard.state, &guard.scope, md5, desired).await;
    }
    Box::pin(client(&guard)?.publish(&key(&guard.scope), md5, desired, guard.as_ref())).await
}

fn client(guard: &Arc<Guard>) -> DomainResult<NacosConfigClient> {
    let (endpoint, mode) =
        guard.state.mse_config_publication.endpoint(guard.scope.tenant, &guard.scope.target.engine_origin)?;
    if mode != guard.scope.target.transport_mode {
        return Err(util::stale());
    }
    NacosConfigClient::new(
        endpoint,
        Arc::new(Credentials { state: guard.state.clone(), guard: guard.clone() }),
        Limits::default(),
    )
}
fn key(scope: &Scope) -> ConfigKey {
    ConfigKey {
        namespace_id: scope.target.namespace_id.clone(),
        group: scope.target.group.clone(),
        data_id: scope.target.data_id.clone(),
    }
}
