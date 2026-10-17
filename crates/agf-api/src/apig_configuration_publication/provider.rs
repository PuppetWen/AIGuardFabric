//! Dedicated typed driver bypasses the forbidden generic cloud write surface.
use super::{
    authority::Submission,
    contract::Scope,
    records::{FACT, Fact, FactOutcome, Main, STATE, Status},
    util,
};
use crate::{cloud_store, state::AppState};
use agf_alicloud::apig::config_driver::{CurrentGuard, Observation, Prepared, WriteOutcome};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use async_trait::async_trait;
use std::sync::Arc;
pub(super) struct Guard {
    pub state: AppState,
    pub submission: Arc<Submission>,
    pub scope: Scope,
    pub operation: Option<Id>,
}
#[async_trait]
impl CurrentGuard for Guard {
    async fn validate(&self) -> DomainResult<()> {
        self.submission.check_budget()?;
        self.submission.authorize(&self.state).await?;
        let row = cloud_store::load(&self.state, self.scope.tenant, super::NAME)
            .await?
            .filter(|row| row.enabled)
            .ok_or_else(util::stale)?;
        if super::scope::from_row(&self.state, self.scope.tenant, &row)? != self.scope {
            return Err(util::stale());
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
                || receipt.lease_expires_at <= Timestamp::now()
                || !main
                    .active
                    .is_some_and(|active| active.request_id == id && active.expires_at == receipt.lease_expires_at)
            {
                return Err(DomainError::Conflict("当前唯一领取或租约失效，原编号不会重派".into()));
            }
        }
        self.submission.authorize(&self.state).await?;
        self.submission.check_budget()
    }
}
pub(super) async fn query(guard: Arc<Guard>, initialize: bool) -> DomainResult<Observation> {
    guard.validate().await?;
    if initialize && (!guard.scope.target.mocked || !guard.submission.write) {
        return Err(DomainError::PreconditionFailed("仅显式写权限POST可以初始化所属Mock目标".into()));
    }
    if guard.scope.target.mocked {
        return super::mock::observe(&guard, initialize).await;
    }
    use crate::cloud_runtime::apig_config::{Call, Invocation, Outcome};
    let value = crate::cloud_runtime::apig_config::run(
        &guard.state,
        Invocation {
            tenant: guard.scope.tenant,
            configuration_version: guard.scope.target.configuration_version,
            payload_fingerprint: &guard.scope.payload_fingerprint,
            guard: guard.as_ref(),
            deadline: guard.submission.deadline,
            call: match &guard.scope.target.binding {
                super::contract::Binding::Content(value) => Call::ObserveContent(value),
                super::contract::Binding::Models(value) => Call::ObserveModels(value),
            },
        },
    )
    .await?;
    match value {
        Outcome::Observed(value) => Ok(*value),
        Outcome::Published(_) => Err(util::corrupt()),
    }
}
pub(super) async fn publish(guard: Arc<Guard>, update: &Prepared) -> DomainResult<WriteOutcome> {
    guard.validate().await?;
    if guard.scope.target.mocked {
        return super::mock::publish(&guard, update).await;
    }
    use crate::cloud_runtime::apig_config::{Call, Invocation, Outcome};
    let value = crate::cloud_runtime::apig_config::run(
        &guard.state,
        Invocation {
            tenant: guard.scope.tenant,
            configuration_version: guard.scope.target.configuration_version,
            payload_fingerprint: &guard.scope.payload_fingerprint,
            guard: guard.as_ref(),
            deadline: guard.submission.deadline,
            call: Call::Publish(update),
        },
    )
    .await?;
    match value {
        Outcome::Published(value) => Ok(value),
        Outcome::Observed(_) => Err(util::corrupt()),
    }
}
