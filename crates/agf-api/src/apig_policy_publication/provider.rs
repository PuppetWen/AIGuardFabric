//! The typed provider entry never records a generic cloud operation as business verification.
use super::{
    authority::Submission,
    contract::Scope,
    dependencies,
    records::{FACT, Fact, FactOutcome, Fence, Main, STATE, Status},
    util,
};
use crate::{
    cloud_runtime::{Call, Invocation, Outcome},
    cloud_store,
    state::AppState,
};
use agf_alicloud::{
    AdapterMode,
    apig::policy_driver::{
        CurrentGuard, MockBridge, MockCodec, MockScope, MockSourceGuard, Observation, PreparedUpdate, WriteOutcome,
    },
};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::Id,
    policy::Policy,
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
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
                || receipt.lease_expires_at <= Timestamp::now()
                || !main
                    .active
                    .is_some_and(|active| active.request_id == id && active.expires_at == receipt.lease_expires_at)
            {
                return Err(DomainError::Conflict("APIG当前领取或租约已失效，原编号不会重派".into()));
            }
        }
        self.submission.authorize(&self.state).await?;
        self.submission.check_budget()
    }
}

pub(super) async fn query(guard: Arc<Guard>, initialize_mock: bool) -> DomainResult<Observation> {
    guard.validate().await?;
    if initialize_mock && (!guard.scope.target.mocked || !guard.submission.write) {
        return Err(DomainError::PreconditionFailed("仅显式写权限POST可初始化所属Mock示例目标".into()));
    }
    if guard.scope.target.mocked {
        let codec = Codec(crate::model_gateway::cipher(&guard.state)?);
        let bridge = MockBridge::new(guard.state.configurations.as_ref(), &codec);
        let scope = mock_scope(&guard.scope)?;
        let source = mock_source(&guard.scope);
        if initialize_mock {
            bridge.seed_owned_fixture(&scope, source, guard.as_ref(), guard.submission.deadline).await?;
        }
        return bridge.observe_current(&scope, source, guard.as_ref(), guard.submission.deadline).await;
    }
    let result = crate::cloud_runtime::execute_apig_policy(
        &guard.state,
        Invocation {
            tenant: guard.scope.tenant,
            configuration_version: guard.scope.target.configuration_version,
            payload_fingerprint: &guard.scope.payload_fingerprint,
            guard: guard.as_ref(),
            deadline: guard.submission.deadline,
            call: Call::Observe(&guard.scope.target.binding),
        },
    )
    .await?;
    match result {
        Outcome::Observed(value) => Ok(*value),
        Outcome::Published(_) => Err(util::corrupt()),
    }
}

pub(super) async fn publish(guard: Arc<Guard>, update: &PreparedUpdate) -> DomainResult<WriteOutcome> {
    guard.validate().await?;
    if update.baseline_fingerprint().is_empty() {
        return Err(util::corrupt());
    }
    if guard.scope.target.mocked {
        let codec = Codec(crate::model_gateway::cipher(&guard.state)?);
        let bridge = MockBridge::new(guard.state.configurations.as_ref(), &codec);
        return bridge
            .publish_once(
                &mock_scope(&guard.scope)?,
                mock_source(&guard.scope),
                update,
                guard.as_ref(),
                guard.submission.deadline,
            )
            .await;
    }
    let result = crate::cloud_runtime::execute_apig_policy(
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
    match result {
        Outcome::Published(value) => Ok(value),
        Outcome::Observed(_) => Err(util::corrupt()),
    }
}

fn mock_scope(scope: &Scope) -> DomainResult<MockScope> {
    let identity =
        util::request_hash(&json!([scope.source_identity, scope.target.endpoint, scope.target.transport_mode]))?;
    MockScope::new(
        scope.tenant,
        scope.target.configuration_id,
        &scope.target.region,
        &identity,
        scope.target.binding.clone(),
        AdapterMode::Mocked,
    )
}
fn mock_source(scope: &Scope) -> MockSourceGuard<'_> {
    MockSourceGuard { version: scope.target.configuration_version, payload_fingerprint: &scope.payload_fingerprint }
}
struct Codec(FieldCipher);
impl MockCodec for Codec {
    fn seal(&self, plaintext: &str, aad: &str) -> DomainResult<SecretMaterial> {
        self.0.encrypt(&SecretString::from(plaintext.to_owned()), aad)
    }
    fn open(&self, material: &SecretMaterial, aad: &str) -> DomainResult<String> {
        if material.aad.as_deref() != Some(aad) {
            return Err(DomainError::Crypto("APIG Mock AAD mismatch".into()));
        }
        Ok(self.0.decrypt(material)?.expose_secret().to_owned())
    }
}
