use super::{CurrentGuard, MockScope, MockState, json, mock_scope::check_hash, observe::evidence};
use crate::http::RpcResponse;
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use agf_storage::{
    configuration::{ConditionalMutation, ConfigStore, ConfigurationGuard, MutationDecision},
    crypto::FieldCipher,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use tokio::time::{Instant, timeout_at};

pub(super) const KIND: &str = "apig-policy-driver-mock";
const MAX_STATE_BYTES: usize = 512 * 1024;
const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// Trusted AEAD adapter, implemented by the owning API with its existing FieldCipher.
/// Implementations must authenticate the supplied AAD and never log returned plaintext.
pub trait MockCodec: Send + Sync {
    /// Encrypt using the exact tenant/record/kind AAD supplied by this bridge.
    ///
    /// # Errors
    /// Key access or authenticated encryption fails.
    fn seal(&self, plaintext: &str, aad: &str) -> DomainResult<SecretMaterial>;

    /// Authenticate the exact AAD and decrypt; no plaintext is accepted on authentication failure.
    ///
    /// # Errors
    /// Key, tenant/record/kind AAD, ciphertext, or authentication tag is invalid.
    fn open(&self, material: &SecretMaterial, aad: &str) -> DomainResult<String>;
}

/// Current cloud source evidence captured by the trusted workflow.
/// The bridge checks it under the fixed source writer's lock before any provider state mutation.
#[derive(Debug, Clone, Copy)]
pub struct MockSourceGuard<'a> {
    /// Current positive cloud configuration revision.
    pub version: u64,
    /// Canonical SHA256 of the entire current cloud-integration stored envelope.
    pub payload_fingerprint: &'a str,
}

/// Atomic encrypted provider state, without workflow claims or duplicate business success audits.
/// SQL persists across instances/restarts; ConfigStore(None) is only process memory.
pub struct MockBridge<'a> {
    configurations: &'a ConfigStore,
    codec: &'a dyn MockCodec,
}

impl fmt::Debug for MockBridge<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApigMockBridge").finish_non_exhaustive()
    }
}

impl<'a> MockBridge<'a> {
    /// Use the API's existing configuration store and trusted authenticated cipher adapter.
    pub fn new(configurations: &'a ConfigStore, codec: &'a dyn MockCodec) -> Self {
        Self { configurations, codec }
    }

    /// Compute the same canonical source-envelope hash used by the locked prerequisite check.
    /// A hash is only comparison evidence; the caller must first authorize and load this source.
    pub fn source_fingerprint(payload: &Value) -> String {
        json::fingerprint(payload)
    }

    /// Explicitly initialize only the owned demonstration target, preserving any existing state.
    /// Call only from an authorized POST observation initialization, never a business state GET.
    /// The original operation deadline includes guards and all SQL/configuration lock waiting.
    ///
    /// # Errors
    /// Scope/source/authority/deadline, fixture ownership, stored ciphertext or publication is invalid.
    pub async fn seed_owned_fixture(
        &self,
        scope: &MockScope,
        source: MockSourceGuard<'_>,
        guard: &dyn CurrentGuard,
        deadline: Instant,
    ) -> DomainResult<()> {
        timeout_at(deadline, async {
            guard.validate().await?;
            self.configurations
                .mutate_conditional_audited::<Option<Record>, _, _>(
                    scope.tenant,
                    mutation(scope),
                    |prerequisite: Option<Value>, stored: &mut Option<Record>| {
                        source.validate(scope, prerequisite.as_ref())?;
                        check_deadline(deadline)?;
                        if let Some(record) = stored.as_ref() {
                            self.checked(scope, source, record)?;
                            return Ok(MutationDecision::Unchanged);
                        }
                        let state = MockState::seed(scope.fingerprint(), &scope.binding)?;
                        *stored = Some(self.encrypted(scope, source, &state)?);
                        check_deadline(deadline)?;
                        Ok(MutationDecision::Write(None))
                    },
                    |_| Ok(None),
                )
                .await?;
            guard.validate().await?;
            check_deadline(deadline)
        })
        .await
        .map_err(|_| unavailable())?
    }

    /// Invoke one of the four actions only against an already initialized owned target.
    /// No implicit seeding, network, automatic retry, or business receipt audit occurs here.
    /// A post-publication timeout/rejection does not roll back provider state: the workflow
    /// must keep its permanent claim and represent an unconfirmed write as Unknown.
    ///
    /// # Errors
    /// Current source/authority, stored AEAD evidence, input, size, counter or deadline is invalid.
    pub async fn execute(
        &self,
        scope: &MockScope,
        source: MockSourceGuard<'_>,
        action: &str,
        input: &Value,
        guard: &dyn CurrentGuard,
        deadline: Instant,
    ) -> DomainResult<RpcResponse> {
        timeout_at(deadline, async {
            guard.validate().await?;
            let mut response = None;
            self.configurations
                .mutate_conditional_audited::<Option<Record>, _, _>(
                    scope.tenant,
                    mutation(scope),
                    |prerequisite: Option<Value>, stored: &mut Option<Record>| {
                        source.validate(scope, prerequisite.as_ref())?;
                        check_deadline(deadline)?;
                        let current = stored
                            .as_ref()
                            .ok_or_else(|| evidence("APIG Mock target has not been explicitly initialized"))?;
                        let mut state = self.checked(scope, source, current)?;
                        let candidate = state.respond(scope.fingerprint(), action, input)?;
                        *stored = Some(self.encrypted(scope, source, &state)?);
                        check_deadline(deadline)?;
                        response = Some(candidate);
                        Ok(MutationDecision::Write(None))
                    },
                    |_| Ok(None),
                )
                .await?;
            guard.validate().await?;
            check_deadline(deadline)?;
            response.ok_or_else(|| evidence("APIG Mock produced no provider response"))
        })
        .await
        .map_err(|_| unavailable())?
    }

    fn checked(&self, scope: &MockScope, source: MockSourceGuard<'_>, record: &Record) -> DomainResult<MockState> {
        if serde_json::to_vec(record)?.len() > MAX_RECORD_BYTES
            || record.schema != 1
            || (record.tenant, record.id, record.source_id) != (scope.tenant, scope.id, scope.source_id)
            || (&record.scope, &record.region, &record.source_identity, &record.binding)
                != (&scope.fingerprint, &scope.region, &scope.source_identity, &scope.binding)
            || record.source_version == 0
            || record.source_version > source.version
        {
            return Err(evidence("Stored APIG Mock source/identity/schema differs"));
        }
        let aad = aad(scope);
        if record.state.aad.as_deref() != Some(aad.as_str()) {
            return Err(DomainError::Crypto("APIG Mock AAD differs".into()));
        }
        let plaintext = self.codec.open(&record.state, &aad)?;
        if plaintext.len() > MAX_STATE_BYTES {
            return Err(evidence("Stored APIG Mock plaintext exceeds 512 KiB"));
        }
        let state: MockState = serde_json::from_str(&plaintext)?;
        state.check_scope(scope.fingerprint(), &scope.binding)?;
        Ok(state)
    }

    fn encrypted(&self, scope: &MockScope, source: MockSourceGuard<'_>, state: &MockState) -> DomainResult<Record> {
        let plaintext = serde_json::to_string(state)?;
        if plaintext.len() > MAX_STATE_BYTES {
            return Err(evidence("APIG Mock state exceeds 512 KiB"));
        }
        let aad = aad(scope);
        let state = self.codec.seal(&plaintext, &aad)?;
        if state.aad.as_deref() != Some(aad.as_str()) {
            return Err(DomainError::Crypto("APIG Mock cipher omitted AAD".into()));
        }
        let record = Record {
            schema: 1,
            tenant: scope.tenant,
            id: scope.id,
            source_id: scope.source_id,
            scope: scope.fingerprint.clone(),
            region: scope.region.clone(),
            source_identity: scope.source_identity.clone(),
            binding: scope.binding.clone(),
            source_version: source.version,
            state,
        };
        if serde_json::to_vec(&record)?.len() > MAX_RECORD_BYTES {
            return Err(evidence("Encrypted APIG Mock record exceeds 1 MiB"));
        }
        Ok(record)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub(super) schema: u64,
    pub(super) tenant: TenantId,
    pub(super) id: Id,
    pub(super) source_id: Id,
    pub(super) scope: String,
    pub(super) region: String,
    pub(super) source_identity: String,
    pub(super) binding: super::Binding,
    pub(super) source_version: u64,
    pub(super) state: SecretMaterial,
}

impl MockSourceGuard<'_> {
    fn validate(self, scope: &MockScope, prerequisite: Option<&Value>) -> DomainResult<()> {
        check_hash(self.payload_fingerprint)?;
        let raw = prerequisite.ok_or_else(|| evidence("APIG cloud source is absent"))?;
        if self.version == 0
            || raw["version"].as_u64() != Some(self.version)
            || raw["id"] != serde_json::to_value(scope.source_id)?
            || raw["name"] != "alicloud-apig"
            || raw["enabled"] != true
            || json::fingerprint(raw) != self.payload_fingerprint
        {
            return Err(DomainError::Conflict("APIG source changed before Mock publication".into()));
        }
        Ok(())
    }
}

fn mutation(scope: &MockScope) -> ConditionalMutation<'static> {
    ConditionalMutation {
        kind: KIND,
        id: scope.id,
        guard: Some(ConfigurationGuard { kind: "cloud-integration", id: scope.source_id }),
    }
}

pub(super) fn aad(scope: &MockScope) -> String {
    format!("{}|kind:{KIND}:v1", FieldCipher::make_aad(&scope.tenant, &scope.id))
}

fn check_deadline(deadline: Instant) -> DomainResult<()> {
    if Instant::now() >= deadline { Err(evidence("APIG original operation deadline expired")) } else { Ok(()) }
}

fn unavailable() -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "alicloud-apig-mock".into(),
        cause: "Original APIG Mock deadline expired".into(),
    }
}
