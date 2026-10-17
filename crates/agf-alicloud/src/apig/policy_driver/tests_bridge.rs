use super::{Binding, CurrentGuard, MockBridge, MockCodec, MockScope, MockSourceGuard, json, mock_bridge::Record};
use crate::AdapterMode;
use agf_core::{
    credential::{KeyBackend, SecretMaterial},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use agf_storage::{configuration::ConfigStore, crypto::FieldCipher};
use async_trait::async_trait;
use secrecy::ExposeSecret;
use serde_json::{Value, json as value};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::{Duration, Instant};

pub(super) struct Codec(FieldCipher);

impl MockCodec for Codec {
    fn seal(&self, plaintext: &str, aad: &str) -> DomainResult<SecretMaterial> {
        self.0.encrypt(&plaintext.to_string().into(), aad)
    }

    fn open(&self, material: &SecretMaterial, aad: &str) -> DomainResult<String> {
        if material.aad.as_deref() != Some(aad) {
            return Err(DomainError::Crypto("Unexpected test AAD".into()));
        }
        Ok(self.0.decrypt(material)?.expose_secret().to_string())
    }
}

pub(super) struct Authority;

struct RejectAfterProvider(AtomicUsize);

#[async_trait]
impl CurrentGuard for RejectAfterProvider {
    async fn validate(&self) -> DomainResult<()> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(DomainError::Forbidden("Submission revoked after provider commit".into()))
        }
    }
}

#[async_trait]
impl CurrentGuard for Authority {
    async fn validate(&self) -> DomainResult<()> {
        Ok(())
    }
}

pub(super) fn codec() -> DomainResult<Codec> {
    Ok(Codec(FieldCipher::new(&[7; 32], "apig-bridge-test", KeyBackend::LocalFile)?))
}

pub(super) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn binding() -> DomainResult<Binding> {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../../../tests/fixtures/alicloud/apig-policy-driver.json"))?;
    serde_json::from_value(fixture["binding"].clone()).map_err(Into::into)
}

pub(super) fn scope(tenant: TenantId, source_id: Id) -> DomainResult<MockScope> {
    MockScope::new(tenant, source_id, "cn-hangzhou", &"a".repeat(64), binding()?, AdapterMode::Mocked)
}

pub(super) async fn source(store: &ConfigStore, scope: &MockScope, version: u64) -> DomainResult<(Value, String)> {
    let row = value!({"id":scope.source_id,"name":"alicloud-apig","enabled":true,"mock":true,"version":version});
    store.put(scope.tenant, "cloud-integration", scope.source_id, &row).await?;
    let fingerprint = json::fingerprint(&row);
    Ok((row, fingerprint))
}

#[tokio::test]
async fn explicit_seed_actual_encryption_and_atomic_mock_writes_survive_bridge_recreation() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let cipher = codec()?;
    let target = scope(TenantId::new(), Id::new())?;
    let (_, fingerprint) = source(&store, &target, 1).await?;
    let guard = MockSourceGuard { version: 1, payload_fingerprint: &fingerprint };
    let bridge = MockBridge::new(&store, &cipher);
    let input = value!({"httpApiId":target.binding.http_api_id,"expandPolicyConfigs":false});
    assert!(bridge.execute(&target, guard, "GetHttpApi", &input, &Authority, deadline()).await.is_err());
    assert!(store.get::<Value>(target.tenant, super::mock_bridge::KIND, target.id).await?.is_none());
    bridge.seed_owned_fixture(&target, guard, &Authority, deadline()).await?;
    let before = store.get::<Value>(target.tenant, super::mock_bridge::KIND, target.id).await?;
    bridge.seed_owned_fixture(&target, guard, &Authority, deadline()).await?;
    assert_eq!(store.get::<Value>(target.tenant, super::mock_bridge::KIND, target.id).await?, before);
    let mut config: Value = serde_json::from_str(
        bridge
            .execute(
                &target,
                guard,
                "GetPolicy",
                &value!({"policyId":target.binding.policy_id}),
                &Authority,
                deadline(),
            )
            .await?
            .body["data"]["config"]
            .as_str()
            .ok_or_else(|| DomainError::Internal("Missing config".into()))?,
    )?;
    config["globalRules"][0]["limitValue"] = value!(1250);
    bridge
        .execute(
            &target,
            guard,
            "UpdatePolicy",
            &value!({"policyId":target.binding.policy_id,"body":{"name":"demo-limit","config":config.to_string()}}),
            &Authority,
            deadline(),
        )
        .await?;
    let stored: Record = store
        .get(target.tenant, super::mock_bridge::KIND, target.id)
        .await?
        .ok_or_else(|| DomainError::Internal("Missing encrypted state".into()))?;
    let encoded = serde_json::to_string(&stored)?;
    assert!(!encoded.contains("globalRules"));
    assert!(!encoded.contains("demo-limit"));
    assert_eq!(stored.state.backend, KeyBackend::LocalFile);
    let recreated_cipher = codec()?;
    let recreated = MockBridge::new(&store, &recreated_cipher);
    let read = recreated
        .execute(&target, guard, "GetPolicy", &value!({"policyId":target.binding.policy_id}), &Authority, deadline())
        .await?;
    assert_eq!(
        serde_json::from_str::<Value>(
            read.body["data"]["config"].as_str().ok_or_else(|| DomainError::Internal("Missing config".into()))?
        )?,
        config
    );
    assert_eq!(read.body["requestId"], "mock-GetPolicy-2");
    let after = store.get::<Value>(target.tenant, super::mock_bridge::KIND, target.id).await?;
    recreated.seed_owned_fixture(&target, guard, &Authority, deadline()).await?;
    assert_eq!(store.get::<Value>(target.tenant, super::mock_bridge::KIND, target.id).await?, after);
    // Offline is intentionally process-local: a separate store has no provider state.
    let independent_store = ConfigStore::new(None);
    source(&independent_store, &target, 1).await?;
    assert!(
        MockBridge::new(&independent_store, &cipher)
            .execute(&target, guard, "GetHttpApi", &input, &Authority, deadline())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn source_revision_aad_scope_and_failed_calls_cannot_overwrite_existing_provider_facts() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let cipher = codec()?;
    let target = scope(TenantId::new(), Id::new())?;
    let (_, fingerprint) = source(&store, &target, 1).await?;
    let guard = MockSourceGuard { version: 1, payload_fingerprint: &fingerprint };
    let bridge = MockBridge::new(&store, &cipher);
    bridge.seed_owned_fixture(&target, guard, &Authority, deadline()).await?;
    let original = store.get::<Value>(target.tenant, super::mock_bridge::KIND, target.id).await?;
    assert!(
        bridge
            .execute(&target, guard, "GetPolicy", &value!({"policyId":"foreign"}), &Authority, deadline())
            .await
            .is_err()
    );
    assert!(
        bridge
            .execute(
                &target,
                guard,
                "GetPolicy",
                &value!({"policyId":target.binding.policy_id}),
                &Authority,
                Instant::now()
            )
            .await
            .is_err()
    );
    assert_eq!(store.get::<Value>(target.tenant, super::mock_bridge::KIND, target.id).await?, original);
    let (_, next_fingerprint) = source(&store, &target, 2).await?;
    assert!(
        bridge
            .execute(
                &target,
                guard,
                "GetPolicy",
                &value!({"policyId":target.binding.policy_id}),
                &Authority,
                deadline()
            )
            .await
            .is_err()
    );
    assert_eq!(store.get::<Value>(target.tenant, super::mock_bridge::KIND, target.id).await?, original);
    let next = MockSourceGuard { version: 2, payload_fingerprint: &next_fingerprint };
    bridge
        .execute(&target, next, "GetPolicy", &value!({"policyId":target.binding.policy_id}), &Authority, deadline())
        .await?;
    let mut stored: Record = store
        .get(target.tenant, super::mock_bridge::KIND, target.id)
        .await?
        .ok_or_else(|| DomainError::Internal("Missing encrypted state".into()))?;
    assert_eq!(stored.source_version, 2);
    stored.state.aad = Some("foreign-domain".into());
    store.put(target.tenant, super::mock_bridge::KIND, target.id, &stored).await?;
    let corrupted = store.get::<Value>(target.tenant, super::mock_bridge::KIND, target.id).await?;
    assert!(matches!(
        bridge.seed_owned_fixture(&target, next, &Authority, deadline()).await,
        Err(DomainError::Crypto(_))
    ));
    assert!(matches!(
        bridge
            .execute(&target, next, "GetPolicy", &value!({"policyId":target.binding.policy_id}), &Authority, deadline())
            .await,
        Err(DomainError::Crypto(_))
    ));
    assert_eq!(store.get::<Value>(target.tenant, super::mock_bridge::KIND, target.id).await?, corrupted);
    let foreign = scope(TenantId::new(), target.source_id)?;
    assert_ne!(foreign.id, target.id);
    assert_ne!(super::mock_bridge::aad(&foreign), super::mock_bridge::aad(&target));
    let different_source = scope(target.tenant, Id::new())?;
    assert_ne!(different_source.id, target.id);
    assert!(
        MockScope::new(target.tenant, target.source_id, "cn-hangzhou", &"a".repeat(64), binding()?, AdapterMode::Live)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn revocation_after_provider_commit_is_unconfirmed_without_undo_or_an_accepted_receipt() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let cipher = codec()?;
    let target = scope(TenantId::new(), Id::new())?;
    let (_, fingerprint) = source(&store, &target, 1).await?;
    let guard = MockSourceGuard { version: 1, payload_fingerprint: &fingerprint };
    let bridge = MockBridge::new(&store, &cipher);
    bridge.seed_owned_fixture(&target, guard, &Authority, deadline()).await?;
    let first = bridge
        .execute(&target, guard, "GetPolicy", &value!({"policyId":target.binding.policy_id}), &Authority, deadline())
        .await?;
    let mut desired: Value = serde_json::from_str(
        first.body["data"]["config"].as_str().ok_or_else(|| DomainError::Internal("Missing config".into()))?,
    )?;
    desired["globalRules"][0]["limitValue"] = value!(1250);
    let authority = RejectAfterProvider(AtomicUsize::new(0));
    let result = bridge.execute(&target, guard, "UpdatePolicy", &value!({"policyId":target.binding.policy_id,"body":{"name":first.body["data"]["name"],"config":desired.to_string()}}), &authority, deadline()).await;
    assert!(matches!(result, Err(DomainError::Forbidden(_))));
    // The owning workflow treats an unconfirmed invocation as Unknown, retaining its original claim.
    // A bridge error after entry must never be interpreted as proof of a pre-transport rejection.
    let row: Record = store
        .get(target.tenant, super::mock_bridge::KIND, target.id)
        .await?
        .ok_or_else(|| DomainError::Internal("Missing encrypted provider state".into()))?;
    let state: super::MockState = serde_json::from_str(&cipher.open(&row.state, &super::mock_bridge::aad(&target))?)?;
    assert_eq!(state.call_count("UpdatePolicy"), 1);
    let current = bridge
        .execute(&target, guard, "GetPolicy", &value!({"policyId":target.binding.policy_id}), &Authority, deadline())
        .await?;
    assert_eq!(
        serde_json::from_str::<Value>(
            current.body["data"]["config"].as_str().ok_or_else(|| DomainError::Internal("Missing config".into()))?
        )?,
        desired
    );
    assert!(matches!(result, Err(DomainError::Forbidden(_))));
    assert_eq!(state.call_count("UpdatePolicy"), 1);
    Ok(())
}
