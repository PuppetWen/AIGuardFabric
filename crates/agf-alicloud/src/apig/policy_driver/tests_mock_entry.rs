use super::{
    CurrentGuard, ManagedLimit, MockBridge, MockCodec, MockScope, MockSourceGuard, MockState, ReadbackState,
    WriteOutcome, current_limit,
    mock_bridge::{KIND, Record, aad},
    prepare_limit,
    tests_bridge::{Authority, Codec, codec, deadline, scope, source},
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use agf_storage::configuration::ConfigStore;
use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::time::Instant;

async fn persisted(store: &ConfigStore, cipher: &Codec, target: &MockScope) -> DomainResult<MockState> {
    let record: Record = store
        .get(target.tenant, KIND, target.id)
        .await?
        .ok_or_else(|| DomainError::Internal("Missing encrypted provider state".into()))?;
    serde_json::from_str(&cipher.open(&record.state, &aad(target))?).map_err(Into::into)
}

struct RejectWritten<'a> {
    store: &'a ConfigStore,
    cipher: &'a Codec,
    target: &'a MockScope,
}

#[async_trait]
impl CurrentGuard for RejectWritten<'_> {
    async fn validate(&self) -> DomainResult<()> {
        if persisted(self.store, self.cipher, self.target).await?.call_count("UpdatePolicy") > 0 {
            Err(DomainError::Forbidden("Submission revoked after provider commit".into()))
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn typed_mock_reads_never_seed_and_one_publish_is_durable_and_acknowledged() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let cipher = codec()?;
    let target = scope(TenantId::new(), Id::new())?;
    let (_, fingerprint) = source(&store, &target, 1).await?;
    let source = MockSourceGuard { version: 1, payload_fingerprint: &fingerprint };
    let bridge = MockBridge::new(&store, &cipher);
    assert!(bridge.observe_current(&target, source, &Authority, deadline()).await.is_err());
    assert!(store.get::<Value>(target.tenant, KIND, target.id).await?.is_none());
    bridge.seed_owned_fixture(&target, source, &Authority, deadline()).await?;
    let baseline = bridge.observe_current(&target, source, &Authority, deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    assert_eq!(
        bridge.publish_once(&target, source, &update, &Authority, deadline()).await?,
        WriteOutcome::Accepted { request_id: "mock-UpdatePolicy-1".into() }
    );
    let restarted_cipher = codec()?;
    let restarted = MockBridge::new(&store, &restarted_cipher);
    let after = restarted.observe_current(&target, source, &Authority, deadline()).await?;
    assert_eq!(current_limit(&after, ManagedLimit::TokenPerMinute)?, 1250);
    assert_eq!(update.compare_readback(&after), ReadbackState::Matched);
    let state = persisted(&store, &cipher, &target).await?;
    assert_eq!(state.call_count("UpdatePolicy"), 1);
    for action in ["GetHttpApi", "GetPolicy", "GetPolicyAttachment"] {
        assert_eq!(state.call_count(action), 3);
    }
    Ok(())
}

#[tokio::test]
async fn changed_mock_baseline_or_expired_original_deadline_prevents_an_additional_write() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let cipher = codec()?;
    let target = scope(TenantId::new(), Id::new())?;
    let (_, fingerprint) = source(&store, &target, 1).await?;
    let source = MockSourceGuard { version: 1, payload_fingerprint: &fingerprint };
    let bridge = MockBridge::new(&store, &cipher);
    bridge.seed_owned_fixture(&target, source, &Authority, deadline()).await?;
    let baseline = bridge.observe_current(&target, source, &Authority, deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    let mut desired = baseline.config.clone();
    desired["globalRules"][0]["limitValue"] = json!(777);
    bridge.execute(&target, source, "UpdatePolicy",
        &json!({"policyId":target.binding.policy_id,"body":{"name":baseline.policy["name"],"config":desired.to_string()}}),
        &Authority, deadline()).await?;
    assert!(matches!(
        bridge.publish_once(&target, source, &update, &Authority, deadline()).await,
        Err(DomainError::Conflict(_))
    ));
    let before = store.get::<Value>(target.tenant, KIND, target.id).await?;
    assert!(bridge.observe_current(&target, source, &Authority, Instant::now()).await.is_err());
    assert!(bridge.publish_once(&target, source, &update, &Authority, Instant::now()).await.is_err());
    assert_eq!(store.get::<Value>(target.tenant, KIND, target.id).await?, before);
    assert_eq!(persisted(&store, &cipher, &target).await?.call_count("UpdatePolicy"), 1);
    Ok(())
}

#[tokio::test]
async fn typed_publish_maps_post_commit_revocation_to_unknown_without_undo_or_retry() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let cipher = codec()?;
    let target = scope(TenantId::new(), Id::new())?;
    let (_, fingerprint) = source(&store, &target, 1).await?;
    let source = MockSourceGuard { version: 1, payload_fingerprint: &fingerprint };
    let bridge = MockBridge::new(&store, &cipher);
    bridge.seed_owned_fixture(&target, source, &Authority, deadline()).await?;
    let baseline = bridge.observe_current(&target, source, &Authority, deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    let guard = RejectWritten { store: &store, cipher: &cipher, target: &target };
    assert_eq!(bridge.publish_once(&target, source, &update, &guard, deadline()).await?, WriteOutcome::Unknown);
    let after = bridge.observe_current(&target, source, &Authority, deadline()).await?;
    assert_eq!(update.compare_readback(&after), ReadbackState::Matched);
    assert_eq!(persisted(&store, &cipher, &target).await?.call_count("UpdatePolicy"), 1);
    // Matching observation does not manufacture an acknowledgement for the original invocation.
    assert_eq!(current_limit(&after, ManagedLimit::TokenPerMinute)?, 1250);
    Ok(())
}
