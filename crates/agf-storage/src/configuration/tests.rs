//! Offline callbacks must not publish unaudited candidates or consume a bounded slot.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    time::Timestamp,
};
use serde::Deserialize;
use std::sync::atomic::{AtomicUsize, Ordering};

fn audit(tenant: TenantId) -> AuditLog {
    AuditLog {
        id: Id::new(),
        tenant_id: tenant,
        sequence: 0,
        action: AuditAction::Configure,
        outcome: AuditOutcome::Success,
        actor: AuditActor::system("configuration-test"),
        target: AuditTarget::new("test", None, None),
        before: None,
        after: None,
        changed_fields: Vec::new(),
        request_id: None,
        error: None,
        note: "configuration test".into(),
        prev_hash: String::new(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    }
}

#[tokio::test]
async fn offline_audit_failure_preserves_existing_record_and_new_slot() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    store.put(tenant, "test", id, &1_u64).await.unwrap();
    for candidate in [id, Id::new()] {
        let result = store
            .mutate_bounded_audited_with(
                tenant,
                "test",
                candidate,
                AuditedMutation { limit: Some(2), audit: audit(tenant) },
                |value: &mut u64| {
                    *value = 2;
                    Ok(())
                },
                |_| Err(DomainError::Internal("audit intentionally rejected".into())),
            )
            .await;
        assert!(result.is_err());
    }
    assert_eq!(store.get::<u64>(tenant, "test", id).await.unwrap(), Some(1));
    assert_eq!(store.list::<u64>(tenant, "test").await.unwrap(), vec![1]);
    let appended = AtomicUsize::new(0);
    let (value, sealed) = store
        .mutate_bounded_audited_with(
            tenant,
            "test",
            Id::new(),
            AuditedMutation { limit: Some(2), audit: audit(tenant) },
            |value: &mut u64| {
                *value = 3;
                Ok(())
            },
            |entry| {
                appended.fetch_add(1, Ordering::SeqCst);
                Ok(Some(entry))
            },
        )
        .await
        .unwrap();
    assert_eq!(value, 3);
    assert!(sealed.is_some());
    assert_eq!(appended.load(Ordering::SeqCst), 1);
    assert_eq!(store.list::<u64>(tenant, "test").await.unwrap().len(), 2);
}

#[derive(Default, Deserialize)]
struct FailsSerialization;
impl Serialize for FailsSerialization {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("serialization intentionally rejected"))
    }
}

#[tokio::test]
async fn validation_serialization_and_tenant_errors_never_append_success_audit() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let appended = AtomicUsize::new(0);
    let id = Id::new();
    let callback = |entry| {
        appended.fetch_add(1, Ordering::SeqCst);
        Ok(Some(entry))
    };
    let invalid = store
        .mutate_bounded_audited_with(
            tenant,
            "test",
            id,
            AuditedMutation { limit: None, audit: audit(tenant) },
            |_: &mut u64| Err(DomainError::Conflict("stale revision".into())),
            callback,
        )
        .await;
    assert!(invalid.is_err());
    let invalid = store
        .mutate_bounded_audited_with(
            tenant,
            "test",
            id,
            AuditedMutation { limit: None, audit: audit(tenant) },
            |_: &mut FailsSerialization| Ok(()),
            callback,
        )
        .await;
    assert!(invalid.is_err());
    let invalid = store
        .mutate_bounded_audited_with(
            tenant,
            "test",
            id,
            AuditedMutation { limit: None, audit: audit(TenantId::new()) },
            |_: &mut u64| Ok(()),
            callback,
        )
        .await;
    assert!(matches!(invalid, Err(DomainError::TenantViolation { .. })));
    assert_eq!(appended.load(Ordering::SeqCst), 0);
    assert_eq!(store.get::<u64>(tenant, "test", id).await.unwrap(), None);
}

#[tokio::test]
async fn bounded_competing_creates_audit_once_and_existing_update_needs_no_slot() {
    let store = Arc::new(ConfigStore::new(None));
    let tenant = TenantId::new();
    let start = Arc::new(tokio::sync::Barrier::new(3));
    let appended = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let start = start.clone();
        let appended = appended.clone();
        handles.push(tokio::spawn(async move {
            let id = Id::new();
            start.wait().await;
            store
                .mutate_bounded_audited_with(
                    tenant,
                    "test",
                    id,
                    AuditedMutation { limit: Some(1), audit: audit(tenant) },
                    |value: &mut u64| {
                        *value = 1;
                        Ok(())
                    },
                    |entry| {
                        appended.fetch_add(1, Ordering::SeqCst);
                        Ok(Some(entry))
                    },
                )
                .await
                .map(|_| id)
        }));
    }
    start.wait().await;
    let mut winner = None;
    let mut rejected = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(id) => {
                assert!(winner.replace(id).is_none());
            }
            Err(DomainError::Validation(_)) => rejected += 1,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
    assert_eq!(rejected, 1);
    assert_eq!(appended.load(Ordering::SeqCst), 1);
    let winner = winner.unwrap();
    store
        .mutate_bounded_audited_with(
            tenant,
            "test",
            winner,
            AuditedMutation { limit: Some(1), audit: audit(tenant) },
            |value: &mut u64| {
                *value = 2;
                Ok(())
            },
            |entry| {
                appended.fetch_add(1, Ordering::SeqCst);
                Ok(Some(entry))
            },
        )
        .await
        .unwrap();
    assert_eq!(store.get::<u64>(tenant, "test", winner).await.unwrap(), Some(2));
    assert_eq!(appended.load(Ordering::SeqCst), 2);
    let foreign = TenantId::new();
    store
        .mutate_bounded_audited_with(
            foreign,
            "test",
            winner,
            AuditedMutation { limit: Some(1), audit: audit(foreign) },
            |value: &mut u64| {
                *value = 7;
                Ok(())
            },
            |entry| {
                appended.fetch_add(1, Ordering::SeqCst);
                Ok(Some(entry))
            },
        )
        .await
        .unwrap();
    assert_eq!(store.get::<u64>(tenant, "test", winner).await.unwrap(), Some(2));
    assert_eq!(store.get::<u64>(foreign, "test", winner).await.unwrap(), Some(7));
    assert_eq!(appended.load(Ordering::SeqCst), 3);
}
