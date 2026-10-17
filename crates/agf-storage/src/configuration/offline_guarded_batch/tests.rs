//! Offline failures retain every original; publication appends one audit for the full batch.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    time::Timestamp,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

mod validation;

fn entry(tenant: TenantId) -> AuditLog {
    AuditLog {
        id: Id::new(),
        tenant_id: tenant,
        sequence: 0,
        action: AuditAction::Configure,
        outcome: AuditOutcome::Success,
        actor: AuditActor::system("offline-batch-test"),
        target: AuditTarget::new("test", None, None),
        before: None,
        after: None,
        changed_fields: Vec::new(),
        request_id: None,
        error: None,
        note: "owned test".into(),
        prev_hash: String::new(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    }
}

fn request(id: Id) -> OfflineGuardedBatch<'static> {
    OfflineGuardedBatch {
        kind: "test",
        id,
        guards: &[],
        security: None,
        related: &[],
        max_main_bytes: 4 * 1024 * 1024,
        max_related_bytes: 1024 * 1024,
        max_total_write_bytes: 8 * 1024 * 1024,
    }
}

fn write(tenant: TenantId, related: Candidates) -> GuardedBatchDecision {
    GuardedBatchDecision::Write { related, audit: Box::new(entry(tenant)) }
}

fn seal(mut audit: AuditLog) -> AuditLog {
    audit.sequence = 1;
    audit.prev_hash = agf_core::audit::GENESIS_HASH.into();
    audit.seal();
    audit
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
struct Candidate {
    broken: bool,
    value: u64,
}
impl Serialize for Candidate {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.broken {
            return Err(serde::ser::Error::custom("intentional candidate serialization failure"));
        }
        json!({"broken": false, "value": self.value}).serialize(serializer)
    }
}

#[tokio::test]
async fn apply_serialization_and_audit_failures_do_not_publish_any_record() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let child = Id::new();
    store.put(tenant, "test", id, &Candidate::default()).await.unwrap();
    store.put(tenant, "related", child, &7_u64).await.unwrap();
    let related = [ConfigurationGuard { kind: "related", id: child }];
    let before = store.memory.lock().unwrap().clone();
    let calls = AtomicUsize::new(0);
    for failure in ["apply", "serialization", "audit", "tenant", "undeclared", "audit-id"] {
        let result = store.mutate_offline_guarded_batch_audited(
            tenant,
            OfflineGuardedBatch { related: &related, ..request(id) },
            |_, main: &mut Candidate, _| {
                main.broken = failure == "serialization";
                main.value = 99;
                if failure == "apply" {
                    return Err(DomainError::Conflict("stale".into()));
                }
                let key = if failure == "undeclared" { Id::new() } else { child };
                let mut audit = entry(if failure == "tenant" { TenantId::new() } else { tenant });
                if failure == "audit-id" {
                    audit.id = Id::nil();
                }
                Ok(GuardedBatchDecision::Write {
                    related: BTreeMap::from([(("related".into(), key), None)]),
                    audit: Box::new(audit),
                })
            },
            |_, _| {
                assert_eq!(failure, "audit");
                calls.fetch_add(1, Ordering::SeqCst);
                Err(DomainError::Internal("trusted sink refused without appending".into()))
            },
        );
        assert!(result.is_err(), "{failure}");
        assert_eq!(*store.memory.lock().unwrap(), before, "{failure}");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unchanged_returns_the_original_even_if_candidate_serialization_would_fail() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let child = Id::new();
    store.put(tenant, "test", id, &Candidate::default()).await.unwrap();
    store.put(tenant, "related", child, &7_u64).await.unwrap();
    let before = store.memory.lock().unwrap().clone();
    let related = [ConfigurationGuard { kind: "related", id: child }];
    let (original, audit) = store
        .mutate_offline_guarded_batch_audited(
            tenant,
            OfflineGuardedBatch { related: &related, ..request(id) },
            |_, main: &mut Candidate, originals| {
                assert_eq!(originals[&("related".into(), child)], Some(Value::from(7)));
                main.broken = true;
                main.value = 99;
                Ok(GuardedBatchDecision::Unchanged)
            },
            |_, _| panic!("no-op must not append an audit"),
        )
        .unwrap();
    assert_eq!(original, Candidate::default());
    assert!(audit.is_none());
    assert_eq!(*store.memory.lock().unwrap(), before);
    let missing = Id::new();
    let (value, audit) = store
        .mutate_offline_guarded_batch_audited(
            tenant,
            request(missing),
            |_, main: &mut u64, _| {
                *main = 999;
                Ok(GuardedBatchDecision::Unchanged)
            },
            |audit, _| Ok(seal(audit)),
        )
        .unwrap();
    assert_eq!(value, 0);
    assert!(audit.is_none());
    assert!(!store.memory.lock().unwrap().contains_key(&(tenant, "test".into(), missing)));
}

#[tokio::test]
async fn current_tenant_guards_and_fixed_authority_are_shared_with_the_audit_callback() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let other = TenantId::new();
    let identity = TenantId::default_tenant();
    let id = Id::new();
    let subject = Id::new();
    for (owner, kind, key, value) in [
        (tenant, "dependency", id, 1),
        (other, "dependency", id, 2),
        (tenant, "related", id, 3),
        (other, "related", id, 30),
        (identity, DIRECTORY, identity.as_id(), 4),
        (tenant, DIRECTORY, identity.as_id(), 40),
        (identity, PASSWORD_POLICY, identity.as_id(), 5),
        (tenant, PASSWORD_POLICY, identity.as_id(), 50),
        (identity, MFA, subject, 6),
        (tenant, MFA, subject, 60),
    ] {
        store.put(owner, kind, key, &value).await.unwrap();
    }
    // Any proof prepared before this update must observe the current guarded value.
    store.put(tenant, "dependency", id, &9_u64).await.unwrap();
    let guards = [ConfigurationGuard { kind: "dependency", id }, ConfigurationGuard { kind: "absent", id }];
    let related = [ConfigurationGuard { kind: "related", id }, ConfigurationGuard { kind: "missing-child", id }];
    let options = OfflineGuardedBatch {
        guards: &guards,
        related: &related,
        security: Some(OfflineSecurityRecords { identity_tenant: identity, subject_id: subject }),
        ..request(Id::new())
    };
    let check = |snapshot: &OfflineGuardedSnapshot| {
        assert_eq!(snapshot.guards.len(), 2);
        assert_eq!(snapshot.guards[&("dependency".into(), id)], Some(Value::from(9)));
        assert_eq!(snapshot.guards[&("absent".into(), id)], None);
        assert_eq!(snapshot.tenant_directory, Some(Value::from(4)));
        assert_eq!(snapshot.password_policy, Some(Value::from(5)));
        assert_eq!(snapshot.mfa_enrollment, Some(Value::from(6)));
        // Internal nonblocking lock inspection proves both callbacks share the publication mutex.
        assert!(matches!(store.memory.try_lock(), Err(std::sync::TryLockError::WouldBlock)));
    };
    store
        .mutate_offline_guarded_batch_audited(
            tenant,
            options,
            |snapshot, main: &mut u64, originals| {
                check(snapshot);
                assert_eq!(originals.len(), 2);
                assert_eq!(originals[&("related".into(), id)], Some(Value::from(3)));
                assert_eq!(originals[&("missing-child".into(), id)], None);
                *main = 8;
                Ok(write(tenant, BTreeMap::new()))
            },
            |audit, snapshot| {
                check(snapshot);
                Ok(seal(audit))
            },
        )
        .unwrap();
    assert_eq!(store.get::<u64>(other, "related", id).await.unwrap(), Some(30));
    assert_eq!(store.get::<u64>(tenant, "related", id).await.unwrap(), Some(3));
}

#[tokio::test]
async fn the_full_declared_batch_updates_inserts_deletes_and_appends_exactly_once() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let other = TenantId::new();
    let id = Id::new();
    let guards = (0..32).map(|_| ConfigurationGuard { kind: "guard", id: Id::new() }).collect::<Vec<_>>();
    let related = (0..100).map(|_| ConfigurationGuard { kind: "related", id: Id::new() }).collect::<Vec<_>>();
    store.put(tenant, "test", id, &1_u64).await.unwrap();
    store.put(other, "test", id, &100_u64).await.unwrap();
    store.put(tenant, "related", related[0].id, &1_u64).await.unwrap();
    store.put(tenant, "related", related[1].id, &2_u64).await.unwrap();
    let untouched = Id::new();
    store.put(tenant, "related", untouched, &999_u64).await.unwrap();
    let mut expected = store.memory.lock().unwrap().clone();
    expected.insert((tenant, "test".into(), id), Value::from(2));
    let mut updates = BTreeMap::new();
    for (index, target) in related.iter().enumerate() {
        let value = match index {
            0 => None,
            1 => Some(Value::Null),
            _ => Some(Value::from(index)),
        };
        match &value {
            Some(value) => {
                expected.insert((tenant, "related".into(), target.id), value.clone());
            }
            None => {
                expected.remove(&(tenant, "related".into(), target.id));
            }
        }
        updates.insert(("related".into(), target.id), value);
    }
    let appends = AtomicUsize::new(0);
    let (value, audit) = store
        .mutate_offline_guarded_batch_audited(
            tenant,
            OfflineGuardedBatch { guards: &guards, related: &related, ..request(id) },
            |snapshot, main: &mut u64, originals| {
                assert_eq!(snapshot.guards.len(), 32);
                assert!(snapshot.tenant_directory.is_none());
                assert!(snapshot.password_policy.is_none());
                assert!(snapshot.mfa_enrollment.is_none());
                assert_eq!(originals.len(), 100);
                *main = 2;
                Ok(write(tenant, updates))
            },
            |audit, _| {
                appends.fetch_add(1, Ordering::SeqCst);
                Ok(seal(audit))
            },
        )
        .unwrap();
    assert_eq!(value, 2);
    assert!(audit.unwrap().verify());
    assert_eq!(appends.load(Ordering::SeqCst), 1);
    assert_eq!(*store.memory.lock().unwrap(), expected);
}

#[tokio::test]
async fn authority_refusal_in_the_final_callback_preserves_all_candidates() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let subject = Id::new();
    store.put(tenant, "test", id, &1_u64).await.unwrap();
    store.put(tenant, MFA, subject, &json!({"required": false})).await.unwrap();
    // A previously prepared authority proof must not override the fixed record at commit.
    store.put(tenant, MFA, subject, &json!({"required": true})).await.unwrap();
    let before = store.memory.lock().unwrap().clone();
    let calls = AtomicUsize::new(0);
    let result = store.mutate_offline_guarded_batch_audited(
        tenant,
        OfflineGuardedBatch {
            security: Some(OfflineSecurityRecords { identity_tenant: tenant, subject_id: subject }),
            ..request(id)
        },
        |_, value: &mut u64, _| {
            *value = 2;
            Ok(write(tenant, BTreeMap::new()))
        },
        |_, snapshot| {
            assert_eq!(snapshot.mfa_enrollment, Some(json!({"required": true})));
            calls.fetch_add(1, Ordering::SeqCst);
            Err(DomainError::PreconditionFailed("current authority requires MFA".into()))
        },
    );
    assert!(matches!(result, Err(DomainError::PreconditionFailed(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(*store.memory.lock().unwrap(), before);
}
