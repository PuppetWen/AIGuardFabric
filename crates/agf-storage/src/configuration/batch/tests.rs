//! Offline batch candidates cannot escape a failed audit or a no-op decision.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    time::Timestamp,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn mutation(id: Id, related: &[Id]) -> BatchMutation<'_> {
    BatchMutation {
        kind: "main",
        id,
        guard: None,
        related_kind: "archive",
        related_ids: related,
        max_main_bytes: 4096,
        max_related_bytes: 1024,
    }
}

fn audit(tenant: TenantId) -> AuditLog {
    AuditLog {
        id: Id::new(),
        tenant_id: tenant,
        sequence: 1,
        action: AuditAction::Update,
        outcome: AuditOutcome::Success,
        actor: AuditActor::system("batch-test"),
        target: AuditTarget::new("batch", None, None),
        before: None,
        after: None,
        changed_fields: vec![],
        request_id: None,
        error: None,
        note: "bounded batch test".into(),
        prev_hash: String::new(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    }
}

#[tokio::test]
async fn no_op_ignores_mutated_main_and_never_calls_audit() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let related = Id::new();
    store.put(tenant, "main", id, &7_u64).await.unwrap();
    let (value, sealed) = store
        .mutate_batch_audited(
            tenant,
            mutation(id, &[related]),
            |_, value: &mut u64, _| {
                *value = 99;
                Ok(BatchDecision::Unchanged)
            },
            |_| panic!("no-op appended audit"),
        )
        .await
        .unwrap();
    assert_eq!(value, 7);
    assert!(sealed.is_none());
    assert_eq!(store.get::<u64>(tenant, "main", id).await.unwrap(), Some(7));
    assert!(store.get::<Value>(tenant, "archive", related).await.unwrap().is_none());
}

#[tokio::test]
async fn failed_audit_preserves_all_records_and_success_publishes_one_batch() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let related = Id::new();
    store.put(tenant, "main", id, &7_u64).await.unwrap();
    store.put(tenant, "archive", related, &"before").await.unwrap();
    let result = store
        .mutate_batch_audited(
            tenant,
            mutation(id, &[related]),
            |_, value: &mut u64, _| {
                *value = 8;
                Ok(BatchDecision::Write {
                    related: BTreeMap::from([(related, Value::from("after"))]),
                    audit: Some(Box::new(audit(tenant))),
                })
            },
            |_| Err(DomainError::Internal("owned audit failure".into())),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(store.get::<u64>(tenant, "main", id).await.unwrap(), Some(7));
    assert_eq!(store.get::<String>(tenant, "archive", related).await.unwrap(), Some("before".into()));
    let appended = AtomicUsize::new(0);
    let (value, sealed) = store
        .mutate_batch_audited(
            tenant,
            mutation(id, &[related]),
            |_, value: &mut u64, prior| {
                assert_eq!(prior[&related], Some(Value::from("before")));
                *value = 8;
                Ok(BatchDecision::Write {
                    related: BTreeMap::from([(related, Value::from("after"))]),
                    audit: Some(Box::new(audit(tenant))),
                })
            },
            |mut audit| {
                appended.fetch_add(1, Ordering::SeqCst);
                audit.seal();
                Ok(audit)
            },
        )
        .await
        .unwrap();
    assert_eq!(value, 8);
    assert!(sealed.unwrap().verify());
    assert_eq!(appended.load(Ordering::SeqCst), 1);
    assert_eq!(store.get::<u64>(tenant, "main", id).await.unwrap(), Some(8));
    assert_eq!(store.get::<String>(tenant, "archive", related).await.unwrap(), Some("after".into()));
    assert!(store.get::<u64>(TenantId::new(), "main", id).await.unwrap().is_none());
}

#[tokio::test]
async fn undeclared_oversized_foreign_and_repeated_candidates_fail_before_audit() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let declared = Id::new();
    let appended = AtomicUsize::new(0);
    for case in 0..4 {
        let result = store
            .mutate_batch_audited(
                tenant,
                mutation(id, &[declared]),
                |_, value: &mut u64, _| {
                    *value = 1;
                    let key = if case == 0 { Id::new() } else { declared };
                    let payload = if case == 1 { Value::from("x".repeat(1024)) } else { Value::Null };
                    let mut entry = audit(tenant);
                    if case == 2 {
                        entry.tenant_id = TenantId::new();
                    }
                    if case == 3 {
                        return Err(DomainError::Conflict("candidate rejected".into()));
                    }
                    Ok(BatchDecision::Write { related: BTreeMap::from([(key, payload)]), audit: Some(Box::new(entry)) })
                },
                |entry| {
                    appended.fetch_add(1, Ordering::SeqCst);
                    Ok(entry)
                },
            )
            .await;
        assert!(result.is_err(), "case {case}");
        assert!(store.get::<u64>(tenant, "main", id).await.unwrap().is_none());
        assert!(store.get::<Value>(tenant, "archive", declared).await.unwrap().is_none());
    }
    let result = store
        .mutate_batch_audited::<u64, _, _>(
            tenant,
            mutation(id, &[declared, declared]),
            |_, _, _| panic!("duplicate keys reached apply"),
            |_| panic!("duplicate keys appended audit"),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(appended.load(Ordering::SeqCst), 0);
}
