//! Conditional no-ops and failed audits must not publish a candidate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget};
use agf_core::time::Timestamp;
use std::sync::atomic::{AtomicUsize, Ordering};

fn audit(tenant: TenantId) -> AuditLog {
    AuditLog {
        id: Id::new(),
        tenant_id: tenant,
        sequence: 0,
        action: AuditAction::Execute,
        outcome: AuditOutcome::Success,
        actor: AuditActor::system("conditional-test"),
        target: AuditTarget::new("test", None, None),
        before: None,
        after: None,
        changed_fields: Vec::new(),
        request_id: None,
        error: None,
        note: "conditional test".into(),
        prev_hash: String::new(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    }
}

fn mutation(id: Id, guard: Option<Id>) -> ConditionalMutation<'static> {
    ConditionalMutation { kind: "result", id, guard: guard.map(|id| ConfigurationGuard { kind: "source", id }) }
}

#[tokio::test]
async fn offline_noop_returns_published_value_without_audit_or_candidate_write() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    store.put(tenant, "result", id, &7_u64).await.unwrap();
    let (value, audit) = store
        .mutate_conditional_audited(
            tenant,
            mutation(id, None),
            |_, value: &mut u64| {
                *value = 99;
                Ok(MutationDecision::Unchanged)
            },
            |_| panic!("no-op appended audit"),
        )
        .await
        .unwrap();
    assert_eq!(value, 7);
    assert!(audit.is_none());
    assert_eq!(store.get::<u64>(tenant, "result", id).await.unwrap(), Some(7));
    let new_id = Id::new();
    store
        .mutate_conditional_audited::<u64, _, _>(
            tenant,
            mutation(new_id, None),
            |_, _| Ok(MutationDecision::Unchanged),
            |_| panic!("missing no-op appended audit"),
        )
        .await
        .unwrap();
    assert_eq!(store.get::<u64>(tenant, "result", new_id).await.unwrap(), None);
}

#[tokio::test]
async fn offline_guard_and_audit_failure_preserve_previous_report() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let source = Id::new();
    store.put(tenant, "source", source, &3_u64).await.unwrap();
    store.put(tenant, "result", id, &8_u64).await.unwrap();
    let result = store
        .mutate_conditional_audited(
            tenant,
            mutation(id, Some(source)),
            |guard, value: &mut u64| {
                assert_eq!(guard, Some(Value::from(3)));
                *value = 9;
                Ok(MutationDecision::Write(Some(Box::new(audit(tenant)))))
            },
            |_| Err(DomainError::Internal("intentional audit rejection".into())),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(store.get::<u64>(tenant, "result", id).await.unwrap(), Some(8));
    let appended = AtomicUsize::new(0);
    let foreign = TenantId::new();
    let result = store
        .mutate_conditional_audited::<u64, _, _>(
            foreign,
            mutation(id, Some(source)),
            |guard, _| {
                assert!(guard.is_none());
                Err(DomainError::Conflict("source unavailable in foreign tenant".into()))
            },
            |_| {
                appended.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            },
        )
        .await;
    assert!(result.is_err());
    assert_eq!(appended.load(Ordering::SeqCst), 0);
    assert_eq!(store.get::<u64>(foreign, "result", id).await.unwrap(), None);
}

#[tokio::test]
async fn offline_completed_revision_audits_once_after_repeated_publication() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let appended = AtomicUsize::new(0);
    for attempt in 0..3 {
        let (value, _) = store
            .mutate_conditional_audited(
                tenant,
                mutation(id, None),
                |_, value: &mut bool| {
                    if *value {
                        return Ok(MutationDecision::Unchanged);
                    }
                    *value = true;
                    Ok(MutationDecision::Write(Some(Box::new(audit(tenant)))))
                },
                |audit| {
                    appended.fetch_add(1, Ordering::SeqCst);
                    Ok(Some(audit))
                },
            )
            .await
            .unwrap();
        assert!(value);
        assert_eq!(appended.load(Ordering::SeqCst), 1, "attempt {attempt}");
    }
}
