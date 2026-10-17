//! Failure paths must not publish a candidate or a successful audit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    time::Timestamp,
};
use serde::Deserialize;
use std::sync::atomic::{AtomicUsize, Ordering};

fn entry(tenant: TenantId) -> AuditLog {
    AuditLog {
        id: Id::new(),
        tenant_id: tenant,
        sequence: 0,
        action: AuditAction::Update,
        outcome: AuditOutcome::Success,
        actor: AuditActor::system("offline-guarded-test"),
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
fn request(id: Id) -> OfflineGuardedMutation<'static> {
    OfflineGuardedMutation { kind: "test", id, guards: &[], security: None }
}

#[derive(Default, Deserialize)]
struct CannotSerialize;
impl Serialize for CannotSerialize {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("intentional candidate serialization failure"))
    }
}

#[tokio::test]
async fn candidate_and_audit_failures_preserve_the_exact_record() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    store.put(tenant, "test", id, &7_u64).await.unwrap();
    let audits = AtomicUsize::new(0);
    let sink = |mut audit: AuditLog, _: &OfflineGuardedSnapshot| {
        audit.seal();
        audits.fetch_add(1, Ordering::SeqCst);
        Ok(audit)
    };
    let result = store.mutate_offline_guarded_audited(
        tenant,
        request(id),
        |_, value: &mut u64| {
            *value = 99;
            Err::<((), AuditLog), _>(DomainError::Conflict("stale".into()))
        },
        sink,
    );
    assert!(result.is_err());
    let result = store.mutate_offline_guarded_audited(
        tenant,
        request(Id::new()),
        |_, _: &mut CannotSerialize| Ok(((), entry(tenant))),
        sink,
    );
    assert!(result.is_err());
    let result = store.mutate_offline_guarded_audited(
        tenant,
        request(id),
        |_, value: &mut u64| {
            *value = 99;
            Ok(((), entry(TenantId::new())))
        },
        sink,
    );
    assert!(matches!(result, Err(DomainError::TenantViolation { .. })));
    let result = store.mutate_offline_guarded_audited(
        tenant,
        request(id),
        |_, value: &mut u64| {
            *value = 99;
            Ok(((), entry(tenant)))
        },
        |_, _| Err(DomainError::Internal("trusted audit sink refused without appending".into())),
    );
    assert!(result.is_err());
    assert_eq!(audits.load(Ordering::SeqCst), 0);
    assert_eq!(store.get::<u64>(tenant, "test", id).await.unwrap(), Some(7));
    assert_eq!(store.list::<u64>(tenant, "test").await.unwrap(), vec![7]);
    let (_, result, sealed) = store
        .mutate_offline_guarded_audited(
            tenant,
            request(id),
            |_, value: &mut u64| {
                *value = 8;
                Ok(("published", entry(tenant)))
            },
            sink,
        )
        .unwrap();
    assert_eq!(result, "published");
    assert!(sealed.verify());
    assert_eq!(audits.load(Ordering::SeqCst), 1);
    assert_eq!(store.get::<u64>(tenant, "test", id).await.unwrap(), Some(8));
}

#[tokio::test]
async fn only_declared_tenant_local_guards_and_fixed_authority_keys_are_read() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let other = TenantId::new();
    let id = Id::new();
    let subject = Id::new();
    let identity = TenantId::default_tenant();
    for (owner, kind, key, value) in [
        (tenant, "dependency", id, 1),
        (other, "dependency", id, 2),
        (identity, DIRECTORY, Id::from_uuid(identity.as_uuid()), 3),
        (other, DIRECTORY, Id::from_uuid(identity.as_uuid()), 30),
        (identity, PASSWORD_POLICY, Id::from_uuid(identity.as_uuid()), 4),
        (tenant, PASSWORD_POLICY, Id::from_uuid(identity.as_uuid()), 40),
        (identity, MFA, subject, 5),
        (tenant, MFA, subject, 50),
    ] {
        store.put(owner, kind, key, &value).await.unwrap();
    }
    let guards = [ConfigurationGuard { kind: "dependency", id }, ConfigurationGuard { kind: "absent", id }];
    let mutation = OfflineGuardedMutation {
        kind: "test",
        id: Id::new(),
        guards: &guards,
        security: Some(OfflineSecurityRecords { identity_tenant: identity, subject_id: subject }),
    };
    store
        .mutate_offline_guarded_audited(
            tenant,
            mutation,
            |snapshot, value: &mut u64| {
                assert_eq!(snapshot.guards.len(), 2);
                assert_eq!(snapshot.guards[&("dependency".into(), id)], Some(Value::from(1)));
                assert_eq!(snapshot.guards[&("absent".into(), id)], None);
                assert_eq!(snapshot.tenant_directory, Some(Value::from(3)));
                assert_eq!(snapshot.password_policy, Some(Value::from(4)));
                assert_eq!(snapshot.mfa_enrollment, Some(Value::from(5)));
                *value = 9;
                Ok(((), entry(tenant)))
            },
            |mut audit, _| {
                audit.seal();
                Ok(audit)
            },
        )
        .unwrap();
}

#[test]
fn duplicate_reserved_and_overlapping_business_keys_are_rejected_before_callbacks() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let sets = vec![
        vec![ConfigurationGuard { kind: "dependency", id }, ConfigurationGuard { kind: "dependency", id }],
        vec![ConfigurationGuard { kind: MFA, id }],
        vec![ConfigurationGuard { kind: "test", id }],
        vec![
            ConfigurationGuard { kind: "a", id },
            ConfigurationGuard { kind: "b", id },
            ConfigurationGuard { kind: "c", id },
        ],
    ];
    for guards in sets {
        let result = store.mutate_offline_guarded_audited(
            tenant,
            OfflineGuardedMutation { kind: "test", id, guards: &guards, security: None },
            |_, _: &mut u64| -> DomainResult<((), AuditLog)> { panic!("invalid keys must not reach apply") },
            |_, _| panic!("invalid keys must not reach audit"),
        );
        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
}
