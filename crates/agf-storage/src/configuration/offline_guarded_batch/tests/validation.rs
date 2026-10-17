//! Bounds and invalid declarations fail before either callback; database mode is unsupported.
use super::*;

#[test]
fn invalid_keys_bounds_and_authority_ids_are_rejected_before_callbacks() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let nil = Id::nil();
    let guards = (0..33).map(|_| ConfigurationGuard { kind: "guard", id: Id::new() }).collect::<Vec<_>>();
    let related = (0..101).map(|_| ConfigurationGuard { kind: "related", id: Id::new() }).collect::<Vec<_>>();
    let duplicate = [ConfigurationGuard { kind: "dependency", id }, ConfigurationGuard { kind: "dependency", id }];
    let overlap = [ConfigurationGuard { kind: "test", id }];
    let same = [ConfigurationGuard { kind: "dependency", id }];
    let reserved = [ConfigurationGuard { kind: MFA, id }];
    let empty = [ConfigurationGuard { kind: "", id }];
    let nil_key = [ConfigurationGuard { kind: "dependency", id: nil }];
    let requests = vec![
        OfflineGuardedBatch { kind: "", ..request(id) },
        OfflineGuardedBatch { kind: DIRECTORY, ..request(id) },
        request(nil),
        OfflineGuardedBatch { guards: &guards, ..request(id) },
        OfflineGuardedBatch { related: &related, ..request(id) },
        OfflineGuardedBatch { guards: &duplicate, ..request(id) },
        OfflineGuardedBatch { related: &duplicate, ..request(id) },
        OfflineGuardedBatch { guards: &overlap, ..request(id) },
        OfflineGuardedBatch { related: &overlap, ..request(id) },
        OfflineGuardedBatch { guards: &same, related: &same, ..request(id) },
        OfflineGuardedBatch { guards: &reserved, ..request(id) },
        OfflineGuardedBatch { related: &reserved, ..request(id) },
        OfflineGuardedBatch { guards: &empty, ..request(id) },
        OfflineGuardedBatch { related: &nil_key, ..request(id) },
        OfflineGuardedBatch { max_main_bytes: 0, ..request(id) },
        OfflineGuardedBatch { max_main_bytes: 4 * 1024 * 1024 + 1, ..request(id) },
        OfflineGuardedBatch { max_related_bytes: 0, ..request(id) },
        OfflineGuardedBatch { max_related_bytes: 1024 * 1024 + 1, ..request(id) },
        OfflineGuardedBatch { max_total_write_bytes: 0, ..request(id) },
        OfflineGuardedBatch { max_total_write_bytes: 8 * 1024 * 1024 + 1, ..request(id) },
        OfflineGuardedBatch {
            security: Some(OfflineSecurityRecords { identity_tenant: tenant, subject_id: nil }),
            ..request(id)
        },
        OfflineGuardedBatch {
            security: Some(OfflineSecurityRecords { identity_tenant: TenantId::from_id(nil), subject_id: id }),
            ..request(id)
        },
    ];
    for options in requests {
        let result = store.mutate_offline_guarded_batch_audited(
            tenant,
            options,
            |_, _: &mut u64, _| panic!("invalid declaration reached apply"),
            |_, _| panic!("invalid declaration reached audit"),
        );
        assert!(matches!(result, Err(DomainError::Validation(_))));
    }
    let result = store.mutate_offline_guarded_batch_audited(
        TenantId::from_id(nil),
        request(id),
        |_, _: &mut u64, _| panic!("nil tenant reached apply"),
        |_, _| panic!("nil tenant reached audit"),
    );
    assert!(matches!(result, Err(DomainError::Validation(_))));
    assert!(store.memory.lock().unwrap().is_empty());
}

#[tokio::test]
async fn main_related_and_full_write_budgets_preserve_originals_and_do_not_audit() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let child = Id::new();
    store.put(tenant, "test", id, &Value::from("old")).await.unwrap();
    store.put(tenant, "related", child, &Value::from("old child")).await.unwrap();
    let before = store.memory.lock().unwrap().clone();
    let related = [ConfigurationGuard { kind: "related", id: child }];
    for failure in ["main", "related", "batch-delete", "batch-audit"] {
        let options = OfflineGuardedBatch {
            related: &related,
            max_main_bytes: if failure == "main" { 3 } else { 1024 },
            max_related_bytes: if failure == "related" { 3 } else { 1024 },
            max_total_write_bytes: if failure.starts_with("batch") { 1024 } else { 4096 },
            ..request(id)
        };
        let result = store.mutate_offline_guarded_batch_audited(
            tenant,
            options,
            |_, main: &mut Value, _| {
                *main = Value::from("new main");
                let value = if failure == "batch-delete" { None } else { Some(Value::from("new child")) };
                let mut audit = entry(tenant);
                if failure.starts_with("batch") {
                    audit.note = "a".repeat(1024);
                }
                Ok(GuardedBatchDecision::Write {
                    related: BTreeMap::from([(("related".into(), child), value)]),
                    audit: Box::new(audit),
                })
            },
            |_, _| panic!("oversized batch must not append an audit"),
        );
        assert!(matches!(result, Err(DomainError::PreconditionFailed(_))), "{failure}");
        assert_eq!(*store.memory.lock().unwrap(), before, "{failure}");
    }
}

#[tokio::test]
async fn deletion_markers_and_record_keys_consume_the_total_budget() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    let related = (0..100).map(|_| ConfigurationGuard { kind: "related", id: Id::new() }).collect::<Vec<_>>();
    for target in &related {
        store.put(tenant, "related", target.id, &9_u64).await.unwrap();
    }
    let audit = entry(tenant);
    let before = store.memory.lock().unwrap().clone();
    // All deleted payloads contribute zero body bytes. Their 100 complete keys and
    // deletion instructions still exceed this budget; a single removal fits it.
    for count in [100, 1] {
        let result = store.mutate_offline_guarded_batch_audited(
            tenant,
            OfflineGuardedBatch { related: &related, max_total_write_bytes: 4096, ..request(id) },
            |_, value: &mut u64, _| {
                *value = 2;
                Ok(GuardedBatchDecision::Write {
                    related: related.iter().take(count).map(|target| (("related".into(), target.id), None)).collect(),
                    audit: Box::new(audit.clone()),
                })
            },
            |audit, _| Ok(seal(audit)),
        );
        if count == 100 {
            assert!(matches!(result, Err(DomainError::PreconditionFailed(_))));
            assert_eq!(*store.memory.lock().unwrap(), before);
        } else {
            assert!(result.unwrap().1.unwrap().verify());
            assert_eq!(store.get::<u64>(tenant, "test", id).await.unwrap(), Some(2));
            assert_eq!(store.get::<u64>(tenant, "related", related[0].id).await.unwrap(), None);
            assert_eq!(store.list::<u64>(tenant, "related").await.unwrap().len(), 99);
        }
    }
}

#[tokio::test]
async fn maximum_sealed_audit_size_is_reserved_before_appending() {
    let store = ConfigStore::new(None);
    let tenant = TenantId::new();
    let id = Id::new();
    store.put(tenant, "test", id, &1_u64).await.unwrap();
    let original = store.memory.lock().unwrap().clone();
    let audit = entry(tenant);
    let plan = json!([{"tenant":tenant,"kind":"test","id":id,"delete":false,"payload":2}]);
    let raw_bytes = serde_json::to_vec(&(&plan, &audit)).unwrap().len();
    let mut maximum = audit.clone();
    maximum.sequence = i64::MAX;
    maximum.prev_hash = agf_core::audit::GENESIS_HASH.into();
    maximum.entry_hash = "0".repeat(64);
    let maximum_bytes = serde_json::to_vec(&(&plan, &maximum)).unwrap().len();
    assert!(raw_bytes + 1 < maximum_bytes);
    let appends = AtomicUsize::new(0);
    for bound in [raw_bytes + 1, maximum_bytes] {
        let result = store.mutate_offline_guarded_batch_audited(
            tenant,
            OfflineGuardedBatch { max_total_write_bytes: bound, ..request(id) },
            |_, main: &mut u64, _| {
                *main = 2;
                Ok(GuardedBatchDecision::Write { related: BTreeMap::new(), audit: Box::new(audit.clone()) })
            },
            |mut audit, _| {
                audit.sequence = i64::MAX;
                audit.prev_hash = agf_core::audit::GENESIS_HASH.into();
                audit.seal();
                appends.fetch_add(1, Ordering::SeqCst);
                Ok(audit)
            },
        );
        if bound < maximum_bytes {
            assert!(matches!(result, Err(DomainError::PreconditionFailed(_))));
            assert_eq!(appends.load(Ordering::SeqCst), 0);
            assert_eq!(*store.memory.lock().unwrap(), original);
        } else {
            let (value, sealed) = result.unwrap();
            let sealed = sealed.unwrap();
            assert_eq!(value, 2);
            assert!(sealed.verify());
            assert_eq!(serde_json::to_vec(&(&plan, &sealed)).unwrap().len(), bound);
            assert_eq!(appends.load(Ordering::SeqCst), 1);
            assert_eq!(store.get::<u64>(tenant, "test", id).await.unwrap(), Some(2));
        }
    }
}

#[tokio::test]
async fn database_mode_is_rejected_before_apply_and_without_acquiring_a_connection() {
    let pool = sqlx::postgres::PgPoolOptions::new().min_connections(0).connect_lazy_with(
        sqlx::postgres::PgConnectOptions::new().host("127.0.0.1").port(1).database("unused").username("unused"),
    );
    let db = crate::Database::from_pool(pool.clone());
    let objects = Arc::new(crate::objectstore::MemoryObjectStore::new());
    let store = ConfigStore::new(Some(Arc::new(crate::Store::new(db, None, objects))));
    let result = store.mutate_offline_guarded_batch_audited(
        TenantId::new(),
        request(Id::new()),
        |_, _: &mut u64, _| panic!("database mode reached apply"),
        |_, _| panic!("database mode reached audit"),
    );
    assert!(matches!(result, Err(DomainError::PreconditionFailed(_))));
    assert_eq!(pool.size(), 0);
    assert!(store.memory.lock().unwrap().is_empty());
    pool.close().await;
}
