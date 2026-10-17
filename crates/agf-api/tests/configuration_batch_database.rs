//! Real SQL batch audit failure rolls back the main and all declared related rows.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod integration_completion_support;
mod mse_inventory_sql_owner;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    ids::Id,
};
use agf_storage::configuration::{BatchDecision, BatchMutation, ConfigurationGuard};
use common::*;
use std::collections::BTreeMap;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn bounded_main_related_and_audit_share_one_transaction_and_noop_restores_original() {
    let case = mse_inventory_sql_owner::open("configuration-batch").await;
    let tenant = case.h.tenant;
    let main = Id::new();
    let related = Id::new();
    let guard = Id::new();
    case.h.state.configurations.put(tenant, "batch-main", main, &7_u64).await.unwrap();
    case.h.state.configurations.put(tenant, "batch-related", related, &"before").await.unwrap();
    case.h.state.configurations.put(tenant, "batch-source", guard, &3_u64).await.unwrap();
    let constraint =
        integration_completion_support::fault(&case.pool, tenant, "audit_logs", "target->>'kind'='bounded-batch-test'")
            .await;
    let before = case.audit_stats().await;
    let ids = [related];
    for attempt in 0..2 {
        let result = case
            .h
            .state
            .configurations
            .mutate_batch_audited(
                tenant,
                BatchMutation {
                    kind: "batch-main",
                    id: main,
                    guard: Some(ConfigurationGuard { kind: "batch-source", id: guard }),
                    related_kind: "batch-related",
                    related_ids: &ids,
                    max_main_bytes: 4096,
                    max_related_bytes: 1024,
                },
                |source, value: &mut u64, prior| {
                    assert_eq!(source, Some(json!(3)));
                    assert_eq!(prior[&related], Some(json!("before")));
                    *value = 8;
                    let entry = AppState::audit_entry(
                        tenant,
                        AuditAction::Update,
                        AuditOutcome::Success,
                        AuditActor::system("owned-sql-batch"),
                        AuditTarget::new("bounded-batch-test", Some(main.to_string()), None),
                        "Bounded main and related candidates",
                    );
                    Ok(BatchDecision::Write {
                        related: BTreeMap::from([(related, json!("after"))]),
                        audit: Some(Box::new(entry)),
                    })
                },
                |_| panic!("SQL invoked offline callback"),
            )
            .await;
        if attempt == 0 {
            assert!(result.is_err());
            assert_eq!(case.h.state.configurations.get::<u64>(tenant, "batch-main", main).await.unwrap(), Some(7));
            assert_eq!(
                case.h.state.configurations.get::<String>(tenant, "batch-related", related).await.unwrap(),
                Some("before".into())
            );
            assert_eq!(case.audit_stats().await, before);
            integration_completion_support::unfault(&case.pool, "audit_logs", &constraint).await;
        } else {
            let (value, sealed) = result.unwrap();
            assert_eq!(value, 8);
            assert!(sealed.unwrap().verify());
        }
    }
    let (value, sealed) = case
        .h
        .state
        .configurations
        .mutate_batch_audited(
            tenant,
            BatchMutation {
                kind: "batch-main",
                id: main,
                guard: None,
                related_kind: "batch-related",
                related_ids: &ids,
                max_main_bytes: 4096,
                max_related_bytes: 1024,
            },
            |_, value: &mut u64, _| {
                *value = 99;
                Ok(BatchDecision::Unchanged)
            },
            |_| panic!("SQL no-op invoked audit"),
        )
        .await
        .unwrap();
    assert_eq!(value, 8);
    assert!(sealed.is_none());
    assert_eq!(case.h.state.configurations.get::<u64>(tenant, "batch-main", main).await.unwrap(), Some(8));
    assert_eq!(
        case.h.state.configurations.get::<String>(tenant, "batch-related", related).await.unwrap(),
        Some("after".into())
    );
    assert_eq!(case.audit_stats().await.0, before.0 + 1);
    assert!(case.h.state.store.audit_verify_durable(tenant).await.unwrap().passed);
    case.pool.close().await;
}
