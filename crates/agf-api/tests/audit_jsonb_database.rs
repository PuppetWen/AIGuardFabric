//! Audit snapshots must hash exactly as PostgreSQL JSONB stores and reloads them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
use agf_core::audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget};
use common::*;
use configuration_audit_support::SqlCase;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn jsonb_snapshot_normalization_preserves_sql_null_and_sealed_readback() {
    let case = SqlCase::open("audit-jsonb-normalization").await;
    let nested: Value = serde_json::from_str(
        r#"{"version":1,"mocked":false,"run_id":null,"status":"succeeded",
            "nested":{"long_key":1.0,"a":[{"z":-0.0,"alphabet":1e20},null,1e-30]},
            "list":[{"zz":2.0,"b":true},[],{}]}"#,
    )
    .unwrap();
    let snapshots = [
        (None, None),
        (Some(Value::Null), Some(Value::Null)),
        (None, Some(nested.clone())),
        (Some(nested), Some(json!({"last":null,"a":[{"long":2.5,"x":0.0}]}))),
    ];
    for (index, (before, after)) in snapshots.into_iter().enumerate() {
        let mut entry = AppState::audit_entry(
            case.h.tenant,
            AuditAction::Execute,
            AuditOutcome::Success,
            AuditActor::system("owned-jsonb-regression"),
            AuditTarget::new("owned-jsonb-regression", Some(index.to_string()), None),
            "Synthetic JSONB snapshot regression",
        );
        entry.before = before.clone();
        entry.after = after.clone();
        let sealed = case.h.state.store.audit_append_durable(entry).await.unwrap();
        assert!(sealed.verify(), "SQL append must return the sealed stored representation");
        let rows = case.h.state.store.audit_chain_durable(case.h.tenant, sealed.sequence, 1).await.unwrap();
        assert_eq!(rows.len(), 1);
        let reloaded = &rows[0];
        assert_eq!(reloaded.id, sealed.id);
        assert!(
            reloaded.verify(),
            "reloaded JSONB payload must preserve the hash; fixture={index}; \
             sealed_before={:?}; read_before={:?}; sealed_after={:?}; read_after={:?}; \
             sealed_at={:?}; read_at={:?}; sealed_hash={}; read_hash={}; recomputed={}",
            sealed.before,
            reloaded.before,
            sealed.after,
            reloaded.after,
            sealed.at,
            reloaded.at,
            sealed.entry_hash,
            reloaded.entry_hash,
            reloaded.compute_hash(),
        );
        assert_eq!(serde_json::to_string(&reloaded.before).unwrap(), serde_json::to_string(&sealed.before).unwrap());
        assert_eq!(serde_json::to_string(&reloaded.after).unwrap(), serde_json::to_string(&sealed.after).unwrap());
        assert_eq!(reloaded.entry_hash, sealed.entry_hash);
        assert_eq!(reloaded.before.is_some(), before.is_some(), "JSON null must remain distinct from SQL null");
        assert_eq!(reloaded.after.is_some(), after.is_some(), "JSON null must remain distinct from SQL null");
        if index == 2 {
            assert_ne!(
                serde_json::to_string(&after).unwrap(),
                serde_json::to_string(&sealed.after).unwrap(),
                "fixture must exercise actual JSONB normalization rather than an already-normalized object"
            );
        }
    }
    let verification = case.h.state.store.audit_verify_durable(case.h.tenant).await.unwrap();
    assert!(verification.passed, "{verification:?}");
    case.pool.close().await;
}
