use super::{
    Client, Identity, Kind, identity,
    test_platform::{Behavior, KEY, Platform},
    types::{NativeState, Outcome},
};
use crate::{Partition, TenantId, tasks::ApiAuth};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::Instant;

fn identity(kind: Kind) -> Identity {
    Identity {
        kind,
        app: "123".into(),
        job: "42".into(),
        execution: "execution-42".into(),
        partition: Partition::default(),
    }
}
#[test]
fn permanent_request_identity_cannot_be_bypassed_by_alias_kind_or_changed_total() {
    let tenant = TenantId::default_tenant();
    let first = identity(Kind::AssetInventory);
    let mut changed = first.clone();
    changed.kind = Kind::LogPull;
    assert_eq!(first.request_id(tenant), changed.request_id(tenant));
    changed.partition.total = 2;
    assert_eq!(first.request_id(tenant), changed.request_id(tenant));
    changed.partition.index = 1;
    assert_ne!(first.request_id(tenant), changed.request_id(tenant));
    assert_eq!(Kind::parse("report"), Kind::parse("report-generate"));
    assert_eq!(Kind::parse("archive"), Kind::parse("cold-archive"));
    for bad in ["0", "01", "+1", "-1", "9223372036854775808", " 1"] {
        assert!(!identity::positive_id(bad));
    }
    for bad in ["", " leading", "trailing ", "secret\n", "a/b"] {
        assert!(!identity::valid_execution(bad));
    }
}
#[tokio::test]
async fn native_partial_binding_uses_selected_authenticated_job_and_rejects_unknown_or_foreign_proofs() {
    let platform = Platform::open(Behavior::Normal).await;
    let original = super::test_platform::native_dto(platform.data.tenant, &platform.data.source);
    let state: NativeState = serde_json::from_value(original.clone()).unwrap();
    // Aggregate current=false is deliberately independent of the selected job's eligibility.
    assert!(state.context(platform.data.tenant, &identity(Kind::AssetInventory), true).is_ok());
    for (path, replacement) in [
        ("/bindings/items/0/eligibility", json!("unverified")),
        ("/bindings/items/0/adoptedProof", Value::Null),
        ("/bindings/items/0/adoptedProof/jobId", json!("43")),
        ("/bindings/items/0/adoptedProof/enabled", json!(false)),
        ("/bindings/items/0/adoptedProof/sourceTarget/configurationVersion", json!(2)),
        ("/sourceTarget/mocked", json!(true)),
    ] {
        let mut bad = original.clone();
        *bad.pointer_mut(path).unwrap() = replacement;
        let state: NativeState = serde_json::from_value(bad).unwrap();
        assert!(
            state.context(platform.data.tenant, &identity(Kind::AssetInventory), true).is_err(),
            "rejected field: {path}"
        );
    }
    let state: NativeState = serde_json::from_value(original).unwrap();
    assert!(state.context(platform.data.tenant, &identity(Kind::AssetInventory), false).is_err());
}
#[tokio::test]
async fn actual_repeated_validate_and_status_never_return_a_second_start_grant() {
    let platform = Platform::open(Behavior::Normal).await;
    let client =
        Client::literal_loopback(&platform.origin, &ApiAuth::ApiKey(KEY.into()), platform.data.tenant).unwrap();
    assert!(!format!("{client:?}").contains(KEY));
    let deadline = Instant::now() + Duration::from_secs(5);
    let identity = identity(Kind::AssetInventory);
    let context = client.context(&identity, deadline).await.unwrap();
    let admission = client.claim(&identity, &context, deadline).await.unwrap();
    assert!(admission.may_confirm_start);
    assert!(!admission.may_execute);
    let first = client.validate(&admission, deadline).await.unwrap();
    assert!(first.may_execute);
    assert!(!first.may_confirm_start);
    let duplicate = client.validate(&admission, deadline).await.unwrap();
    assert!(!duplicate.may_execute && !duplicate.may_confirm_start);
    assert_eq!(first.started_at, duplicate.started_at);
    assert_eq!(first.execution_lease_expires_at, duplicate.execution_lease_expires_at);
    let status = client.status(&admission, deadline).await.unwrap();
    assert!(!status.may_execute && !status.may_confirm_start);
}
#[test]
fn safe_completion_rejects_paths_notes_unknown_fields_and_unbounded_artifacts() {
    let valid = json!({"ok":true,"skipped":false,"degraded":false,"artifacts":[]});
    for field in ["note", "path", "callback_token", "providerDiagnostic"] {
        let mut bad = valid.clone();
        bad[field] = json!("must-not-enter-protocol");
        assert!(serde_json::from_value::<Outcome>(bad).is_err());
    }
    let mut bad: Outcome = serde_json::from_value(valid).unwrap();
    bad.artifacts = vec![super::types::Artifact { sha256: "a".repeat(64), bytes: 0 }; 65];
    assert!(bad.check().is_err());
    bad.artifacts.truncate(1);
    bad.skipped = true;
    assert!(bad.check().is_err());
}
