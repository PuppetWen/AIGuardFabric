#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;

fn policy() -> ModelRoutePolicy {
    ModelRoutePolicy {
        version: 1,
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "owned-route".into(),
        primary_endpoint_id: Id::new().to_string(),
        fallback_endpoint_ids: Vec::new(),
        strategy: "priority".into(),
        weights: BTreeMap::new(),
        budget_cny_per_day: 0.0,
        enabled: true,
    }
}
#[test]
fn cas_accepts_version_zero_seed_but_never_overrides_persisted_current() {
    let mut seed = policy();
    seed.version = 0;
    assert!(compare(None, Some(&seed), 0).is_ok());
    let current = policy();
    assert!(compare(Some(&current), Some(&seed), 0).is_err());
    assert!(compare(Some(&current), Some(&seed), 1).is_ok());
    assert!(compare(None, None, 1).is_err());
}
#[test]
fn candidate_version_cannot_wrap_or_silently_replace() {
    let mut row = policy();
    assert!(validation::candidate(&row, row.tenant_id, 0).is_ok());
    assert!(validation::candidate(&row, row.tenant_id, 1).is_err());
    row.version = 0;
    assert!(validation::candidate(&row, row.tenant_id, u64::MAX).is_err());
}
#[test]
fn stored_policy_tenant_and_record_id_are_checked_before_cas() {
    let row = policy();
    assert!(validation::identity(&row, TenantId::from_uuid(Id::new().as_uuid()), row.id).is_err());
    assert!(validation::identity(&row, row.tenant_id, Id::new()).is_err());
}
#[test]
fn all_thirty_three_endpoint_prerequisites_are_retained_and_only_duplicates_are_removed() {
    let mut row = policy();
    row.fallback_endpoint_ids = (0..32).map(|_| Id::new().to_string()).collect();
    assert!(validation::candidate(&row, row.tenant_id, 0).is_ok());
    assert_eq!(validation::keys(&row).unwrap().len(), 33);
    row.fallback_endpoint_ids[0] = row.primary_endpoint_id.clone();
    assert_eq!(validation::keys(&row).unwrap().len(), 32);
    row.fallback_endpoint_ids.push(Id::new().to_string());
    assert!(validation::candidate(&row, row.tenant_id, 0).is_err());
}
#[test]
fn disabling_a_legacy_route_does_not_require_an_endpoint_that_has_been_removed() {
    let mut row = policy();
    row.enabled = false;
    row.primary_endpoint_id = "removed-legacy-endpoint".into();
    assert!(validation::keys(&row).unwrap().is_empty());
    assert!(validation::references(&row, &Rows::new()).is_ok());
    row.enabled = true;
    assert!(validation::keys(&row).is_err());
}
#[test]
fn encoded_payload_budget_counts_escaping_instead_of_raw_string_length() {
    let mut row = policy();
    row.enabled = false;
    row.name = "\0".repeat(12 * 1024);
    assert!(row.name.len() < MAX_POLICY_BYTES);
    assert!(serde_json::to_vec(&row).unwrap().len() > MAX_POLICY_BYTES);
    // Use a genuine AuditLog shape; its contents are immaterial to the main-payload limit.
    let log = AppState::audit_entry(
        row.tenant_id,
        AuditAction::Configure,
        AuditOutcome::Success,
        agf_core::audit::AuditActor::system("owned-budget-test"),
        AuditTarget::new(super::super::KIND, Some(row.id.to_string()), None),
        "",
    );
    assert!(serialized_budget(&row, &log).is_err());
    row.name = "\0".repeat(1024);
    assert!(serialized_budget(&row, &log).is_ok());
}
