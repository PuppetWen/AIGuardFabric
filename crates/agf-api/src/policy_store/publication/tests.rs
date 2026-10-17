//! Selecting a subset must still authenticate the entire durable registry and every dependency.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use serde_json::json;

fn state() -> AppState {
    let mut env: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_JWT_SECRET", "publication-unit-owned-secret-at-least-32-bytes"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_PROJECT_ROOT", "."),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    let data = std::env::var_os("AGF_TEST_DATA_DIR").map_or_else(
        || std::path::PathBuf::from("./target/test-data/publication-selection"),
        |root| std::path::PathBuf::from(root).join("publication-selection"),
    );
    env.insert("AGF_DATA_DIR".into(), data.to_string_lossy().into_owned());
    AppState::offline(agf_core::config::from_env_map(&env).unwrap()).unwrap()
}

fn policy(state: &AppState, name: &str) -> Policy {
    let now = Timestamp::now();
    let mut row: Policy = serde_json::from_value(json!({
        "id":Id::new(),"tenant_id":TenantId::default_tenant(),"name":name,
        "language":"cel","source":"{}","action":"deny","priority":1,
        "enabled":true,"content_hash":"","signature":"","version":1,
        "created_at":now,"updated_at":now,"intercept_points":["mcp-proxy"]
    }))
    .unwrap();
    sign(state, &mut row);
    row
}
fn sign(state: &AppState, row: &mut Policy) {
    row.content_hash = row.compute_hash();
    row.signature = signer(state).unwrap().sign(row);
}
fn registry(policies: &[Policy]) -> Value {
    let entries = policies.iter().map(|row| (row.id.to_string(), serde_json::to_value(row).unwrap())).collect();
    json!({"initialized":true,"entries":Value::Object(entries),"history":{}})
}
fn selected(state: &AppState, policies: &[Policy]) -> TrustedPolicySelection {
    let expected = policies.iter().map(|row| (row.id, row.version)).collect();
    parse_publication_snapshot(state, TenantId::default_tenant(), Some(registry(policies)), &expected).unwrap()
}

#[tokio::test]
async fn absent_durable_snapshot_never_initializes_from_demo_or_memory() {
    let state = state();
    let tenant = TenantId::default_tenant();
    let expected = BTreeMap::from([(Id::new(), 1)]);
    assert!(matches!(
        parse_publication_snapshot(&state, tenant, None, &expected),
        Err(DomainError::PreconditionFailed(_))
    ));
    assert!(state.configurations.get::<Value>(tenant, KIND, tenant_record_id(tenant)).await.unwrap().is_none());
}

#[tokio::test]
async fn selection_is_canonical_and_fences_the_exact_current_revision() {
    let state = state();
    let rows = [policy(&state, "owned-b"), policy(&state, "owned-a")];
    let selection = selected(&state, &rows);
    assert!(selection.policies.windows(2).all(|pair| pair[0].id < pair[1].id));
    let expected = BTreeMap::from([(rows[0].id, 2)]);
    assert!(matches!(
        parse_publication_snapshot(&state, rows[0].tenant_id, Some(registry(&rows)), &expected),
        Err(DomainError::Conflict(_))
    ));
}

#[tokio::test]
async fn a_valid_disabled_policy_can_be_saved_but_cannot_be_selected_for_cloud_publication() {
    let state = state();
    let mut row = policy(&state, "owned-disabled-policy");
    row.enabled = false;
    sign(&state, &mut row);
    validation::candidate(&row, row.tenant_id).unwrap();
    assert!(matches!(
        parse_publication_snapshot(
            &state,
            row.tenant_id,
            Some(registry(&[row.clone()])),
            &BTreeMap::from([(row.id, row.version)])
        ),
        Err(DomainError::PreconditionFailed(_))
    ));
    row.enabled = true;
    sign(&state, &mut row);
    assert_eq!(selected(&state, &[row]).policies.len(), 1);
}

#[tokio::test]
async fn an_unselected_corrupt_policy_or_wrongly_nested_signed_history_is_rejected() {
    let state = state();
    let selected_row = policy(&state, "selected");
    let mut other = policy(&state, "unselected");
    let expected = BTreeMap::from([(selected_row.id, 1)]);
    other.source = "tampered".into();
    assert!(
        parse_publication_snapshot(
            &state,
            selected_row.tenant_id,
            Some(registry(&[selected_row.clone(), other])),
            &expected
        )
        .is_err()
    );
    let mut current = selected_row.clone();
    current.version = 2;
    sign(&state, &mut current);
    let mut raw = registry(&[current]);
    raw["history"][selected_row.id.to_string()] = json!([policy(&state, "wrong-identity")]);
    assert!(
        parse_publication_snapshot(&state, selected_row.tenant_id, Some(raw), &BTreeMap::from([(selected_row.id, 2)]))
            .is_err()
    );
}

#[tokio::test]
async fn agent_scope_is_rejected_above_aggregate_limit_without_truncation() {
    let state = state();
    let mut row = policy(&state, "too-many-agents");
    row.scope_agent_ids = (0..501).map(|_| Id::new()).collect();
    sign(&state, &mut row);
    assert!(matches!(
        parse_publication_snapshot(
            &state,
            row.tenant_id,
            Some(registry(&[row.clone()])),
            &BTreeMap::from([(row.id, 1)])
        ),
        Err(DomainError::PreconditionFailed(_))
    ));
    assert_eq!(row.scope_agent_ids.len(), 501);
}

#[tokio::test]
async fn every_distinct_quota_is_checked_even_when_they_share_one_registry_guard() {
    let state = state();
    let tenant = TenantId::default_tenant();
    let mut policies = [policy(&state, "quota-a"), policy(&state, "quota-b")];
    let quota_a = Id::new();
    let quota_b = Id::new();
    for (row, id) in policies.iter_mut().zip([quota_a, quota_b]) {
        row.quota_id = Some(id);
        sign(&state, row);
    }
    let selection = selected(&state, &policies);
    assert_eq!(selection.guards.len(), 1);
    let quota = |id, name, enabled| {
        json!({
            "id":id,"tenant_id":tenant,"name":name,"scope":"tenant","dimension":"tokens",
            "window":"day","limit":100,"on_exceed":"deny","enabled":enabled,
            "created_at":Timestamp::now(),"updated_at":Timestamp::now()
        })
    };
    let mut payload = json!({"initialized":true,"entries":{
        "a":quota(quota_a,"a",true),"b":quota(quota_b,"b",false)
    },"versions":{"a":1,"b":2}});
    let key = (crate::quota_definitions::KIND.to_owned(), tenant_record_id(tenant));
    let invalid = BTreeMap::from([(key.clone(), Some(payload.clone()))]);
    assert!(validate_publication_dependencies(tenant, &selection, &invalid, &BTreeMap::new()).is_err());
    payload["entries"]["b"]["enabled"] = json!(true);
    let valid = BTreeMap::from([(key, Some(payload))]);
    let evidence = validate_publication_dependencies(tenant, &selection, &valid, &BTreeMap::new()).unwrap();
    assert_eq!(evidence.len(), 2);
    assert!(evidence.iter().any(|row| row.id == quota_a && row.version == Some(1)));
    assert!(evidence.iter().any(|row| row.id == quota_b && row.version == Some(2)));
    assert!(evidence.iter().all(|row| row.fingerprint.len() == 64));
}

#[tokio::test]
async fn selected_agent_dependency_must_remain_live_and_in_the_same_tenant() {
    let state = state();
    let tenant = TenantId::default_tenant();
    let mut asset = Asset::new(tenant, agf_core::enums::AssetKind::Agent, "owned-agent", "owned-agent");
    let mut row = policy(&state, "agent-scoped");
    row.scope_agent_ids = vec![asset.id];
    sign(&state, &mut row);
    let selection = selected(&state, &[row]);
    let assets = BTreeMap::from([(asset.id, asset.clone())]);
    let evidence = validate_publication_dependencies(tenant, &selection, &BTreeMap::new(), &assets).unwrap();
    assert_eq!(evidence.len(), 1);
    asset.tenant_id = TenantId::new();
    assert!(
        validate_publication_dependencies(tenant, &selection, &BTreeMap::new(), &BTreeMap::from([(asset.id, asset)]))
            .is_err()
    );
}
