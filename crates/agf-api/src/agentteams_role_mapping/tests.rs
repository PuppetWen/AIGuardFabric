#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::cloud_inventory::Snapshot;
use agf_core::{
    credential::{KeyBackend, SecretMaterial},
    enums::{AssetKind, DataClass},
    rbac::Role,
};

fn role(tenant: TenantId) -> RoleEntry {
    let definitions = Role::builtin_definitions();
    let (_, display, _, permissions) = definitions.iter().find(|(name, _, _, _)| *name == "viewer").unwrap();
    RoleEntry {
        id: Id::new(),
        tenant_id: tenant,
        name: "viewer".into(),
        display_name: (*display).into(),
        permissions: permissions.iter().map(|permission| Permission::from_raw(*permission)).collect(),
        builtin: true,
    }
}
fn fixture() -> (TenantId, Asset, crate::integration_store::Stored, Snapshot, RoleEntry, model::Record, ApiKey) {
    let tenant = TenantId::new();
    let mut asset = Asset::new(tenant, AssetKind::Agent, "worker", "agentteams:owned-worker");
    asset.attributes.insert(MARKER.into(), json!(true));
    let cfg = crate::integration_store::Stored {
        id: crate::integration_store::id(tenant, crate::cloud_inventory::NAME),
        name: crate::cloud_inventory::NAME.into(),
        enabled: true,
        mock: true,
        version: 1,
        updated_at: Timestamp::now(),
        private: SecretMaterial {
            backend: KeyBackend::LocalFile,
            key_id: "fixture".into(),
            ciphertext_b64: String::new(),
            nonce_b64: String::new(),
            tag_b64: None,
            plaintext_len: 0,
            encrypted_at: Timestamp::now(),
            aad: None,
        },
    };
    let snapshot = Snapshot {
        version: 1,
        mocked: true,
        checked_at: Timestamp::now(),
        region: "cn-hangzhou".into(),
        instance_id: "inst-owned".into(),
        teams: vec![json!({"InstanceId":"inst-owned","Name":"team","WorkerNames":["worker"]})],
        workers: vec![
            json!({"InstanceId":"inst-owned","Name":"worker","Groups":[{"Type":"team","Name":"team","Role":"member"}]}),
        ],
        tasks: BTreeMap::new(),
        assets: BTreeMap::from([("worker".into(), asset.id)]),
    };
    let role = role(tenant);
    let change = model::Change::Adopt {
        configuration_version: 1,
        observed_at: snapshot.checked_at,
        worker_name: "worker".into(),
        team_name: "team".into(),
        cloud_role: "member".into(),
        role_id: role.id,
    };
    let proof = proof::adopt(tenant, &cfg, &snapshot, &asset, &role, &change, true).unwrap();
    let record = model::Record {
        tenant,
        asset_id: asset.id,
        version: 1,
        governed: true,
        eligibility: model::Eligibility::Eligible,
        reason: None,
        proof,
        updated_at: Timestamp::now(),
    };
    let key = ApiKey {
        id: Id::new(),
        tenant_id: tenant,
        name: "synthetic".into(),
        prefix: "agf_test".into(),
        key_fingerprint: String::new(),
        scopes: vec![Permission::from_raw("*")],
        bound_agent_id: Some(asset.id),
        expires_at: None,
        last_used_at: None,
        allowed_cidrs: vec![],
        revoked: false,
        created_at: Timestamp::now(),
    };
    (tenant, asset, cfg, snapshot, role, record, key)
}
fn state() -> AppState {
    let env: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_JWT_SECRET", "owned-role-mapping-unit-key-at-least-32-bytes"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    AppState::offline(agf_core::config::from_env_map(&env).unwrap()).unwrap()
}

#[test]
fn scope_intersection_cannot_expand_either_wildcard_or_specific_grants() {
    let own = [Permission::from_raw("assets:*"), Permission::from_raw("models:execute")];
    let role = [Permission::from_raw("assets:read"), Permission::from_raw("reports:read")];
    let combined = authority::intersection(&own, &role);
    assert_eq!(combined, vec![Permission::from_raw("assets:read")]);
    for group in ["assets", "models", "reports", "platform"] {
        for action in ["read", "write", "delete", "execute", "admin"] {
            let required = Permission::new(group, action);
            if combined.iter().any(|scope| scope.matches(&required)) {
                assert!(own.iter().any(|scope| scope.matches(&required)));
                assert!(role.iter().any(|scope| scope.matches(&required)));
            }
        }
    }
    assert_eq!(
        authority::intersection(&[Permission::from_raw("assets:read")], &[Permission::from_raw("*")]),
        vec![Permission::from_raw("assets:read")]
    );
}

#[test]
fn displayed_mapping_qualification_uses_current_authority_not_hint_or_stored_eligibility_alone() {
    let (tenant, mut asset, cfg, snapshot, role, mut row, _) = fixture();
    assert!(views::qualified(&row, tenant, Some(&cfg), Some(&snapshot), Some(&asset), Some(&role), true));
    assert_eq!(views::record(&row)["currentQualified"], Value::Null);
    asset.department = Some("another-department".into());
    assert!(!views::qualified(&row, tenant, Some(&cfg), Some(&snapshot), Some(&asset), Some(&role), true));
    asset.department = row.proof.agent.department.clone();
    row.eligibility = model::Eligibility::Disabled;
    assert!(!views::qualified(&row, tenant, Some(&cfg), Some(&snapshot), Some(&asset), Some(&role), true));
    row.eligibility = model::Eligibility::Eligible;
    assert!(!views::qualified(&row, tenant, None, Some(&snapshot), Some(&asset), Some(&role), true));
    asset.attributes.remove(MARKER);
    assert!(!views::qualified(&row, tenant, Some(&cfg), Some(&snapshot), Some(&asset), Some(&role), true));
}
#[test]
fn losing_either_marker_or_mapping_never_restores_broad_key_scopes() {
    let (tenant, mut asset, cfg, snapshot, role, record, key) = fixture();
    assert!(authority::constrain(tenant, &key, &asset, None, None, None, None, true).is_err());
    asset.attributes.remove(MARKER);
    assert!(
        authority::constrain(tenant, &key, &asset, Some(&record), Some(&cfg), Some(&snapshot), Some(&role), true)
            .is_err()
    );
    assert_eq!(authority::constrain(tenant, &key, &asset, None, None, None, None, true).unwrap(), key.scopes);
}
#[test]
fn disabled_revoked_and_unknown_mappings_cannot_grant_scopes() {
    let (tenant, asset, cfg, snapshot, role, mut record, key) = fixture();
    for eligibility in [model::Eligibility::Disabled, model::Eligibility::Revoked, model::Eligibility::Unverified] {
        record.eligibility = eligibility;
        assert!(
            authority::constrain(tenant, &key, &asset, Some(&record), Some(&cfg), Some(&snapshot), Some(&role), true)
                .is_err()
        );
    }
}
#[test]
fn current_agent_classification_department_kind_and_tenant_are_fenced_but_telemetry_is_not() {
    let (tenant, asset, cfg, snapshot, role, record, key) = fixture();
    let mut candidates = vec![asset.clone(); 5];
    candidates[0].department = Some("other-department".into());
    candidates[1].data_class = DataClass::Confidential;
    candidates[2].kind = AssetKind::Skill;
    candidates[3].tenant_id = TenantId::new();
    candidates[4].deleted_at = Some(Timestamp::now());
    for changed in candidates {
        assert!(
            authority::constrain(tenant, &key, &changed, Some(&record), Some(&cfg), Some(&snapshot), Some(&role), true)
                .is_err()
        );
    }
    let mut telemetry = asset;
    telemetry.last_seen_at = Some(Timestamp::now());
    telemetry.risk_score = Some(80);
    telemetry.attributes.insert("cloud_Status".into(), json!("RUNNING"));
    assert!(
        !authority::constrain(tenant, &key, &telemetry, Some(&record), Some(&cfg), Some(&snapshot), Some(&role), true)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn old_adopted_evidence_does_not_create_a_five_minute_runtime_permission_ttl() {
    let (tenant, asset, cfg, mut snapshot, role, record, key) = fixture();
    snapshot.checked_at = Timestamp::from_unix_secs(Timestamp::now().unix_secs() - 3600).unwrap();
    assert!(
        authority::constrain(tenant, &key, &asset, Some(&record), Some(&cfg), Some(&snapshot), Some(&role), true)
            .is_ok()
    );
    let change = model::Change::Adopt {
        configuration_version: 1,
        observed_at: snapshot.checked_at,
        worker_name: "worker".into(),
        team_name: "team".into(),
        cloud_role: "member".into(),
        role_id: role.id,
    };
    assert!(proof::adopt(tenant, &cfg, &snapshot, &asset, &role, &change, true).is_err());
}
#[test]
fn source_revision_or_role_permission_change_invalidates_the_saved_proof() {
    let (tenant, asset, mut cfg, snapshot, mut role, record, key) = fixture();
    cfg.version = 2;
    assert!(
        authority::constrain(tenant, &key, &asset, Some(&record), Some(&cfg), Some(&snapshot), Some(&role), true)
            .is_err()
    );
    cfg.version = 1;
    role.permissions.push(Permission::from_raw("assets:write"));
    assert!(
        authority::constrain(tenant, &key, &asset, Some(&record), Some(&cfg), Some(&snapshot), Some(&role), true)
            .is_err()
    );
}
#[test]
fn complete_negative_membership_evidence_is_sticky_even_after_positive_observation() {
    let (_, _, _, snapshot, _, mut record, _) = fixture();
    let mut removed = snapshot.clone();
    removed.teams[0]["WorkerNames"] = json!([]);
    removed.workers[0]["Groups"] = json!([]);
    let (eligibility, reason) = refresh::decision(&record, &removed).unwrap().unwrap();
    assert!(record.retire(eligibility, reason).unwrap());
    assert_eq!(record.version, 2);
    assert_eq!(record.eligibility, model::Eligibility::Revoked);
    assert!(refresh::decision(&record, &snapshot).unwrap().is_none());
    assert_eq!(record.eligibility, model::Eligibility::Revoked);
    let mut unknown = record.clone();
    unknown.eligibility = model::Eligibility::Eligible;
    let mut missing_role = snapshot;
    missing_role.workers[0]["Groups"][0].as_object_mut().unwrap().remove("Role");
    let (eligibility, reason) = refresh::decision(&unknown, &missing_role).unwrap().unwrap();
    unknown.retire(eligibility, reason).unwrap();
    assert_eq!(unknown.eligibility, model::Eligibility::Unverified);
}
#[test]
fn foreign_or_department_scoped_roles_cannot_be_reinterpreted_as_flat_worker_permissions() {
    let (tenant, _, _, _, mut role, _, _) = fixture();
    role.tenant_id = TenantId::new();
    assert!(catalog::supported(&role, tenant).is_err());
    role.tenant_id = tenant;
    role.name = "asset-owner".into();
    assert!(catalog::supported(&role, tenant).is_err());
}
#[tokio::test]
async fn encrypted_mapping_rejects_foreign_tenant_asset_purpose_and_tampered_ciphertext() {
    let state = state();
    let (tenant, asset, _, _, _, record, _) = fixture();
    let sealed = codec::seal(&state, tenant, KIND, asset.id, &record).unwrap();
    assert_eq!(codec::record(&state, tenant, asset.id, &sealed).unwrap().version, 1);
    assert!(codec::record(&state, TenantId::new(), asset.id, &sealed).is_err());
    assert!(codec::record(&state, tenant, Id::new(), &sealed).is_err());
    assert!(codec::open::<model::Record>(&state, tenant, INTENTS, asset.id, &sealed).is_err());
    let mut altered = sealed;
    altered.secret.ciphertext_b64 = "AAAA".into();
    assert!(codec::record(&state, tenant, asset.id, &altered).is_err());
}
#[tokio::test]
async fn immutable_intent_replay_requires_same_actor_asset_body_and_purpose() {
    let state = state();
    let (tenant, asset, _, _, _, record, _) = fixture();
    let actor = Id::new();
    let input = model::Input {
        request_id: Id::new(),
        expected_version: 1,
        confirm_local_constraint: true,
        change: model::Change::Disable,
    };
    let fact = model::Intent {
        tenant,
        actor_id: actor,
        request_id: input.request_id,
        asset_id: asset.id,
        body_hash: hash(&(asset.id, &input)).unwrap(),
        result: record,
    };
    let sealed = codec::seal(&state, tenant, INTENTS, input.request_id, &fact).unwrap();
    assert_eq!(codec::replay(&state, tenant, actor, asset.id, &input, &sealed).unwrap().result.version, 1);
    assert!(codec::replay(&state, tenant, Id::new(), asset.id, &input, &sealed).is_err());
    assert!(codec::replay(&state, tenant, actor, Id::new(), &input, &sealed).is_err());
    let mut changed = input.clone();
    changed.expected_version = 2;
    assert!(codec::replay(&state, tenant, actor, asset.id, &changed, &sealed).is_err());
    changed = input;
    changed.change = model::Change::Adopt {
        configuration_version: 1,
        observed_at: Timestamp::now(),
        worker_name: "worker".into(),
        team_name: "team".into(),
        cloud_role: "member".into(),
        role_id: Id::new(),
    };
    assert!(codec::replay(&state, tenant, actor, asset.id, &changed, &sealed).is_err());
}
#[test]
fn input_never_accepts_client_permissions_or_missing_cas_as_administrator_proof() {
    let base = json!({"request_id":Id::new(),"expected_version":0,"confirm_local_constraint":true,"change":{"action":"disable"}});
    let mut unknown = base.clone();
    unknown["permissions"] = json!(["*"]);
    assert!(serde_json::from_value::<model::Input>(unknown).is_err());
    let mut missing = base;
    missing.as_object_mut().unwrap().remove("expected_version");
    assert!(serde_json::from_value::<model::Input>(missing).is_err());
}
