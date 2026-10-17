//! No provider call is needed to verify strict inputs, target binding and exact signed content.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "tests_support.rs"]
mod support;
use super::*;
use agf_alicloud::mse::config_cas::{PublishOutcome, content_md5};
use agf_core::{
    error::DomainError,
    ids::{Id, TenantId},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::SocketAddr};

#[tokio::test]
async fn actual_cloud_configuration_save_binds_the_public_service_name_and_cloud_kind() {
    let state = support::state(true);
    let tenant = TenantId::default_tenant();
    let name = agf_core::enums::AliCloudService::Mse.as_str();
    assert_eq!(name, "alicloud-mse");
    let update = crate::integration_store::Update {
        enabled: true,
        mock: true,
        settings: serde_json::from_value(support::settings()).unwrap(),
        secrets: BTreeMap::default(),
        clear_secrets: Vec::new(),
        expected_version: 0,
    };
    crate::cloud_store::save(&state, tenant, name, update).await.unwrap();
    let row = crate::cloud_store::load(&state, tenant, name).await.unwrap().unwrap();
    let bound = scope::from_row(&state, tenant, &row, &Registry::default()).unwrap();
    assert_eq!(bound.target.configuration_version, 1);
    assert_eq!(bound.target.configuration_id, crate::integration_store::id(tenant, name));
    assert!(state.configurations.get::<Value>(tenant, crate::integration_store::KIND, row.id).await.unwrap().is_none());
}

#[tokio::test]
async fn engine_retargeting_clears_old_credentials_and_requires_explicit_live_replacement() {
    let state = support::state(false);
    let tenant = TenantId::default_tenant();
    let name = agf_core::enums::AliCloudService::Mse.as_str();
    let credentials = |suffix: &str| {
        std::collections::BTreeMap::from([
            ("access_key_id".into(), format!("owned-test-id-{suffix}")),
            ("access_key_secret".into(), format!("owned-test-secret-{suffix}")),
        ])
    };
    let update = |settings: Value, version, enabled, secrets| crate::integration_store::Update {
        enabled,
        mock: false,
        settings: serde_json::from_value(settings).unwrap(),
        secrets,
        clear_secrets: Vec::new(),
        expected_version: version,
    };
    let settings = support::settings();
    crate::cloud_store::save(&state, tenant, name, update(settings.clone(), 0, true, credentials("original")))
        .await
        .unwrap();
    crate::cloud_store::save(&state, tenant, name, update(settings.clone(), 1, true, BTreeMap::default()))
        .await
        .unwrap();
    let row = crate::cloud_store::load(&state, tenant, name).await.unwrap().unwrap();
    assert_eq!(crate::integration_store::decrypt(&state, tenant, &row).unwrap().secrets, credentials("original"));
    let mut target = settings;
    target["engine_origin"] = json!("https://new-owned-engine.invalid");
    assert!(
        crate::cloud_store::save(&state, tenant, name, update(target.clone(), 2, true, BTreeMap::default()))
            .await
            .is_err()
    );
    assert_eq!(
        serde_json::to_value(crate::cloud_store::load(&state, tenant, name).await.unwrap().unwrap()).unwrap(),
        serde_json::to_value(&row).unwrap()
    );
    crate::cloud_store::save(&state, tenant, name, update(target.clone(), 2, false, BTreeMap::default()))
        .await
        .unwrap();
    let disabled = crate::cloud_store::load(&state, tenant, name).await.unwrap().unwrap();
    assert!(crate::integration_store::decrypt(&state, tenant, &disabled).unwrap().secrets.is_empty());
    crate::cloud_store::save(&state, tenant, name, update(target.clone(), 3, true, credentials("new"))).await.unwrap();
    target["engine_origin"] = json!("https://third-owned-engine.invalid");
    crate::cloud_store::save(&state, tenant, name, update(target, 4, true, credentials("replacement"))).await.unwrap();
    let replaced = crate::cloud_store::load(&state, tenant, name).await.unwrap().unwrap();
    assert_eq!(replaced.version, 5);
    assert_eq!(
        crate::integration_store::decrypt(&state, tenant, &replaced).unwrap().secrets,
        credentials("replacement")
    );
}

#[test]
fn workflow_inputs_reject_target_overrides_null_ids_and_unconfirmed_writes() {
    let request = Id::new();
    let observation = Id::new();
    let policy = Id::new();
    let mut value = json!({"request_id":request,"configuration_version":1,"confirm_live":false});
    let input: input::ObserveInput = input::parse(value.clone()).unwrap();
    input.validate().unwrap();
    value["engine_origin"] = json!("https://override.invalid");
    assert!(input::parse::<input::ObserveInput>(value).is_err());
    let preview = json!({"request_id":request,"configuration_version":1,"observation_id":observation,
        "expected_state_version":0,"change":{"action":"publish","policies":[{"policy_id":policy,"version":1}]}});
    input::parse::<input::PreviewInput>(preview.clone()).unwrap().normalize().unwrap();
    let mut invalid = preview.clone();
    invalid["acknowledge_unknown_operation_id"] = Value::Null;
    assert!(input::parse::<input::PreviewInput>(invalid).is_err());
    let mut maximum = preview.clone();
    maximum["change"]["policies"][0]["version"] = json!(u32::MAX);
    input::parse::<input::PreviewInput>(maximum).unwrap().normalize().unwrap();
    for version in [-1_i64, 0, i64::from(u32::MAX) + 1] {
        let mut invalid = preview.clone();
        invalid["change"]["policies"][0]["version"] = json!(version);
        assert!(input::parse::<input::PreviewInput>(invalid).and_then(input::PreviewInput::normalize).is_err());
    }
    let mut duplicated = preview;
    duplicated["change"]["policies"] = json!([
        {"policy_id":policy,"version":1},{"policy_id":policy,"version":1}]);
    assert!(input::parse::<input::PreviewInput>(duplicated).unwrap().normalize().is_err());
    let apply: input::ApplyInput = input::parse(json!({"request_id":request,"preview_id":observation,
        "expected_state_version":0,"confirm_apply":false,"confirm_upsert":true}))
    .unwrap();
    assert!(matches!(apply.validate(), Err(DomainError::PreconditionFailed(_))));
    assert!(input::parse::<input::RecoverInput>(json!({"content":"copied history"})).is_err());
}

#[tokio::test]
async fn target_scope_uses_explicit_namespace_and_identity_but_not_configuration_revision() {
    let state = support::state(true);
    let tenant = TenantId::default_tenant();
    let original = support::row(&state, tenant, support::settings(), true);
    let baseline = scope::from_row(&state, tenant, &original, &Registry::default()).unwrap();
    assert!(baseline.target.namespace_id.is_empty());
    let mut newer = original.clone();
    newer.version = 2;
    let changed = scope::from_row(&state, tenant, &newer, &Registry::default()).unwrap();
    assert_eq!(changed.target.target_scope_id, baseline.target.target_scope_id);
    assert_eq!(changed.target.configuration_version, 2);
    for key in ["region_id", "instance_id", "namespace_id", "config_group", "config_data_id", "account_id"] {
        let mut settings = support::settings();
        settings[key] = json!("different-owned-source");
        let row = support::row(&state, tenant, settings, true);
        let changed = scope::from_row(&state, tenant, &row, &Registry::default()).unwrap();
        assert_ne!(changed.target.target_scope_id, baseline.target.target_scope_id);
    }
    let mut missing = support::settings();
    missing.as_object_mut().unwrap().remove("namespace_id");
    assert!(
        scope::from_row(&state, tenant, &support::row(&state, tenant, missing, true), &Registry::default()).is_err()
    );
    let mut wrong = support::settings();
    wrong["namespace_id"] = json!("public");
    assert!(scope::from_row(&state, tenant, &support::row(&state, tenant, wrong, true), &Registry::default()).is_err());
}

#[tokio::test]
async fn origin_never_falls_back_to_the_console_endpoint_or_another_test_tenant() {
    let state = support::state(false);
    let tenant = TenantId::default_tenant();
    let mut missing = support::settings();
    missing.as_object_mut().unwrap().remove("engine_origin");
    missing["endpoint"] = json!("https://mse.cn-hangzhou.aliyuncs.com");
    assert!(
        scope::from_row(&state, tenant, &support::row(&state, tenant, missing, false), &Registry::default()).is_err()
    );
    let socket: SocketAddr = "127.0.0.1:39019".parse().unwrap();
    let mut settings = support::settings();
    settings["engine_origin"] = json!(format!("http://{socket}"));
    let row = support::row(&state, tenant, settings.clone(), false);
    assert!(scope::from_row(&state, tenant, &row, &Registry::default()).is_err());
    let capability = Registry::literal_loopback_for_test(tenant, socket).unwrap();
    let bound = scope::from_row(&state, tenant, &row, &capability).unwrap();
    assert_eq!(bound.target.transport_mode, contract::TransportMode::LoopbackTest);
    let other = TenantId::new();
    assert!(scope::from_row(&state, other, &support::row(&state, other, settings, false), &capability).is_err());
    assert!(Registry::literal_loopback_for_test(tenant, "192.168.1.2:39019".parse().unwrap()).is_err());
}

#[tokio::test]
async fn canonical_signed_bundle_preserves_exact_history_and_rejects_cross_target_or_tampering() {
    let state = support::state(true);
    let scope = support::scope(&state);
    let signer = crate::policy_store::signer(&state).unwrap();
    let a = support::policy(&state, "owned-a");
    let b = support::policy(&state, "owned-b");
    let first = bundle::generate(&scope, vec![b.clone(), a.clone()], Vec::new(), &signer).unwrap();
    let again = bundle::generate(&scope, vec![a, b], Vec::new(), &signer).unwrap();
    assert_eq!(first.plaintext, again.plaintext);
    assert_eq!(first.content_hash, again.content_hash);
    let verified = bundle::verify_history(&scope, &first.plaintext, &first.content_hash, &signer).unwrap();
    assert_eq!(verified.plaintext, first.plaintext);
    let mut newer = scope.clone();
    newer.target.configuration_version += 1;
    assert!(bundle::verify_history(&newer, &first.plaintext, &first.content_hash, &signer).is_ok());
    let mut target = scope.clone();
    target.target.data_id = "different.json".into();
    assert!(bundle::verify_history(&target, &first.plaintext, &first.content_hash, &signer).is_err());
    let mut tampered: Value = serde_json::from_str(&first.plaintext).unwrap();
    tampered["payload"]["policies"][0]["description"] = json!("tampered source");
    use sha2::{Digest, Sha256};
    tampered["payloadHash"] = json!(hex::encode(Sha256::digest(tampered["payload"].to_string().as_bytes())));
    let text = tampered.to_string();
    let file_hash = hex::encode(Sha256::digest(text.as_bytes()));
    assert!(bundle::verify_history(&scope, &text, &file_hash, &signer).is_err());
    assert!(!format!("{first:?}").contains("owned-a"));
}

#[tokio::test]
async fn bundle_requires_every_dependency_and_checks_full_serialized_content_size() {
    let state = support::state(true);
    let scope = support::scope(&state);
    let signer = crate::policy_store::signer(&state).unwrap();
    let mut policy = support::policy(&state, "owned-agent-binding");
    policy.scope_agent_ids = vec![Id::new()];
    policy.content_hash = policy.compute_hash();
    policy.signature = signer.sign(&policy);
    assert!(bundle::generate(&scope, vec![policy], Vec::new(), &signer).is_err());
    let mut too_large = support::policy(&state, "owned-too-large");
    too_large.description = "a".repeat(MAX_CONTENT_BYTES);
    too_large.content_hash = too_large.compute_hash();
    too_large.signature = signer.sign(&too_large);
    assert!(matches!(
        bundle::generate(&scope, vec![too_large], Vec::new(), &signer),
        Err(DomainError::PreconditionFailed(_))
    ));
}

#[tokio::test]
async fn explicit_mock_observation_persists_encrypted_exact_content_and_cas_does_not_reseed() {
    let state = support::state(true);
    let scope = support::scope(&state);
    let initial = mock::query(&state, &scope).await.unwrap();
    assert_eq!(initial.content, "{}");
    let desired = "owned Unicode 测试\r\n";
    assert_eq!(mock::publish(&state, &scope, &initial.md5, desired).await.unwrap(), PublishOutcome::Accepted);
    let stored: Vec<Value> = state.configurations.list(scope.tenant, "mse-config-publication-mock").await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0]["revision"], 2);
    assert!(!serde_json::to_string(&stored).unwrap().contains("owned Unicode"));
    let shared = state.clone();
    let observed = mock::query(&shared, &scope).await.unwrap();
    assert_eq!(observed.content, desired);
    assert_eq!(observed.md5, content_md5(desired));
    assert_eq!(mock::publish(&state, &scope, &initial.md5, "stale").await.unwrap(), PublishOutcome::Conflict);
    let unchanged: Vec<Value> = state.configurations.list(scope.tenant, "mse-config-publication-mock").await.unwrap();
    assert_eq!(unchanged, stored);
    assert_eq!(mock::publish(&state, &scope, &observed.md5, "").await.unwrap(), PublishOutcome::Accepted);
    let empty = mock::query(&state, &scope).await.unwrap();
    assert!(empty.content.is_empty());
    assert_eq!(empty.md5, content_md5(""));
    let mut wrong = scope.clone();
    wrong.target.data_id = "unregistered-target.json".into();
    wrong.target.target_scope_id = Id::new();
    assert!(mock::query(&state, &wrong).await.is_err());
    let after: Vec<Value> = state.configurations.list(scope.tenant, "mse-config-publication-mock").await.unwrap();
    assert_eq!(after.len(), 1);
}
