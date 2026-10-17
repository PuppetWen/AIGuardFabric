//! Strict policy revisions and genuine model/MCP forwarding: no external consumer is inferred.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod policy_publication_support;
use common::*;
use policy_publication_support::loopback::Fixture;
use policy_publication_support::*;

#[tokio::test]
async fn saved_policy_denies_both_real_upstreams_and_restore_publishes_a_new_signed_revision() {
    let f = Fixture::attach(setup().await).await;
    let first = create(&f.h, "policy-real-enforcement", "allow").await;
    f.assert_both(false).await;
    let changed = update(&f.h, &first, "deny").await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    let second = changed.json()["policy"].clone();
    assert_eq!(second["version"], 2);
    assert_signed(&f.h, &second);
    f.assert_both(true).await;
    let restored = restore(&f.h, &second, 1).await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.text);
    let third = restored.json()["policy"].clone();
    assert_eq!(third["version"], 3);
    assert_eq!(third["action"], "allow");
    assert_signed(&f.h, &third);
    assert_ne!(first["signature"], third["signature"], "restoration signs a higher revision");
    f.assert_both(false).await;
    assert_eq!(f.calls("/chat/completions").await, 2);
    assert_eq!(f.calls("/mcp").await, 2);
    let versions = history(&f.h, id(&first)).await;
    assert_eq!(versions["versions"].as_array().unwrap().len(), 3);
    for version in versions["versions"].as_array().unwrap() {
        assert_signed(&f.h, version);
    }
    assert_eq!(successes(&f.h, id(&first), "create").await, 1);
    assert_eq!(successes(&f.h, id(&first), "update").await, 2);
    intact_chain(&f.h).await;
}

#[tokio::test]
async fn every_mutation_requires_its_precise_current_version_and_same_name_creation_never_updates() {
    let h = setup().await;
    let first = create(&h, "policy-conditions", "allow").await;
    let before = registry(&h).await;
    let audits = policy_audits(&h).await.len();
    let uri = path(id(&first));
    for version in [None, Some(0), Some(1)] {
        let response = h.post(POLICIES, body("policy-conditions", "deny", version)).await;
        assert_eq!(
            response.status,
            if version == Some(1) { StatusCode::BAD_REQUEST } else { StatusCode::CONFLICT },
            "{}",
            response.text
        );
    }
    for version in [None, Some(0)] {
        let response = h.request("PUT", &uri, Some(&h.admin), Some(body("ignored-name", "deny", version))).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
    }
    for suffix in ["", "?expected_version=0"] {
        assert_eq!(
            h.request("DELETE", &format!("{uri}{suffix}"), Some(&h.admin), None).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    for value in [json!({}), json!({"version":2,"expected_version":1}), json!({"version":1,"expected_version":0})] {
        assert_eq!(h.post(&restore_path(id(&first), 1), value).await.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(registry(&h).await, before);
    assert_eq!(policy_audits(&h).await.len(), audits);
    let changed = h.request("PUT", &uri, Some(&h.admin), Some(body("ignored-name", "deny", Some(1)))).await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(changed.json()["policy"]["name"], first["name"]);
    let current = registry(&h).await;
    let count = policy_audits(&h).await.len();
    for response in [
        h.request("PUT", &uri, Some(&h.admin), Some(body("ignored-name", "allow", Some(1)))).await,
        h.request("DELETE", &format!("{uri}?expected_version=1"), Some(&h.admin), None).await,
        h.post(&restore_path(id(&first), 1), json!({"version":1,"expected_version":1})).await,
    ] {
        assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.text);
    }
    assert_eq!(registry(&h).await, current);
    assert_eq!(policy_audits(&h).await.len(), count);
    let deleted = h.request("DELETE", &format!("{uri}?expected_version=2"), Some(&h.admin), None).await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text);
    assert_eq!(h.get(&uri).await.status, StatusCode::NOT_FOUND);
    let recovered = h.post(&restore_path(id(&first), 1), json!({"version":1,"expected_version":3})).await;
    assert_eq!(recovered.status, StatusCode::OK, "{}", recovered.text);
    assert_eq!(recovered.json()["policy"]["version"], 4);
    assert_eq!(recovered.json()["policy"]["action"], "allow");
    assert_signed(&h, &recovered.json()["policy"]);
    assert_eq!(history(&h, id(&first)).await["versions"].as_array().unwrap().len(), 4);
    intact_chain(&h).await;
}

#[tokio::test]
async fn bad_candidate_and_restore_path_mismatch_preserve_exact_history_signature_and_effective_behavior() {
    let f = Fixture::attach(setup().await).await;
    let first = create(&f.h, "policy-invalid-candidate", "allow").await;
    let before = registry(&f.h).await;
    let versions = history(&f.h, id(&first)).await;
    let count = policy_audits(&f.h).await.len();
    let mut invalid = body("policy-invalid-candidate", "deny", Some(1));
    invalid["source"] = json!("this is not valid CEL");
    let rejected = f.h.request("PUT", &path(id(&first)), Some(&f.h.admin), Some(invalid)).await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST, "{}", rejected.text);
    let mismatched = f.h.post(&restore_path(id(&first), 1), json!({"version":2,"expected_version":1})).await;
    assert_eq!(mismatched.status, StatusCode::BAD_REQUEST, "{}", mismatched.text);
    assert_eq!(registry(&f.h).await, before);
    assert_eq!(history(&f.h, id(&first)).await, versions);
    assert_eq!(policy_audits(&f.h).await.len(), count);
    f.assert_both(false).await;
    intact_chain(&f.h).await;
}

#[tokio::test]
async fn signed_history_from_a_different_policy_or_tenant_and_bad_hash_signature_are_rejected() {
    for corruption in ["policy-id", "tenant", "hash", "signature", "duplicate-version"] {
        let h = setup().await;
        let first = create(&h, "policy-history-identity", "allow").await;
        assert_eq!(update(&h, &first, "deny").await.status, StatusCode::OK);
        let mut raw = registry(&h).await;
        let target = id(&first).to_string();
        let mut historical: agf_core::policy::Policy =
            serde_json::from_value(raw["history"][&target][0].clone()).unwrap();
        match corruption {
            "policy-id" => historical.id = agf_core::ids::Id::new(),
            "tenant" => historical.tenant_id = h.other_tenant,
            "hash" => historical.content_hash = "0".repeat(64),
            "signature" => historical.source = json!({"action":"deny"}).to_string(),
            "duplicate-version" => {}
            _ => unreachable!(),
        }
        if matches!(corruption, "policy-id" | "tenant") {
            historical.content_hash = historical.compute_hash();
            historical.signature = agf_api::policy_store::signer(&h.state).unwrap().sign(&historical);
            agf_api::policy_store::signer(&h.state).unwrap().verify(&historical).unwrap();
        }
        raw["history"][&target][0] = serde_json::to_value(historical).unwrap();
        replace_registry(&h, &raw).await;
        if corruption == "duplicate-version" {
            let duplicate = raw["history"][&target][0].clone();
            raw["history"][&target].as_array_mut().unwrap().push(duplicate);
            replace_registry(&h, &raw).await;
        }
        let count = policy_audits(&h).await.len();
        assert!(
            !h.get(&format!("{}/versions", path(id(&first)))).await.status.is_success(),
            "{corruption} history must not be served as trustworthy"
        );
        let restored = h.post(&restore_path(id(&first), 1), json!({"version":1,"expected_version":2})).await;
        assert!(!restored.status.is_success(), "{corruption} restore must reject");
        assert_eq!(registry(&h).await, raw, "{corruption} must not be silently repaired or published");
        assert_eq!(policy_audits(&h).await.len(), count);
        intact_chain(&h).await;
    }
}

#[tokio::test]
async fn restoring_or_trusted_saving_a_deleted_policy_cannot_take_another_active_policys_name() {
    let h = setup().await;
    let first = create(&h, "policy-reused-name", "allow").await;
    let first_id = id(&first);
    let deleted = h.request("DELETE", &format!("{}?expected_version=1", path(first_id)), Some(&h.admin), None).await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text);
    let replacement = create(&h, "policy-reused-name", "deny").await;
    let replacement_id = id(&replacement);
    assert_ne!(first_id, replacement_id);

    let before = registry(&h).await;
    let first_history = history(&h, first_id).await;
    let replacement_history = history(&h, replacement_id).await;
    let deleted_revision = &first_history["versions"][1];
    assert_eq!(first_history["versions"].as_array().unwrap().len(), 2);
    assert_eq!(replacement_history["versions"].as_array().unwrap().len(), 1);
    assert_eq!(deleted_revision["version"], 2);
    assert_eq!(deleted_revision["enabled"], false);
    assert!(deleted_revision["deleted_at"].is_string());
    for versions in [&first_history, &replacement_history] {
        for policy in versions["versions"].as_array().unwrap() {
            assert_signed(&h, policy);
        }
    }
    let audits = serde_json::to_value(policy_audits(&h).await).unwrap();
    let audit_tail = h.state.store.audit_stats_durable(h.tenant).await.unwrap();

    for trusted_save in [false, true] {
        if trusted_save {
            let active: agf_core::policy::Policy = serde_json::from_value(first.clone()).unwrap();
            assert!(active.enabled && active.deleted_at.is_none());
            let rejected = agf_api::policy_store::save(&h.state, h.tenant, active).await.unwrap_err();
            assert!(matches!(rejected, agf_core::error::DomainError::Conflict(_)), "{rejected}");
            assert_eq!(rejected.status_code(), 409);
        } else {
            let rejected = h.post(&restore_path(first_id, 1), json!({"version":1,"expected_version":2})).await;
            assert_eq!(rejected.status, StatusCode::CONFLICT, "{}", rejected.text);
        }
        assert_eq!(registry(&h).await, before, "signed entries and all history must remain unchanged");
        assert_eq!(history(&h, first_id).await, first_history);
        assert_eq!(history(&h, replacement_id).await, replacement_history);
        assert_eq!(serde_json::to_value(policy_audits(&h).await).unwrap(), audits);
        assert_eq!(h.state.store.audit_stats_durable(h.tenant).await.unwrap(), audit_tail);
        assert_eq!(h.get(&path(first_id)).await.status, StatusCode::NOT_FOUND);
        let readable = h.get(&path(replacement_id)).await;
        assert_eq!(readable.status, StatusCode::OK, "{}", readable.text);
        assert_eq!(readable.json()["policy"], replacement);
        assert_signed(&h, &readable.json()["policy"]);
        intact_chain(&h).await;
    }
}
