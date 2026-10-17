//! Real middleware identity and existing current-grant checks; no provider or paid call.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{Principal, gateway_semantic::CurrentCallAuthority};
use agf_core::{
    asset::Asset,
    enums::{AssetKind, DataClass},
    ids::Id,
};
use agf_storage::semantic_response_cache::{
    ConfigurationFence, SemanticReadAuthority, ServerSemanticEvidence, TrustedSemanticDomain,
};
use axum::extract::FromRequestParts;
use common::*;
use tokio::time::{Duration, Instant};

async fn principal(h: &Harness, token: &str) -> (Principal, HeaderMap) {
    let (mut parts, _) = Request::builder()
        .uri("/api/v1/gateway/chat")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
        .into_parts();
    let identity = Principal::from_request_parts(&mut parts, &h.state).await.unwrap();
    (identity, parts.headers)
}

async fn evidence(h: &Harness) -> ServerSemanticEvidence {
    let source = Id::new();
    let payload = json!({"version":1,"enabled":true,"owned":"semantic-authority-fixture"});
    h.state.configurations.put(h.tenant, "semantic-authority-fixture", source, &payload).await.unwrap();
    ServerSemanticEvidence {
        tenant: h.other_tenant,
        subject_id: Id::new(),
        subject_kind: "user".into(),
        identity_tenant: h.other_tenant,
        session: Some("caller-must-not-set-session".into()),
        agent_id: None,
        department: None,
        data_class: DataClass::Public,
        internal_placement_verified: false,
        chat_endpoint: source,
        chat_model: "owned-chat".into(),
        chat_model_revision: "revision-1".into(),
        embedding_endpoint: Id::new(),
        embedding_model: "owned-embedding".into(),
        embedding_model_revision: "revision-1".into(),
        dimensions: 3,
        transport_mode: "mock".into(),
        cache_configuration_version: 1,
        fences: vec![
            ConfigurationFence::from_server_record("semantic-authority-fixture", source, 1, &payload).unwrap(),
        ],
        fixed_request: json!({"temperature":0,"messages":[{"role":"user","content":null}]}),
        authority_deadline_ms: i64::MAX,
    }
}

#[tokio::test]
async fn actual_user_session_is_retained_and_fresh_full_source_change_blocks_original_domain() {
    let h = setup().await;
    let (identity, headers) = principal(&h, &h.admin).await;
    let mut authority =
        CurrentCallAuthority::capture(&h.state, &identity, &headers, None, Instant::now() + Duration::from_mins(1))
            .await
            .unwrap();
    let snapshot = evidence(&h).await;
    let source = snapshot.fences[0].id();
    let mut normalized = snapshot.clone();
    normalized.tenant = identity.tenant;
    normalized.identity_tenant = identity.identity_tenant;
    normalized.subject_id = identity.subject_id.unwrap();
    normalized.session.clone_from(&identity.session_id);
    normalized.department.clone_from(&identity.department);
    normalized.authority_deadline_ms = Timestamp::now().unix_millis() + 60_000;
    let expected = authority.issuer().issue(normalized).unwrap();
    let domain = authority.issue_domain(snapshot).await.unwrap();
    assert_eq!(domain.tenant(), h.tenant);
    assert_eq!(domain.digest(), expected.digest());
    authority.revalidate(&domain).await.unwrap();
    assert!(
        authority.issue_domain(evidence(&h).await).await.is_err(),
        "One original call cannot swap its issued domain"
    );
    h.state
        .configurations
        .put(h.tenant, "semantic-authority-fixture", source, &json!({"version":1,"enabled":false}))
        .await
        .unwrap();
    assert!(authority.revalidate(&domain).await.is_err(), "Same-version full source changes fail closed");
}

#[tokio::test]
async fn current_api_key_revocation_prevents_delivery_without_replacing_original_authority() {
    let h = setup().await;
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("models:write")],
        ..ApiKeyIssueRequest::named(h.tenant, "owned-semantic-model-key", Timestamp::now())
    });
    h.state.store.api_key_insert(issued.record.clone()).unwrap();
    let (identity, headers) = principal(&h, &issued.plaintext).await;
    let mut authority =
        CurrentCallAuthority::capture(&h.state, &identity, &headers, None, Instant::now() + Duration::from_mins(1))
            .await
            .unwrap();
    let domain = authority.issue_domain(evidence(&h).await).await.unwrap();
    authority.revalidate(&domain).await.unwrap();
    h.state.store.api_key_revoke(h.tenant, issued.record.id).unwrap();
    assert!(authority.revalidate(&domain).await.is_err());
}

#[tokio::test]
async fn read_only_subject_wrong_original_token_and_elapsed_deadline_never_gain_cache_authority() {
    let h = setup().await;
    let (viewer, viewer_headers) = principal(&h, &h.viewer).await;
    assert!(
        CurrentCallAuthority::capture(
            &h.state,
            &viewer,
            &viewer_headers,
            None,
            Instant::now() + Duration::from_mins(1)
        )
        .await
        .is_err()
    );
    let (admin, headers) = principal(&h, &h.admin).await;
    assert!(
        CurrentCallAuthority::capture(&h.state, &admin, &viewer_headers, None, Instant::now() + Duration::from_mins(1))
            .await
            .is_err()
    );
    assert!(
        CurrentCallAuthority::capture(&h.state, &admin, &headers, None, Instant::now() - Duration::from_millis(1))
            .await
            .is_err()
    );
}

async fn agent_authority(h: &Harness, token: &str, id: Id) -> (CurrentCallAuthority, TrustedSemanticDomain) {
    let (identity, headers) = principal(h, token).await;
    let mut authority =
        CurrentCallAuthority::capture(&h.state, &identity, &headers, Some(id), Instant::now() + Duration::from_mins(1))
            .await
            .unwrap();
    let domain = authority.issue_domain(evidence(h).await).await.unwrap();
    authority.revalidate(&domain).await.unwrap();
    (authority, domain)
}

async fn changed_agent_rejects_original_user_and_unbound_key(deleted: bool) {
    let h = setup().await;
    let key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("models:write")],
        ..ApiKeyIssueRequest::named(h.tenant, "owned-semantic-unbound-key", Timestamp::now())
    });
    h.state.store.api_key_insert(key.record).unwrap();
    for token in [&h.admin, &key.plaintext] {
        let mut asset = Asset::new(h.tenant, AssetKind::Agent, "owned-semantic-agent", Id::new().to_string());
        asset.data_class = DataClass::Public;
        h.state.store.asset_upsert(&asset).unwrap();
        let (authority, domain) = agent_authority(&h, token, asset.id).await;
        if deleted {
            asset.deleted_at = Some(Timestamp::now());
        } else {
            asset.kind = AssetKind::ModelEndpoint;
        }
        h.state.store.asset_upsert(&asset).unwrap();
        assert!(
            authority.revalidate(&domain).await.is_err(),
            "Original cache authority must read current Agent assets"
        );
        let (identity, headers) = principal(&h, token).await;
        assert!(
            CurrentCallAuthority::capture(
                &h.state,
                &identity,
                &headers,
                Some(asset.id),
                Instant::now() + Duration::from_mins(1),
            )
            .await
            .is_err(),
            "A new authority cannot adopt a deleted or non-Agent asset"
        );
    }
}

#[tokio::test]
async fn actual_agent_deletion_blocks_existing_and_new_user_or_unbound_key_authority() {
    changed_agent_rejects_original_user_and_unbound_key(true).await;
}

#[tokio::test]
async fn actual_agent_kind_change_blocks_existing_and_new_user_or_unbound_key_authority() {
    changed_agent_rejects_original_user_and_unbound_key(false).await;
}

async fn agent_tokens(h: &Harness, id: Id) -> Vec<String> {
    let mut tokens = vec![h.admin.clone()];
    for bound in [None, Some(id)] {
        let key = h.state.api_keys.issue(ApiKeyIssueRequest {
            scopes: vec![Permission::from_raw("models:write")],
            bound_agent_id: bound,
            ..ApiKeyIssueRequest::named(h.tenant, "owned-semantic-classification-key", Timestamp::now())
        });
        h.state.store.api_key_insert(key.record).unwrap();
        tokens.push(key.plaintext);
    }
    tokens
}

async fn captured(h: &Harness, token: &str, id: Id) -> CurrentCallAuthority {
    let (identity, headers) = principal(h, token).await;
    CurrentCallAuthority::capture(&h.state, &identity, &headers, Some(id), Instant::now() + Duration::from_mins(1))
        .await
        .unwrap()
}

async fn sensitive_agent_change_rejects_original_authority(classification: bool) {
    let h = setup().await;
    let mut asset = Asset::new(h.tenant, AssetKind::Agent, "owned-semantic-agent", Id::new().to_string());
    asset.data_class = DataClass::Public;
    asset.department = Some("owned-original-department".into());
    h.state.store.asset_upsert(&asset).unwrap();
    let snapshot = evidence(&h).await;
    for token in agent_tokens(&h, asset.id).await {
        let mut initial = asset.clone();
        h.state.store.asset_upsert(&initial).unwrap();
        let mut waiting = captured(&h, &token, asset.id).await;
        let mut issued = captured(&h, &token, asset.id).await;
        let domain = issued.issue_domain(snapshot.clone()).await.unwrap();
        if classification {
            initial.data_class = DataClass::Confidential;
        } else {
            initial.department = Some("owned-changed-department".into());
        }
        h.state.store.asset_upsert(&initial).unwrap();
        assert!(waiting.issue_domain(snapshot.clone()).await.is_err(), "Changes before domain issuance fail closed");
        assert!(issued.revalidate(&domain).await.is_err(), "Changes after issuance reject the original domain");
        let mut fresh = captured(&h, &token, asset.id).await;
        let view = fresh.agent_view().unwrap();
        assert_eq!(view.id(), initial.id);
        assert_eq!(view.tenant(), h.tenant);
        assert_eq!(view.data_class(), initial.data_class);
        assert_eq!(view.department(), initial.department.as_deref());
        if classification {
            assert!(
                fresh.issue_domain(snapshot.clone()).await.is_err(),
                "A caller cannot downgrade actual classification"
            );
        } else {
            let new_domain = fresh.issue_domain(snapshot.clone()).await.unwrap();
            assert_ne!(domain.digest(), new_domain.digest(), "Agent department changes partition future cache domains");
        }
    }
}

#[tokio::test]
async fn actual_agent_classification_change_blocks_waiting_user_unbound_and_bound_key() {
    sensitive_agent_change_rejects_original_authority(true).await;
}

#[tokio::test]
async fn actual_agent_department_change_blocks_waiting_user_unbound_and_bound_key() {
    sensitive_agent_change_rejects_original_authority(false).await;
}

#[tokio::test]
async fn actual_agent_telemetry_changes_preserve_authority_and_domain() {
    let h = setup().await;
    let mut asset = Asset::new(h.tenant, AssetKind::Agent, "owned-semantic-agent", Id::new().to_string());
    asset.data_class = DataClass::Public;
    h.state.store.asset_upsert(&asset).unwrap();
    let snapshot = evidence(&h).await;
    for token in agent_tokens(&h, asset.id).await {
        let mut waiting = captured(&h, &token, asset.id).await;
        let mut issued = captured(&h, &token, asset.id).await;
        let domain = issued.issue_domain(snapshot.clone()).await.unwrap();
        asset.last_seen_at = Some(Timestamp::now());
        asset.updated_at = Timestamp::now();
        asset.risk_score = Some(99);
        asset.exposure_score = 90;
        asset.attributes.insert("heartbeat-sequence".into(), json!(123));
        h.state.store.asset_upsert(&asset).unwrap();
        issued.revalidate(&domain).await.unwrap();
        let waiting_domain = waiting.issue_domain(snapshot.clone()).await.unwrap();
        assert_eq!(domain.digest(), waiting_domain.digest());
        let mut fresh = captured(&h, &token, asset.id).await;
        let new_domain = fresh.issue_domain(snapshot.clone()).await.unwrap();
        assert_eq!(domain.digest(), new_domain.digest(), "Ordinary telemetry is outside authorization identity");
    }
}

#[tokio::test]
async fn internal_agent_requires_non_downgraded_server_placement_evidence() {
    let h = setup().await;
    let asset = Asset::new(h.tenant, AssetKind::Agent, "owned-internal-agent", Id::new().to_string());
    h.state.store.asset_upsert(&asset).unwrap();
    let mut authority = captured(&h, &h.admin, asset.id).await;
    let mut snapshot = evidence(&h).await;
    assert!(authority.issue_domain(snapshot.clone()).await.is_err());
    snapshot.data_class = DataClass::Internal;
    assert!(authority.issue_domain(snapshot.clone()).await.is_err(), "A classification is not placement proof");
    // This is service-constructed proof in a test; no client DTO or HTTP option can set it.
    snapshot.internal_placement_verified = true;
    let domain = authority.issue_domain(snapshot).await.unwrap();
    authority.revalidate(&domain).await.unwrap();
}
