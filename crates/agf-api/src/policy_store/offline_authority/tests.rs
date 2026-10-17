//! A proof never invokes the configuration-backed MFA/session futures while their mutex is held.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    user::User,
};
use agf_storage::configuration::OfflineGuardedMutation;
use axum::http::{HeaderMap, HeaderValue, header};
use std::collections::BTreeMap;

async fn fixture() -> (AppState, Principal, AccessLease) {
    let data_dir = std::env::var_os("AGF_TEST_DATA_DIR").filter(|root| !root.is_empty()).map_or_else(
        || std::path::PathBuf::from("./target/test-data/policy-unit"),
        |root| std::path::PathBuf::from(root).join("policy-unit"),
    );
    let mut env: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_JWT_SECRET", "policy-unit-owned-secret-at-least-32-bytes"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_PROJECT_ROOT", "."),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    env.insert("AGF_DATA_DIR".into(), data_dir.to_string_lossy().into_owned());
    let state = AppState::offline(agf_core::config::from_env_map(&env).unwrap()).unwrap();
    let tenant = TenantId::default_tenant();
    let mut user = User::new_local(tenant, "policy-unit-editor", "editor@owned.local");
    user.must_change_password = false;
    state.auth_backend.save_account(&user, None, &["tenant-admin".into()]).await.unwrap();
    let token = state.auth.issue_for_user(&user, tenant, vec!["tenant-admin".into()]).unwrap();
    let principal = Principal {
        subject_id: Some(user.id),
        subject_kind: SubjectKind::User,
        tenant,
        identity_tenant: tenant,
        agent_id: None,
        roles: vec!["tenant-admin".into()],
        scopes: Vec::new(),
        superadmin: false,
        must_change_password: false,
        must_setup_mfa: false,
        session_id: Some(token.session_id),
        source_ip: None,
        user_agent: None,
        department: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", token.access_token)).unwrap());
    let lease = AccessLease::capture(&state, &principal, &headers).unwrap().unwrap();
    (state, principal, lease)
}

fn snapshot(proof: &Proof) -> OfflineGuardedSnapshot {
    OfflineGuardedSnapshot {
        guards: BTreeMap::new(),
        tenant_directory: proof.evidence.directory.clone(),
        password_policy: proof.evidence.password_policy.clone(),
        mfa_enrollment: proof.evidence.mfa_enrollment.clone(),
    }
}

#[tokio::test]
async fn builtin_protected_user_and_role_reads_complete_under_the_configuration_mutex() {
    let (state, principal, lease) = fixture().await;
    let submission = mutation::Submission::management(&principal, Timestamp::now(), Some(lease));
    let proof = prepare(&state, &submission, "write").await.unwrap().unwrap();
    let id = Id::new();
    let mutation =
        OfflineGuardedMutation { kind: "proof-test", id, guards: &[], security: Some(security(&principal).unwrap()) };
    state
        .configurations
        .mutate_offline_guarded_audited(
            principal.tenant,
            mutation,
            |_, value: &mut u64| {
                *value = 1;
                Ok((
                    (),
                    AppState::audit_entry(
                        principal.tenant,
                        AuditAction::Update,
                        AuditOutcome::Success,
                        AppState::audit_actor(&principal, "proof-test"),
                        AuditTarget::new("proof-test", None, None),
                        "owned proof test",
                    ),
                ))
            },
            |audit, locked| {
                proof.check(&state, &submission, "write", locked)?;
                state.store.audit_append(audit)
            },
        )
        .unwrap();
    assert_eq!(state.configurations.get::<u64>(principal.tenant, "proof-test", id).await.unwrap(), Some(1));
}

#[tokio::test]
async fn account_or_role_change_after_prepare_rejects_the_proof() {
    for change_role in [true, false] {
        let (state, principal, lease) = fixture().await;
        let submission = mutation::Submission::management(&principal, Timestamp::now(), Some(lease));
        let proof = prepare(&state, &submission, "write").await.unwrap().unwrap();
        let mut user = state
            .auth_backend
            .find_user(principal.identity_tenant, principal.subject_id.unwrap())
            .await
            .unwrap()
            .unwrap();
        if !change_role {
            user.password_changed_at = Some(Timestamp::now());
        }
        let role = if change_role { "viewer" } else { "tenant-admin" };
        state.auth_backend.save_account(&user, None, &[role.into()]).await.unwrap();
        assert!(proof.check(&state, &submission, "write", &snapshot(&proof)).is_err());
    }
}

#[tokio::test]
async fn locked_mfa_policy_directory_and_original_token_expiry_are_checked() {
    let (state, principal, lease) = fixture().await;
    let mut submission = mutation::Submission::management(&principal, Timestamp::now(), Some(lease));
    let proof = prepare(&state, &submission, "write").await.unwrap().unwrap();
    for field in [0, 1, 2] {
        let mut locked = snapshot(&proof);
        let replacement = Some(serde_json::json!({"changed":true}));
        match field {
            0 => locked.password_policy = replacement,
            1 => locked.mfa_enrollment = replacement,
            _ => locked.tenant_directory = replacement,
        }
        assert!(proof.check(&state, &submission, "write", &locked).is_err());
    }
    submission.lease.as_mut().unwrap().expires_at = Timestamp::now().unix_secs();
    assert!(matches!(
        proof.check(&state, &submission, "write", &snapshot(&proof)),
        Err(DomainError::Unauthenticated(_))
    ));
}

#[test]
fn fixed_security_kinds_match_the_existing_authentication_store_contract() {
    assert_eq!(crate::auth_policy::KIND, "password-policy");
    assert_eq!(crate::mfa_store::KIND, "mfa-enrollment");
    for tenant in [TenantId::default_tenant(), TenantId::new()] {
        assert_eq!(tenant_record_id(tenant), Id::from_uuid(tenant.as_uuid()));
    }
    assert!(tenant_enabled(TenantId::new(), None).is_err());
    assert!(tenant_enabled(TenantId::default_tenant(), None).is_ok());
}

#[tokio::test]
async fn current_key_revocation_permissions_and_expiry_reject_prepared_authority() {
    for mode in ["revoked", "scope", "expired"] {
        let (state, user, _) = fixture().await;
        let issued = state.api_keys.issue(agf_auth::api_key::ApiKeyIssueRequest {
            scopes: vec![agf_core::rbac::Permission::from_raw("policies:write")],
            ..agf_auth::api_key::ApiKeyIssueRequest::named(user.tenant, "policy-unit-key", Timestamp::now())
        });
        state.store.hydrate_api_key(&issued.record).unwrap();
        let mut principal = user.clone();
        principal.subject_id = Some(issued.record.id);
        principal.subject_kind = SubjectKind::ApiKey;
        principal.roles = Vec::new();
        principal.scopes = issued.record.scopes.clone();
        principal.session_id = None;
        let submission = mutation::Submission::management(&principal, Timestamp::now(), None);
        let proof = prepare(&state, &submission, "write").await.unwrap().unwrap();
        let mut key = issued.record;
        match mode {
            "revoked" => key.revoked = true,
            "scope" => key.scopes = Vec::new(),
            _ => key.expires_at = Some(Timestamp::now()),
        }
        state.store.hydrate_api_key(&key).unwrap();
        assert!(proof.check(&state, &submission, "write", &snapshot(&proof)).is_err());
    }
}

#[tokio::test]
async fn unchanged_role_names_do_not_preserve_removed_role_grants() {
    let (mut state, principal, lease) = fixture().await;
    let submission = mutation::Submission::management(&principal, Timestamp::now(), Some(lease));
    let proof = prepare(&state, &submission, "write").await.unwrap().unwrap();
    let now = Timestamp::now();
    std::sync::Arc::make_mut(&mut state.authorizer).upsert_role(agf_core::rbac::Role {
        id: Id::new(),
        tenant_id: principal.tenant,
        name: "tenant-admin".into(),
        display_name: "changed grants".into(),
        description: String::new(),
        permissions: vec![agf_core::rbac::Permission::from_raw("policies:read")],
        builtin: true,
        created_at: now,
        updated_at: now,
    });
    assert_eq!(current_subject(&state, &principal).unwrap().1, proof.evidence.roles);
    assert!(matches!(proof.check(&state, &submission, "write", &snapshot(&proof)), Err(DomainError::Forbidden(_))));
}

#[test]
fn a_pending_identity_backend_is_rejected_without_blocking_or_repolling() {
    assert!(matches!(ready(futures::future::pending::<DomainResult<()>>()), Err(DomainError::PreconditionFailed(_))));
}
