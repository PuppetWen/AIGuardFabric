//! Additional fixed grants and original identity are checked by the same offline proof as policy writes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::{rbac::SubjectKind, user::User};
use axum::http::{HeaderMap, HeaderValue, header};
use std::collections::BTreeMap;

static WRITE: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "write",
    additional: &[Grant { resource: "alicloud", action: "read" }, Grant { resource: "policies", action: "read" }],
};
static DENIED_EXTRA: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "read",
    additional: &[Grant { resource: "unknown-grant", action: "write" }],
};

async fn fixture() -> (AppState, Principal, AccessLease, User) {
    let mut env: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_JWT_SECRET", "publication-auth-owned-secret-at-least-32-bytes"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_PROJECT_ROOT", "."),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    let data = std::env::var_os("AGF_TEST_DATA_DIR").map_or_else(
        || std::path::PathBuf::from("./target/test-data/publication-authority"),
        |root| std::path::PathBuf::from(root).join("publication-authority"),
    );
    env.insert("AGF_DATA_DIR".into(), data.to_string_lossy().into_owned());
    let state = AppState::offline(agf_core::config::from_env_map(&env).unwrap()).unwrap();
    let tenant = TenantId::default_tenant();
    let mut user = User::new_local(tenant, "publication-editor", "publication@owned.local");
    user.must_change_password = false;
    state.auth_backend.save_account(&user, None, &["tenant-admin".into()]).await.unwrap();
    let issued = state.auth.issue_for_user(&user, tenant, vec!["tenant-admin".into()]).unwrap();
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
        session_id: Some(issued.session_id),
        source_ip: None,
        user_agent: None,
        department: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", issued.access_token)).unwrap());
    let lease = AccessLease::capture(&state, &principal, &headers).unwrap().unwrap();
    (state, principal, lease, user)
}
async fn locked(state: &AppState, submission: &AuthorizedSubmission<'_>) -> OfflineGuardedSnapshot {
    let security = OfflinePublicationProof::security(submission).unwrap();
    OfflineGuardedSnapshot {
        guards: BTreeMap::new(),
        tenant_directory: state
            .configurations
            .get(TenantId::default_tenant(), "tenant-directory", tenant_record_id(TenantId::default_tenant()))
            .await
            .unwrap(),
        password_policy: state
            .configurations
            .get(security.identity_tenant, crate::auth_policy::KIND, tenant_record_id(security.identity_tenant))
            .await
            .unwrap(),
        mfa_enrollment: state
            .configurations
            .get(security.identity_tenant, crate::mfa_store::KIND, security.subject_id)
            .await
            .unwrap(),
    }
}

#[tokio::test]
async fn a_valid_cloud_grant_does_not_replace_a_missing_additional_grant() {
    let (mut state, principal, lease, _) = fixture().await;
    let now = Timestamp::now();
    let role = agf_core::rbac::Role {
        id: Id::new(),
        tenant_id: principal.tenant,
        name: "tenant-admin".into(),
        display_name: "Owned cloud reader".into(),
        description: String::new(),
        permissions: vec![agf_core::rbac::Permission::from_raw("alicloud:read")],
        builtin: false,
        created_at: now,
        updated_at: now,
    };
    state.authorizer = std::sync::Arc::new(agf_auth::rbac::Authorizer::from_parts(vec![role], Vec::new()));
    authority::authorize_for(&state, &principal, "alicloud", "read", Timestamp::now(), Some(&lease)).await.unwrap();
    let submission = AuthorizedSubmission {
        principal: &principal,
        submitted_at: Timestamp::now(),
        lease: Some(&lease),
        authorization: &DENIED_EXTRA,
    };
    assert!(authorize_publication(&state, &submission).await.is_err());
    assert!(OfflinePublicationProof::prepare(&state, &submission).await.is_err());
}

#[tokio::test]
async fn publication_proof_rejects_current_role_changes_and_wrong_scope() {
    let (state, principal, lease, user) = fixture().await;
    let submission = AuthorizedSubmission {
        principal: &principal,
        submitted_at: Timestamp::now(),
        lease: Some(&lease),
        authorization: &WRITE,
    };
    let proof = OfflinePublicationProof::prepare(&state, &submission).await.unwrap();
    let snapshot = locked(&state, &submission).await;
    proof.check(&state, &submission, &snapshot).unwrap();
    let mut wrong_scope = principal.clone();
    wrong_scope.tenant = TenantId::new();
    let wrong = AuthorizedSubmission {
        principal: &wrong_scope,
        submitted_at: submission.submitted_at,
        lease: Some(&lease),
        authorization: &WRITE,
    };
    assert!(proof.check(&state, &wrong, &snapshot).is_err());
    let current = state.auth_backend.find_user(user.tenant_id, user.id).await.unwrap().unwrap();
    state.auth_backend.save_account(&current, None, &[]).await.unwrap();
    assert!(proof.check(&state, &submission, &snapshot).is_err());
    assert!(authorize_publication(&state, &submission).await.is_err());
}
