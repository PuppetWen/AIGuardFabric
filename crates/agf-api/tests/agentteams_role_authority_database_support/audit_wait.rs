//! Original JWT and current administrator authority must survive the actual audit wait.
use super::{Case, MARKER, Worker, gate::Gate, prepare};
use crate::common::*;
use agf_auth::claims::{IssueContext, TokenIssuer};
use agf_core::ids::Id;
use std::time::Duration;

async fn administrator(case: &Case) -> (Id, String) {
    case.check().await;
    let mut user = User::new_local(case.h.tenant, "role-admin", "role-admin@owned.test");
    user.must_change_password = false;
    assert!(!user.is_superadmin);
    let hash = case.h.state.auth.hasher().hash_checked(ADMIN_PWD, "role-admin").unwrap();
    case.h.state.auth_backend.save_account(&user, Some(&hash), &["tenant-admin".into()]).await.unwrap();
    assert_eq!(case.h.state.auth_backend.roles_of(case.h.tenant, user.id).await.unwrap(), vec!["tenant-admin"]);
    let token =
        case.h.state.auth.issue_for_user(&user, case.h.tenant, vec!["tenant-admin".into()]).unwrap().access_token;
    (user.id, token)
}
async fn unchanged(case: &Case, worker: &Worker, before: Value, attributes: Value) {
    assert_eq!(case.snapshot().await, before);
    let fresh = case.second().await;
    let asset = fresh.state.store.asset_get_durable(fresh.tenant, worker.asset).await.unwrap().unwrap();
    assert_eq!(serde_json::to_value(&asset.attributes).unwrap(), attributes);
    assert!(!asset.attributes.contains_key(MARKER));
    assert!(fresh.state.store.audit_verify_durable(fresh.tenant).await.unwrap().passed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires dedicated owner-checked AgentTeams role authority PostgreSQL"]
async fn current_administrator_user_grant_revoked_during_exact_audit_wait_rolls_back_every_authority_fact() {
    let case = Case::open("role-audit-grant").await;
    let worker = prepare(&case.h).await;
    let (user, token) = administrator(&case).await;
    let before = case.snapshot().await;
    let asset = case.h.state.store.asset_get_durable(case.h.tenant, worker.asset).await.unwrap().unwrap();
    let attributes = serde_json::to_value(asset.attributes).unwrap();
    let gate = Gate::install(&case, &worker).await;
    let response = gate.invoke(&case, &worker, token, || async {
        case.check().await;
        // Separate identity binding rows are not the Role/Agent/source rows held by publication.
        // Commit the actual privilege removal while the precise success audit INSERT is blocked.
        let revoked = sqlx::query("UPDATE role_bindings SET deleted_at=now() WHERE tenant_id=$1 AND subject_id=$2 AND subject_kind='user' AND deleted_at IS NULL")
            .bind(case.h.tenant.as_uuid()).bind(user.as_uuid()).execute(&case.pool).await.unwrap();
        assert_eq!(revoked.rows_affected(), 1);
        assert!(case.h.state.auth_backend.roles_of(case.h.tenant, user).await.unwrap().is_empty());
    }).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    unchanged(&case, &worker, before, attributes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires dedicated owner-checked AgentTeams role authority PostgreSQL"]
async fn original_signed_administrator_jwt_expiring_during_exact_audit_wait_rolls_back_every_authority_fact() {
    let case = Case::open("role-audit-expiry").await;
    let worker = prepare(&case.h).await;
    let existing = case.h.state.auth.issuer().verify(&case.h.admin).unwrap();
    let issuer = TokenIssuer::new(
        &case.h.state.config.security.jwt_secret,
        existing.iss.clone(),
        existing.aud.clone(),
        10,
        case.h.state.config.security.jwt_refresh_ttl_secs,
    )
    .unwrap();
    let context = IssueContext {
        subject: Id::parse(&existing.sub).unwrap(),
        tenant: TenantId::parse(&existing.tenant_id).unwrap(),
        kind: existing.subject_kind,
        roles: existing.roles,
        superadmin: existing.superadmin,
        must_change_password: existing.must_change_password,
        session_id: existing.session_id,
    };
    let before = case.snapshot().await;
    let asset = case.h.state.store.asset_get_durable(case.h.tenant, worker.asset).await.unwrap().unwrap();
    let attributes = serde_json::to_value(asset.attributes).unwrap();
    let gate = Gate::install(&case, &worker).await;
    let token = issuer.issue_access(&context, Timestamp::now()).unwrap();
    let claims = case.h.state.auth.issuer().verify(&token).unwrap();
    assert_eq!(claims.exp - claims.iat, 10);
    let response = gate
        .invoke(&case, &worker, token, || async {
            assert!(
                !claims.is_expired(Timestamp::now().unix_secs()),
                "the original signed JWT must still be valid at the actual audit wait"
            );
            tokio::time::timeout(Duration::from_secs(12), async {
                while !claims.is_expired(Timestamp::now().unix_secs()) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("signed JWT did not expire within bounded real time");
        })
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    unchanged(&case, &worker, before, attributes).await;
}
