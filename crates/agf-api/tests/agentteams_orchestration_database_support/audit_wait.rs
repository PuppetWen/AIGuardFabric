//! Original signed JWT and current administrator grants survive the real terminal audit wait.
use super::{Case, gate::Gate};
use crate::{BASE, KIND, common::*, input, prepare, uri};
use agf_auth::claims::{IssueContext, TokenIssuer};
use agf_core::ids::Id;
use std::time::Duration;
async fn unchanged(case: &Case, request: &Value, before: Value) {
    let fresh = case.second().await;
    let now = json!({"rows":fresh.state.configurations.list::<Value>(fresh.tenant,KIND).await.unwrap(),
        "audit":fresh.state.store.audit_stats_durable(fresh.tenant).await.unwrap()});
    assert_eq!(now, before);
    assert_eq!(
        fresh.get(&format!("{BASE}/requests/{}", request["request_id"].as_str().unwrap())).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(fresh.state.store.audit_verify_durable(fresh.tenant).await.unwrap().passed);
}
async fn snapshot(case: &Case) -> Value {
    json!({"rows":case.h.state.configurations.list::<Value>(case.h.tenant,KIND).await.unwrap(),
        "audit":case.h.state.store.audit_stats_durable(case.h.tenant).await.unwrap()})
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires separate exact-owner AgentTeams orchestration PostgreSQL"]
async fn administrator_grant_revoked_during_audit_wait_rolls_back_definition_receiver_intent_and_audit() {
    let case = Case::open("orch-grant-wait").await;
    let target = prepare(&case.h).await;
    let body = input(&target);
    case.check().await;
    let mut user = User::new_local(case.h.tenant, "orchestration-admin", "orchestration-admin@owned.test");
    user.must_change_password = false;
    assert!(!user.is_superadmin);
    let phc = case.h.state.auth.hasher().hash_checked(ADMIN_PWD, "orchestration-admin").unwrap();
    case.h.state.auth_backend.save_account(&user, Some(&phc), &["tenant-admin".into()]).await.unwrap();
    assert_eq!(case.h.state.auth_backend.roles_of(case.h.tenant, user.id).await.unwrap(), vec!["tenant-admin"]);
    let token =
        case.h.state.auth.issue_for_user(&user, case.h.tenant, vec!["tenant-admin".into()]).unwrap().access_token;
    let before = snapshot(&case).await;
    let gate = Gate::install(&case, &body).await;
    let response=gate.invoke(&case,uri(&target),body.clone(),token,||async{
        case.check().await;
        let changed=sqlx::query("UPDATE role_bindings SET deleted_at=now() WHERE tenant_id=$1 AND subject_id=$2 AND subject_kind='user' AND deleted_at IS NULL")
            .bind(case.h.tenant.as_uuid()).bind(user.id.as_uuid()).execute(&case.pool).await.unwrap();
        assert_eq!(changed.rows_affected(),1);
        assert!(case.h.state.auth_backend.roles_of(case.h.tenant,user.id).await.unwrap().is_empty());
    }).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    unchanged(&case, &body, before).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires separate exact-owner AgentTeams orchestration PostgreSQL"]
async fn original_jwt_expiring_during_audit_wait_rolls_back_definition_receiver_intent_and_audit() {
    let case = Case::open("orch-expiry-wait").await;
    let target = prepare(&case.h).await;
    let body = input(&target);
    let original = case.h.state.auth.issuer().verify(&case.h.admin).unwrap();
    let issuer = TokenIssuer::new(
        &case.h.state.config.security.jwt_secret,
        original.iss.clone(),
        original.aud.clone(),
        10,
        case.h.state.config.security.jwt_refresh_ttl_secs,
    )
    .unwrap();
    let context = IssueContext {
        subject: Id::parse(&original.sub).unwrap(),
        tenant: TenantId::parse(&original.tenant_id).unwrap(),
        kind: original.subject_kind,
        roles: original.roles,
        superadmin: original.superadmin,
        must_change_password: original.must_change_password,
        session_id: original.session_id,
    };
    let before = snapshot(&case).await;
    let gate = Gate::install(&case, &body).await;
    let token = issuer.issue_access(&context, Timestamp::now()).unwrap();
    let claims = case.h.state.auth.issuer().verify(&token).unwrap();
    assert_eq!(claims.exp - claims.iat, 10);
    let response = gate
        .invoke(&case, uri(&target), body.clone(), token, || async {
            assert!(!claims.is_expired(Timestamp::now().unix_secs()));
            tokio::time::timeout(Duration::from_secs(12), async {
                while !claims.is_expired(Timestamp::now().unix_secs()) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("original signed JWT must expire in bounded real time");
        })
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    unchanged(&case, &body, before).await;
}
