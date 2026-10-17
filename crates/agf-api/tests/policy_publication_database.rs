//! Owned PostgreSQL proves policy/history/audit rollback, CAS and final authority checks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
#[path = "policy_publication_support/audit_gate.rs"]
mod policy_gate;
mod policy_publication_support;
#[path = "policy_publication_support/sql_owner.rs"]
mod policy_sql;
use common::*;
use policy_gate::{Mode, Pending, Target, with_audit};
use policy_publication_support::loopback::Fixture;
use policy_publication_support::*;

#[derive(Clone, Copy)]
enum Mutation {
    Create,
    Update,
    Delete,
    Restore,
}

async fn audit_failure(label: &str, mutation: Mutation) {
    let case = policy_sql::open(label).await;
    let f = Fixture::attach(case.h.clone()).await;
    let first =
        create(&f.h, "policy-audit-baseline", if matches!(mutation, Mutation::Delete) { "deny" } else { "allow" })
            .await;
    let current = if matches!(mutation, Mutation::Restore) {
        let response = update(&f.h, &first, "deny").await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        response.json()["policy"].clone()
    } else {
        first
    };
    let denied = matches!(mutation, Mutation::Delete | Mutation::Restore);
    f.assert_gateway(denied).await;
    let before = registry(&f.h).await;
    let versions = history(&f.h, id(&current)).await;
    let audits = serde_json::to_value(policy_audits(&f.h).await).unwrap();
    let second = case.second_instance().await;
    let (method, uri, payload, target) = match mutation {
        Mutation::Create => (
            "POST",
            POLICIES.into(),
            Some(body("policy-audit-new", "deny", Some(0))),
            Target { id: None, name: "policy-audit-new".into(), action: "create" },
        ),
        Mutation::Update => (
            "PUT",
            path(id(&current)),
            Some(body("policy-audit-baseline", "deny", current["version"].as_u64())),
            Target { id: Some(id(&current)), name: "policy-audit-baseline".into(), action: "update" },
        ),
        Mutation::Delete => (
            "DELETE",
            format!("{}?expected_version={}", path(id(&current)), current["version"]),
            None,
            Target { id: Some(id(&current)), name: "policy-audit-baseline".into(), action: "delete" },
        ),
        Mutation::Restore => (
            "POST",
            restore_path(id(&current), 1),
            Some(json!({"version":1,"expected_version":current["version"]})),
            Target { id: Some(id(&current)), name: "policy-audit-baseline".into(), action: "update" },
        ),
    };
    with_audit(&case.pool, f.h.tenant, target, Mode::Reject, move |_gate| {
        Box::pin(async move {
            let response = f.h.request(method, &uri, Some(&f.h.admin), payload).await;
            assert!(
                response.status.is_server_error(),
                "valid policy candidate must fail at audit INSERT: {}",
                response.text
            );
            assert_eq!(registry(&f.h).await, before, "entire signed registry/history must roll back");
            assert_eq!(history(&f.h, id(&current)).await, versions);
            assert_eq!(serde_json::to_value(policy_audits(&f.h).await).unwrap(), audits);
            assert_eq!(registry(&second).await, before, "a fresh instance must not see an uncommitted candidate");
            // The rejection trigger only targets this policy mutation, not runtime interception audits.
            f.assert_gateway(denied).await;
            intact_chain(&f.h).await;
        })
    })
    .await;
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn create_audit_failure_does_not_activate_or_record_the_candidate() {
    audit_failure("pol-create-audit", Mutation::Create).await;
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn update_audit_failure_preserves_the_signed_revision_and_real_allow_decision() {
    audit_failure("pol-update-audit", Mutation::Update).await;
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn delete_audit_failure_preserves_the_signed_revision_and_real_deny_decision() {
    audit_failure("pol-delete-audit", Mutation::Delete).await;
}
#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn restore_audit_failure_preserves_current_history_and_real_deny_decision() {
    audit_failure("pol-restore-audit", Mutation::Restore).await;
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn two_api_instances_with_the_same_revision_have_one_winner_and_one_success_audit() {
    let case = policy_sql::open("pol-concurrent-cas").await;
    let f = Fixture::attach(case.h.clone()).await;
    let first = create(&f.h, "policy-concurrent", "allow").await;
    f.assert_gateway(false).await;
    let second = live(case.second_instance().await);
    let uri = path(id(&first));
    let (left, right) = tokio::join!(
        f.h.request("PUT", &uri, Some(&f.h.admin), Some(body("policy-concurrent", "deny", Some(1)))),
        second.request("PUT", &uri, Some(&second.admin), Some(body("policy-concurrent", "audit", Some(1))))
    );
    let statuses = [left.status, right.status];
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!(
        statuses.iter().filter(|status| **status == StatusCode::CONFLICT).count(),
        1,
        "{} / {}",
        left.text,
        right.text
    );
    let winner =
        if left.status == StatusCode::OK { left.json()["policy"].clone() } else { right.json()["policy"].clone() };
    assert_eq!(winner["version"], 2);
    assert_signed(&f.h, &winner);
    assert_eq!(successes(&f.h, id(&first), "update").await, 1);
    assert_eq!(history(&f.h, id(&first)).await["versions"].as_array().unwrap().len(), 2);
    assert_eq!(registry(&f.h).await, registry(&second).await);
    let denied = winner["action"] == "deny";
    f.assert_gateway(denied).await;
    let before = f.calls("/chat/completions").await;
    let response = f.gateway_for(&second).await;
    assert_eq!(response.status, if denied { StatusCode::FORBIDDEN } else { StatusCode::OK }, "{}", response.text);
    assert_eq!(f.calls("/chat/completions").await, before + usize::from(!denied));
    let fresh = case.second_instance().await;
    assert_eq!(fresh.get(&uri).await.json()["policy"], winner);
    intact_chain(&fresh).await;
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn revoking_the_original_key_while_success_audit_waits_rolls_back_every_policy_change() {
    let case = policy_sql::open("pol-key-audit-guard").await;
    let f = Fixture::attach(case.h.clone()).await;
    let first = create(&f.h, "policy-key-authority", "allow").await;
    f.assert_gateway(false).await;
    let before = registry(&f.h).await;
    let versions = history(&f.h, id(&first)).await;
    let (token, key) = policy_gate::key(&f.h).await;
    let pool = case.pool.clone();
    let target = Target { id: Some(id(&first)), name: "policy-key-authority".into(), action: "update" };
    with_audit(&case.pool, f.h.tenant, target, Mode::Wait, move |gate| {
        Box::pin(async move {
            let pending = Pending::start(
                f.h.clone(),
                "PUT",
                path(id(&first)),
                token,
                Some(body("policy-key-authority", "deny", Some(1))),
            );
            gate.waiting().await;
            policy_gate::revoke(&pool, f.h.tenant, key).await;
            gate.release().await;
            let response = pending.finish().await;
            assert_eq!(response.status, StatusCode::FORBIDDEN, "{}", response.text);
            assert_eq!(registry(&f.h).await, before);
            assert_eq!(history(&f.h, id(&first)).await, versions);
            assert_eq!(successes(&f.h, id(&first), "update").await, 0);
            assert_eq!(f.h.get(&path(id(&first))).await.json()["policy"], first);
            f.assert_gateway(false).await;
            intact_chain(&f.h).await;
        })
    })
    .await;
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn invalidating_the_original_user_session_during_audit_wait_rolls_back_publication() {
    let case = policy_sql::open("pol-session-audit-guard").await;
    let f = Fixture::attach(case.h.clone()).await;
    let first = create(&f.h, "policy-session-authority", "allow").await;
    let before = registry(&f.h).await;
    let versions = history(&f.h, id(&first)).await;
    // The editor has a distinct identity; independent admin inspection remains authorized.
    // A role named superadmin does not grant cross-tenant identity: this account belongs to the owned tenant.
    let mut editor = User::new_local(f.h.tenant, "owned-policy-editor", "policy-editor@owned.test");
    editor.must_change_password = false;
    f.h.state.auth_backend.save_account(&editor, None, &["superadmin".into()]).await.unwrap();
    let token =
        f.h.state.auth.issue_for_user(&editor, editor.tenant_id, vec!["superadmin".into()]).unwrap().access_token;
    let claims = f.h.state.auth.issuer().verify(&token).unwrap();
    assert_eq!(claims.sub, editor.id.to_string());
    assert_eq!(claims.tenant_id, f.h.tenant.to_string());
    assert!(!claims.superadmin && !claims.session_id.is_empty() && claims.issued_at_ms > 0);
    let issued_at = claims.issued_at_ms;
    assert!(f.h.state.auth_backend.session_valid(editor.tenant_id, &editor, issued_at).await.unwrap());
    let readable = f.h.request("GET", &path(id(&first)), Some(&token), None).await;
    assert_eq!(readable.status, StatusCode::OK, "{}", readable.text);
    assert_eq!(readable.json()["policy"], first);
    let audits = serde_json::to_value(policy_audits(&f.h).await).unwrap();
    let audit_tail = f.h.state.store.audit_stats_durable(f.h.tenant).await.unwrap();
    let target = Target { id: Some(id(&first)), name: "policy-session-authority".into(), action: "update" };
    with_audit(&case.pool, f.h.tenant, target, Mode::Wait, move |gate| {
        Box::pin(async move {
            let pending = Pending::start(
                f.h.clone(),
                "PUT",
                path(id(&first)),
                token,
                Some(body("policy-session-authority", "deny", Some(1))),
            );
            gate.waiting().await;
            // save_account advances the stored revision; read the current record for the legal CAS update.
            let mut current = f.h.state.auth_backend.find_user(editor.tenant_id, editor.id).await.unwrap().unwrap();
            assert_eq!(current.id, editor.id);
            assert_eq!(current.tenant_id, f.h.tenant);
            assert!(current.version > editor.version);
            assert!(f.h.state.auth_backend.session_valid(current.tenant_id, &current, issued_at).await.unwrap());
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                while Timestamp::now().unix_millis() <= issued_at {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            })
            .await
            .expect("session invalidation must cross the original JWT issuance millisecond");
            let prior_version = current.version;
            current.password_changed_at = Some(Timestamp::now());
            f.h.state.auth_backend.save_user(&current, None).await.unwrap();
            let saved = f.h.state.auth_backend.find_user(current.tenant_id, current.id).await.unwrap().unwrap();
            assert_eq!(saved.version, prior_version + 1);
            assert_eq!(saved.password_changed_at, current.password_changed_at);
            assert!(!f.h.state.auth_backend.session_valid(saved.tenant_id, &saved, issued_at).await.unwrap());
            gate.release().await;
            let response = pending.finish().await;
            assert_eq!(response.status, StatusCode::FORBIDDEN, "{}", response.text);
            assert_eq!(registry(&f.h).await, before);
            assert_eq!(history(&f.h, id(&first)).await, versions);
            assert_eq!(serde_json::to_value(policy_audits(&f.h).await).unwrap(), audits);
            assert_eq!(f.h.state.store.audit_stats_durable(f.h.tenant).await.unwrap(), audit_tail);
            assert_eq!(successes(&f.h, id(&first), "update").await, 0);
            f.assert_gateway(false).await;
            intact_chain(&f.h).await;
        })
    })
    .await;
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn the_original_signed_jwt_expiring_while_audit_waits_cannot_commit_a_policy_revision() {
    use agf_auth::claims::{IssueContext, TokenIssuer};
    let case = policy_sql::open("pol-jwt-expiry-audit").await;
    let f = Fixture::attach(case.h.clone()).await;
    let first = create(&f.h, "policy-jwt-expiry", "allow").await;
    f.assert_gateway(false).await;
    let before = registry(&f.h).await;
    let versions = history(&f.h, id(&first)).await;
    let audits = serde_json::to_value(policy_audits(&f.h).await).unwrap();
    let audit_stats = f.h.state.store.audit_stats_durable(f.h.tenant).await.unwrap();
    let target = Target { id: Some(id(&first)), name: "policy-jwt-expiry".into(), action: "update" };
    with_audit(&case.pool, f.h.tenant, target, Mode::Wait, move |gate| {
        Box::pin(async move {
            // Reuse the actual verified admin identity/session and the configured signing key.
            // Only this issuer's public TTL parameter changes; no Principal or clock is fabricated.
            let existing = f.h.state.auth.issuer().verify(&f.h.admin).unwrap();
            let issuer = TokenIssuer::new(
                &f.h.state.config.security.jwt_secret,
                existing.iss.clone(),
                existing.aud.clone(),
                10,
                f.h.state.config.security.jwt_refresh_ttl_secs,
            )
            .unwrap();
            let context = IssueContext {
                subject: agf_core::ids::Id::parse(&existing.sub).unwrap(),
                tenant: TenantId::parse(&existing.tenant_id).unwrap(),
                kind: existing.subject_kind,
                roles: existing.roles,
                superadmin: existing.superadmin,
                must_change_password: existing.must_change_password,
                session_id: existing.session_id,
            };
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(12);
            let token = issuer.issue_access(&context, Timestamp::now()).unwrap();
            let claims = f.h.state.auth.issuer().verify(&token).unwrap();
            assert_eq!(claims.exp - claims.iat, 10);
            assert!(!claims.is_expired(Timestamp::now().unix_secs()));
            let pending = Pending::start(
                f.h.clone(),
                "PUT",
                path(id(&first)),
                token,
                Some(body("policy-jwt-expiry", "deny", Some(1))),
            );
            gate.waiting().await; // pg_locks proves the handler reached the exact SQL INSERT gate.
            assert!(
                !claims.is_expired(Timestamp::now().unix_secs()),
                "the request must reach the gate while authorized"
            );
            tokio::time::timeout_at(deadline, async {
                while !claims.is_expired(Timestamp::now().unix_secs()) {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("the real signed JWT must expire within twelve seconds of issuance");
            assert!(claims.is_expired(Timestamp::now().unix_secs()));
            gate.release().await;
            let response = pending.finish().await;
            assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{}", response.text);
            assert_eq!(registry(&f.h).await, before);
            assert_eq!(history(&f.h, id(&first)).await, versions);
            assert_eq!(serde_json::to_value(policy_audits(&f.h).await).unwrap(), audits);
            assert_eq!(f.h.state.store.audit_stats_durable(f.h.tenant).await.unwrap(), audit_stats);
            assert_eq!(successes(&f.h, id(&first), "update").await, 0);
            assert_eq!(f.h.get(&path(id(&first))).await.json()["policy"], first);
            f.assert_gateway(false).await;
            intact_chain(&f.h).await;
        })
    })
    .await;
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn restart_reads_committed_signed_history_without_leaking_another_tenants_same_named_policy() {
    let case = policy_sql::open("pol-restart-tenant").await;
    let f = Fixture::attach(case.h.clone()).await;
    let first = create(&f.h, "policy-shared-name", "allow").await;
    let changed = update(&f.h, &first, "deny").await;
    assert_eq!(changed.status, StatusCode::OK);
    let second = changed.json()["policy"].clone();
    let restored = restore(&f.h, &second, 1).await;
    assert_eq!(restored.status, StatusCode::OK);
    let current = restored.json()["policy"].clone();
    let other = Fixture::attach(case.foreign_instance().await).await;
    let foreign = create(&other.h, "policy-shared-name", "deny").await;
    assert_eq!(other.h.get(&path(id(&first))).await.status, StatusCode::NOT_FOUND);
    assert_eq!(f.h.get(&path(id(&foreign))).await.status, StatusCode::NOT_FOUND);
    f.assert_gateway(false).await;
    other.assert_gateway(true).await;
    let fresh = live(case.second_instance().await);
    assert_eq!(fresh.get(&path(id(&first))).await.json()["policy"], current);
    assert_eq!(history(&fresh, id(&first)).await, history(&f.h, id(&first)).await);
    assert_eq!(registry(&fresh).await, registry(&f.h).await);
    intact_chain(&fresh).await;
    intact_chain(&other.h).await;
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn a_valid_signature_cannot_move_a_foreign_policy_into_this_tenants_history() {
    let case = policy_sql::open("pol-history-tenant").await;
    let first = create(&case.h, "policy-history-owner", "allow").await;
    assert_eq!(update(&case.h, &first, "deny").await.status, StatusCode::OK);
    let other = case.foreign_instance().await;
    let foreign = create(&other, "policy-foreign-history", "deny").await;
    assert_signed(&other, &foreign);
    let mut corrupted = registry(&case.h).await;
    corrupted["history"][id(&first).to_string()][0] = foreign;
    replace_registry(&case.h, &corrupted).await;
    let audit_count = policy_audits(&case.h).await.len();
    let fresh = case.second_instance().await;
    assert!(!fresh.get(&format!("{}/versions", path(id(&first)))).await.status.is_success());
    let response = fresh.post(&restore_path(id(&first), 1), json!({"version":1,"expected_version":2})).await;
    assert!(!response.status.is_success(), "{}", response.text);
    assert_eq!(registry(&fresh).await, corrupted);
    assert_eq!(policy_audits(&fresh).await.len(), audit_count);
    intact_chain(&fresh).await;
    intact_chain(&other).await;
    case.pool.close().await;
}
