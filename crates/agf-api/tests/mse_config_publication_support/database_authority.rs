//! Durable authority must be checked after real network or audit-tail waits using the original lease.
use crate::{
    common::*,
    publication_db as db,
    publication_gate::{Mode, Target, with_gate},
    transport::*,
};
use agf_core::{error::DomainResult, ids::Id};
use std::time::Duration;

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn durable_identity_or_source_changes_across_real_network_waits_preserve_delivery_evidence() -> DomainResult<()> {
    for scope_only in [false, true] {
        preflight_key_change(scope_only).await?;
    }
    for change in ["configuration", "policy", "mode"] {
        delivered_source_change(change).await?;
    }
    Ok(())
}

async fn preflight_key_change(scope_only: bool) -> DomainResult<()> {
    let case = db::open(if scope_only { "mse-pub-key-scope" } else { "mse-pub-key-revoke" }).await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let preview = f.ready().await?;
    let second = route(case.second_instance().await, f.engine.address)?;
    let (token, key) = db::key(&f.h).await?;
    let request = Id::new();
    f.engine.hold("GET", 2).await;
    let pending = Pending::start(f.h.clone(), format!("{BASE}/operations"), token, apply_input(&preview, request)?);
    f.engine.waiting("GET", 2).await?;
    db::revoke(&case.pool, f.h.tenant, key, scope_only).await?;
    f.engine.release();
    let response = pending.finish().await?;
    assert!(response.status.is_success() || response.status == StatusCode::FORBIDDEN);
    assert_eq!(f.engine.counts().await, (2, 0));
    assert_eq!(f.engine.content().await, INITIAL);
    let observed = read(&second, &receipt(request)).await?;
    assert_eq!(observed["cloudWrite"]["status"], "not_attempted");
    assert_ne!(observed["status"], "verified");
    assert!(audits(&second, request, "mse-config-publication").await?.is_empty());
    let recovered = post(&second, &format!("{}/recover", receipt(request)), json!({})).await?;
    assert_eq!(recovered["cloudWrite"]["status"], "not_attempted");
    assert_eq!(recovered["completionState"], "complete");
    assert_eq!(f.engine.counts().await, (2, 0));
    db::chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

async fn delivered_source_change(change: &str) -> DomainResult<()> {
    let case = db::open("mse-pub-delivered-fence").await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    f.engine.hold("POST", 1).await;
    let pending =
        Pending::start(f.h.clone(), format!("{BASE}/operations"), f.h.admin.clone(), apply_input(&preview, request)?);
    f.engine.waiting("POST", 1).await?;
    assert_ne!(f.engine.content().await, INITIAL);
    let accepted_content = f.engine.content().await;
    match change {
        "configuration" => configure(&f.h, f.engine.address, 1, false).await?,
        "policy" => {
            let response =
                f.h.request(
                    "PUT",
                    &format!("/api/v1/policies/{}", id(&f.policy, "id")?),
                    Some(&f.h.admin),
                    Some(json!({
                    "expected_version":1,"name":f.policy["name"],"language":"cel","source":"{\"action\":\"deny\"}",
                    "action":"deny","enabled":true,"priority":1,"intercept_points":["ai-gateway","mcp-proxy"]})),
                )
                .await;
            assert_eq!(response.status, StatusCode::OK);
        }
        _ => {
            let response =
                f.h.request(
                    "PUT",
                    CONFIG,
                    Some(&f.h.admin),
                    Some(json!({"expected_version":1,"enabled":true,
                    "mock":true,"settings":settings(f.engine.address)})),
                )
                .await;
            assert_eq!(response.status, StatusCode::OK);
        }
    }
    f.engine.release();
    let response = pending.finish().await?;
    assert_eq!(response.status, StatusCode::OK);
    let known = response.json();
    assert_eq!(known["cloudWrite"]["status"], "accepted");
    assert_eq!(known["readback"]["status"], "unavailable");
    assert_eq!(known["completionState"], "pending_audit");
    assert_eq!(f.engine.counts().await, (2, 1));
    assert!(audits(&f.h, request, "mse-config-publication").await?.is_empty());
    let original_fact = db::row(&f.h, FACT, db::fact_id(f.h.tenant, request)).await?;
    let original_versions = original_fact["outcome"]["receipt"]["source_policy_versions"].clone();
    assert_eq!(original_versions, json!([{"policy_id":id(&f.policy,"id")?,"version":1}]));
    let second = case.second_instance().await;
    let recovered = post(&second, &format!("{}/recover", receipt(request)), json!({})).await?;
    assert_eq!(recovered["target"], known["target"]);
    assert_eq!(
        db::row(&second, FACT, db::fact_id(second.tenant, request)).await?["outcome"]["receipt"]["source_policy_versions"],
        original_versions
    );
    assert_eq!(recovered["status"], "uncertain");
    assert_eq!(recovered["cloudWrite"]["status"], "accepted");
    assert_eq!(recovered["readback"]["status"], "unavailable");
    assert_eq!(recovered["completionState"], "complete");
    assert_eq!(f.engine.counts().await, (2, 1));
    assert_eq!(f.engine.content().await, accepted_content);
    db::chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn original_key_revoked_while_claim_audit_waits_rolls_back_claim_and_consumption() -> DomainResult<()> {
    let case = db::open("mse-pub-claim-authority").await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let (token, key) = db::key(&f.h).await?;
    let before = snapshot(&f.h).await?;
    let pool = case.pool.clone();
    with_gate(
        &case.pool,
        f.h.tenant,
        Target { kind: "mse-config-publication-claim", id: request, action: "configure" },
        Mode::Wait,
        move |gate| {
            Box::pin(async move {
                let pending =
                    Pending::start(f.h.clone(), format!("{BASE}/operations"), token, apply_input(&preview, request)?);
                gate.waiting().await?;
                db::revoke(&pool, f.h.tenant, key, false).await?;
                gate.release().await?;
                let response = pending.finish().await?;
                assert_eq!(response.status, StatusCode::FORBIDDEN, "{}", response.text);
                assert_eq!(snapshot(&f.h).await?, before);
                assert_eq!(f.engine.counts().await, (1, 0));
                assert_eq!(f.h.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
                db::chain(&f.h).await
            })
        },
    )
    .await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn terminal_audit_wait_then_key_or_original_session_invalidation_retains_only_known_pending_evidence()
-> DomainResult<()> {
    for session in [false, true] {
        let case = db::open(if session { "mse-pub-terminal-session" } else { "mse-pub-terminal-key" }).await?;
        let f = Fixture::attach(case.h.clone()).await?;
        let preview = f.ready().await?;
        let request = Id::new();
        let (token, user, key, issued) = if session {
            let mut user = User::new_local(f.h.tenant, "owned-mse-editor", "mse-editor@owned.test");
            user.must_change_password = false;
            f.h.state.auth_backend.save_account(&user, None, &["superadmin".into()]).await?;
            let token = f.h.state.auth.issue_for_user(&user, user.tenant_id, vec!["superadmin".into()])?.access_token;
            let claims = f.h.state.auth.issuer().verify(&token)?;
            assert!(f.h.state.auth_backend.session_valid(user.tenant_id, &user, claims.issued_at_ms).await?);
            assert_eq!(f.h.request("GET", BASE, Some(&token), None).await.status, StatusCode::OK);
            (token, Some(user), None, claims.issued_at_ms)
        } else {
            let (token, key) = db::key(&f.h).await?;
            (token, None, Some(key), 0)
        };
        let pool = case.pool.clone();
        with_gate(
            &case.pool,
            f.h.tenant,
            Target { kind: "mse-config-publication", id: request, action: "execute" },
            Mode::Wait,
            move |gate| {
                Box::pin(async move {
                    let pending = Pending::start(
                        f.h.clone(),
                        format!("{BASE}/operations"),
                        token,
                        apply_input(&preview, request)?,
                    );
                    gate.waiting().await?;
                    assert_eq!(f.engine.counts().await, (3, 1));
                    let before = snapshot(&f.h).await?;
                    if let Some(user) = user {
                        let mut current =
                            f.h.state.auth_backend.find_user(user.tenant_id, user.id).await?.ok_or_else(|| {
                                agf_core::error::DomainError::Internal("owned editor disappeared".into())
                            })?;
                        tokio::time::timeout(Duration::from_secs(2), async {
                            while Timestamp::now().unix_millis() <= issued {
                                tokio::time::sleep(Duration::from_millis(2)).await;
                            }
                        })
                        .await
                        .map_err(|_| agf_core::error::DomainError::Timeout("real session issuance boundary".into()))?;
                        current.password_changed_at = Some(Timestamp::now());
                        f.h.state.auth_backend.save_user(&current, None).await?;
                        assert!(!f.h.state.auth_backend.session_valid(current.tenant_id, &current, issued).await?);
                    } else if let Some(key) = key {
                        db::revoke(&pool, f.h.tenant, key, false).await?;
                    }
                    gate.release().await?;
                    let response = pending.finish().await?;
                    assert!(response.status.is_success() || response.status == StatusCode::FORBIDDEN);
                    assert_eq!(
                        snapshot(&f.h).await?,
                        before,
                        "terminal transaction must not leak business or success audit after authority changes"
                    );
                    assert!(audits(&f.h, request, "mse-config-publication").await?.is_empty());
                    let staged = read(&f.h, &receipt(request)).await?;
                    assert_eq!(staged["completionState"], "pending_audit");
                    assert_eq!(staged["cloudWrite"]["status"], "accepted");
                    assert_eq!(staged["readback"]["status"], "matched");
                    let recovered = post(&f.h, &format!("{}/recover", receipt(request)), json!({})).await?;
                    verified(&recovered);
                    assert_eq!(f.engine.counts().await, (3, 1));
                    db::chain(&f.h).await
                })
            },
        )
        .await?;
        case.pool.close().await;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn real_signed_original_jwt_expires_during_terminal_audit_and_requires_fresh_local_recovery() -> DomainResult<()>
{
    use agf_auth::claims::{IssueContext, TokenIssuer};
    let case = db::open("mse-pub-terminal-jwt").await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    with_gate(
        &case.pool,
        f.h.tenant,
        Target { kind: "mse-config-publication", id: request, action: "execute" },
        Mode::Wait,
        move |gate| {
            Box::pin(async move {
                let existing = f.h.state.auth.issuer().verify(&f.h.admin)?;
                let issuer = TokenIssuer::new(
                    &f.h.state.config.security.jwt_secret,
                    existing.iss.clone(),
                    existing.aud.clone(),
                    10,
                    f.h.state.config.security.jwt_refresh_ttl_secs,
                )?;
                let context = IssueContext {
                    subject: Id::parse(&existing.sub)?,
                    tenant: TenantId::parse(&existing.tenant_id)?,
                    kind: existing.subject_kind,
                    roles: existing.roles,
                    superadmin: existing.superadmin,
                    must_change_password: existing.must_change_password,
                    session_id: existing.session_id,
                };
                let token = issuer.issue_access(&context, Timestamp::now())?;
                let claims = f.h.state.auth.issuer().verify(&token)?;
                assert_eq!(claims.exp - claims.iat, 10);
                let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
                let pending =
                    Pending::start(f.h.clone(), format!("{BASE}/operations"), token, apply_input(&preview, request)?);
                gate.waiting().await?;
                assert!(!claims.is_expired(Timestamp::now().unix_secs()));
                let before = snapshot(&f.h).await?;
                tokio::time::timeout_at(deadline, async {
                    while !claims.is_expired(Timestamp::now().unix_secs()) {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .map_err(|_| {
                    agf_core::error::DomainError::Timeout("real JWT did not expire in twelve seconds".into())
                })?;
                gate.release().await?;
                let response = pending.finish().await?;
                assert!(response.status.is_success() || response.status == StatusCode::UNAUTHORIZED);
                assert_eq!(snapshot(&f.h).await?, before);
                assert_eq!(f.engine.counts().await, (3, 1));
                assert!(audits(&f.h, request, "mse-config-publication").await?.is_empty());
                let result = read(&f.h, &receipt(request)).await?;
                assert_eq!(result["completionState"], "pending_audit");
                assert_eq!(result["cloudWrite"]["status"], "accepted");
                verified(&post(&f.h, &format!("{}/recover", receipt(request)), json!({})).await?);
                assert_eq!(f.engine.counts().await, (3, 1));
                db::chain(&f.h).await
            })
        },
    )
    .await?;
    case.pool.close().await;
    Ok(())
}
