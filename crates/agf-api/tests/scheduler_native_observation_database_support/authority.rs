use super::{
    gate::{Mode, Target, with_gate},
    provider::{self, Engine},
    *,
};
use tokio::time::{Duration, Instant, timeout, timeout_at};

async fn change_key(owner: &Owner, h: &Harness, id: Id, scope_only: bool) -> DomainResult<()> {
    owner.check().await?;
    // This owned fault bypasses the normal revocation audit, which would wait on the same audit tail.
    let query = if scope_only {
        "UPDATE api_keys SET scopes=scopes-'alicloud:read',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL"
    } else {
        "UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL"
    };
    assert_eq!(
        sqlx::query(query)
            .bind(h.tenant.as_uuid())
            .bind(id.as_uuid())
            .execute(&owner.pool)
            .await
            .map_err(sql)?
            .rows_affected(),
        1
    );
    Ok(())
}
pub(crate) async fn current_key(scope_only: bool) -> DomainResult<()> {
    for claim in [true, false] {
        let case = SqlCase::open(if claim { "sch-key-claim" } else { "sch-key-final" }).await?;
        let engine = Engine::new(101, false).await?;
        let h = provider::attach(case.h.clone(), &engine)?;
        provider::configure(&h, &engine, 0, true).await?;
        let (token, key_id) = key(&h).await?;
        let id = Id::new();
        let prior = snapshot(&h).await?;
        let owner = case.owner.clone();
        let target = Target {
            kind: if claim { "scheduler-native-read-claim" } else { "scheduler-native-observation" },
            id,
            action: if claim { "create" } else { "read" },
        };
        with_gate(&case.owner, h.tenant, target, Mode::Wait, move |gate| {
            Box::pin(async move {
                let mut pending = provider::start(&h, id, token);
                gate.waiting().await?;
                let before = snapshot(&h).await?;
                change_key(&owner, &h, key_id, scope_only).await?;
                gate.release().await?;
                let result = pending.finish().await?;
                assert_eq!(result.status, StatusCode::FORBIDDEN);
                assert_eq!(snapshot(&h).await?, before);
                assert!(row(&h, BODY, record_id(&h, BODY, id)).await?.is_none());
                if claim {
                    assert_eq!(snapshot(&h).await?, prior);
                    assert_eq!(h.get(&receipt(id)).await.status, StatusCode::NOT_FOUND);
                } else {
                    assert_eq!(read(&h, &receipt(id)).await?["status"], "reading");
                }
                assert!(audits(&h, id, "scheduler-native-observation").await?.is_empty());
                engine.count(if claim { 0 } else { 3 }).await?;
                chain(&h).await
            })
        })
        .await?;
        case.owner.pool.close().await;
    }
    Ok(())
}
pub(crate) async fn original_jwt() -> DomainResult<()> {
    use agf_auth::claims::{IssueContext, TokenIssuer};
    let case = SqlCase::open("sch-jwt-expiry").await?;
    let engine = Engine::new(101, false).await?;
    let h = provider::attach(case.h.clone(), &engine)?;
    provider::configure(&h, &engine, 0, true).await?;
    let id = Id::new();
    with_gate(
        &case.owner,
        h.tenant,
        Target { kind: "scheduler-native-observation", id, action: "read" },
        Mode::Wait,
        move |gate| {
            Box::pin(async move {
                let original = h.state.auth.issuer().verify(&h.admin)?;
                let issuer = TokenIssuer::new(
                    &h.state.config.security.jwt_secret,
                    original.iss.clone(),
                    original.aud.clone(),
                    10,
                    h.state.config.security.jwt_refresh_ttl_secs,
                )?;
                let ctx = IssueContext {
                    subject: Id::parse(&original.sub)?,
                    tenant: TenantId::parse(&original.tenant_id)?,
                    kind: original.subject_kind,
                    roles: original.roles,
                    superadmin: original.superadmin,
                    must_change_password: original.must_change_password,
                    session_id: original.session_id,
                };
                let deadline = Instant::now() + Duration::from_secs(12);
                let token = issuer.issue_access(&ctx, Timestamp::now())?;
                let claims = h.state.auth.issuer().verify(&token)?;
                assert_eq!(claims.exp - claims.iat, 10);
                assert!(!claims.is_expired(Timestamp::now().unix_secs()));
                let mut pending = provider::start(&h, id, token);
                gate.waiting().await?;
                assert!(
                    !claims.is_expired(Timestamp::now().unix_secs()),
                    "request must reach the exact gate while its signed JWT is valid"
                );
                let before = snapshot(&h).await?;
                timeout_at(deadline, async {
                    while !claims.is_expired(Timestamp::now().unix_secs()) {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .map_err(|_| wire::fixture_error("signed JWT did not expire within twelve seconds"))?;
                gate.release().await?;
                assert_eq!(pending.finish().await?.status, StatusCode::UNAUTHORIZED);
                assert_eq!(snapshot(&h).await?, before);
                assert!(row(&h, BODY, record_id(&h, BODY, id)).await?.is_none());
                assert!(audits(&h, id, "scheduler-native-observation").await?.is_empty());
                engine.count(3).await?;
                chain(&h).await
            })
        },
    )
    .await?;
    case.owner.pool.close().await;
    Ok(())
}
pub(crate) async fn original_budget() -> DomainResult<()> {
    let case = SqlCase::open("sch-original-budget").await?;
    let engine = Engine::new(101, false).await?;
    let h = provider::attach(case.h.clone(), &engine)?;
    provider::configure(&h, &engine, 0, true).await?;
    let id = Id::new();
    let owner = case.owner.clone();
    with_gate(
        &case.owner,
        h.tenant,
        Target { kind: "scheduler-native-observation", id, action: "read" },
        Mode::Wait,
        move |gate| {
            Box::pin(async move {
                let started = Instant::now();
                let mut pending = provider::start(&h, id, h.admin.clone());
                gate.waiting().await?;
                let before = snapshot(&h).await?;
                // A real clock and the original 110-second request budget. No paused Tokio time or fabricated deadline.
                let result = pending.finish_within(Duration::from_secs(115)).await?;
                assert_eq!(result.status, StatusCode::GATEWAY_TIMEOUT);
                assert!(started.elapsed() >= Duration::from_secs(109) && started.elapsed() < Duration::from_secs(117));
                gate.release().await?;
                // Lock the actual fact row to await rollback of the owned publication task, not merely its parent response.
                owner.check().await?;
                timeout(Duration::from_secs(10), async {
                    let mut tx = owner.pool.begin().await.map_err(sql)?;
                    sqlx::query(
                        "SELECT id FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3 FOR SHARE",
                    )
                    .bind(h.tenant.as_uuid())
                    .bind(FACT)
                    .bind(record_id(&h, FACT, id).as_uuid())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(sql)?;
                    tx.rollback().await.map_err(sql)
                })
                .await
                .map_err(|_| wire::fixture_error("expired owned publication did not roll back"))??;
                assert_eq!(snapshot(&h).await?, before);
                assert!(row(&h, BODY, record_id(&h, BODY, id)).await?.is_none());
                assert!(audits(&h, id, "scheduler-native-observation").await?.is_empty());
                let receipt = read(&h, &receipt(id)).await?;
                assert_eq!(receipt["status"], "reading");
                engine.count(3).await?;
                chain(&h).await
            })
        },
    )
    .await?;
    case.owner.pool.close().await;
    Ok(())
}
pub(crate) async fn source_and_tenant() -> DomainResult<()> {
    for disable_tenant in [false, true] {
        let case = SqlCase::open("sch-provider-fresh").await?;
        let engine = Engine::new(101, false).await?;
        let h = provider::attach(case.h.clone(), &engine)?;
        provider::configure(&h, &engine, 0, true).await?;
        let id = Id::new();
        let (gate, _release) = engine.hold("GetApp", 1)?;
        let mut pending = provider::start(&h, id, h.admin.clone());
        gate.wait_entered().await?;
        if disable_tenant {
            case.owner.check().await?;
            let mut entry = agf_api::tenant_directory::get(&h.state, h.tenant).await?;
            entry.enabled = false;
            let saved = agf_api::tenant_directory::save(&h.state, entry, false).await?;
            assert!(!saved.enabled);
        } else {
            provider::configure(&h, &engine, 1, true).await?;
        }
        gate.release();
        let result = pending.finish().await?;
        assert_eq!(result.status, if disable_tenant { StatusCode::FORBIDDEN } else { StatusCode::CONFLICT });
        assert!(rows(&h, BODY).await?.is_empty());
        assert!(
            audits(&h, id, "scheduler-native-observation").await?.iter().all(|a| a.outcome != AuditOutcome::Success)
        );
        engine.count(1).await?;
        chain(&h).await?;
        case.owner.pool.close().await;
    }
    Ok(())
}
