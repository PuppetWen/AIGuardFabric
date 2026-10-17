use super::{Case, error, fault};
use crate::{common::*, scheduler_managed_jobs_support::*};
use agf_auth::claims::{IssueContext, TokenIssuer};
use agf_core::{error::DomainResult, ids::Id};
use std::time::Duration;
async fn administrator(case: &Case) -> DomainResult<(Harness, Id)> {
    case.owner.check().await?;
    let mut user = User::new_local(case.h.tenant, "managed-admin", "managed-admin@owned.test");
    user.must_change_password = false;
    assert!(!user.is_superadmin);
    let hash = case.h.state.auth.hasher().hash_checked(ADMIN_PWD, "managed-admin")?;
    case.h.state.auth_backend.save_account(&user, Some(&hash), &["tenant-admin".into()]).await?;
    let mut h = case.h.clone();
    h.admin = h.state.auth.issue_for_user(&user, h.tenant, vec!["tenant-admin".into()])?.access_token;
    Ok((h, user.id))
}
pub(crate) async fn revoke_wait(case: &Case) -> DomainResult<()> {
    config(&case.h, 0, true).await?;
    let (h, user) = administrator(case).await?;
    let observed = observe(&h).await?;
    let prepared = preview(&h, &observed, create("report"), None).await?;
    let before = digest(&h).await?;
    let request = Id::new();
    let owner = case.owner.clone();
    fault::with_gate(&case.owner,h.tenant,request,fault::Mode::Wait,move |gate|Box::pin(async move {
        let mut pending=fault::Pending::start(&h,receipt(request),apply_input(&prepared));gate.waiting().await?;
        owner.check().await?;
        // These independent User grant rows are not held by the source/tenant/association locks.
        let changed=sqlx::query("UPDATE role_bindings SET deleted_at=now() WHERE tenant_id=$1 AND subject_id=$2 AND subject_kind='user' AND deleted_at IS NULL")
            .bind(h.tenant.as_uuid()).bind(user.as_uuid()).execute(&owner.pool).await.map_err(super::sql)?;
        assert_eq!(changed.rows_affected(),1);assert!(h.state.auth_backend.roles_of(h.tenant,user).await?.is_empty());
        gate.release().await?;assert_eq!(pending.finish().await?.status,StatusCode::FORBIDDEN);Ok(())
    })).await?;
    assert_eq!(digest(&case.h).await?, before);
    assert_eq!(case.h.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
    Ok(())
}
pub(crate) async fn expiry_wait(case: &Case) -> DomainResult<()> {
    config(&case.h, 0, true).await?;
    let existing = case.h.state.auth.issuer().verify(&case.h.admin)?;
    let observed = observe(&case.h).await?;
    let prepared = preview(&case.h, &observed, create("report"), None).await?;
    let issuer = TokenIssuer::new(
        &case.h.state.config.security.jwt_secret,
        existing.iss.clone(),
        existing.aud.clone(),
        10,
        case.h.state.config.security.jwt_refresh_ttl_secs,
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
    let mut h = case.h.clone();
    h.admin = issuer.issue_access(&context, Timestamp::now())?;
    let claims = h.state.auth.issuer().verify(&h.admin)?;
    assert_eq!(claims.exp - claims.iat, 10);
    let before = digest(&case.h).await?;
    let request = Id::new();
    fault::with_gate(&case.owner, h.tenant, request, fault::Mode::Wait, move |gate| {
        Box::pin(async move {
            let mut pending = fault::Pending::start(&h, receipt(request), apply_input(&prepared));
            gate.waiting().await?;
            assert!(!claims.is_expired(Timestamp::now().unix_secs()), "JWT must be valid at the real audit wait");
            tokio::time::timeout(Duration::from_secs(12), async {
                while !claims.is_expired(Timestamp::now().unix_secs()) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .map_err(|_| error())?;
            gate.release().await?;
            assert_eq!(pending.finish().await?.status, StatusCode::UNAUTHORIZED);
            Ok(())
        })
    })
    .await?;
    assert_eq!(digest(&case.h).await?, before);
    assert_eq!(case.h.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
    Ok(())
}
