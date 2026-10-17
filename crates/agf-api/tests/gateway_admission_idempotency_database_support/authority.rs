//! Real same-config signed ten-second JWT, with its genuine existing user/session.
use super::*;
pub(crate) fn short_token(h: &Harness) -> DomainResult<(String, agf_auth::claims::AccessClaims)> {
    use agf_auth::claims::{IssueContext, TokenIssuer};
    let existing = h.state.auth.issuer().verify(&h.admin)?;
    let issuer = TokenIssuer::new(
        &h.state.config.security.jwt_secret,
        existing.iss.clone(),
        existing.aud.clone(),
        10,
        h.state.config.security.jwt_refresh_ttl_secs,
    )?;
    let context = IssueContext {
        subject: Id::parse(&existing.sub).map_err(|_| invalid())?,
        tenant: TenantId::parse(&existing.tenant_id).map_err(|_| invalid())?,
        kind: existing.subject_kind,
        roles: existing.roles,
        superadmin: existing.superadmin,
        must_change_password: existing.must_change_password,
        session_id: existing.session_id,
    };
    let token = issuer.issue_access(&context, Timestamp::now())?;
    let claims = h.state.auth.issuer().verify(&token)?;
    Ok((token, claims))
}
pub(crate) async fn wait_expired(claims: &agf_auth::claims::AccessClaims) -> DomainResult<()> {
    assert!(!claims.is_expired(Timestamp::now().unix_secs()));
    tokio::time::timeout(std::time::Duration::from_secs(12), async {
        while !claims.is_expired(Timestamp::now().unix_secs()) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| invalid())?;
    Ok(())
}
