//! Real issued Key and signed JWT mutation; no fake Principal or clock override.
use super::{Case, invalid, sql_error};
use crate::common::*;
use agf_core::{error::DomainResult, ids::Id};
pub(crate) async fn key(case: &Case) -> DomainResult<(String, Id)> {
    let response = case
        .sql
        .h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"route-policy-audit-owned-editor","scopes":["models:read","models:write"]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    let value = response.json();
    Ok((
        value["plaintext"].as_str().ok_or_else(invalid)?.into(),
        serde_json::from_value(value["api_key"]["id"].clone())?,
    ))
}
pub(crate) async fn revoke(case: &Case, key: Id) -> DomainResult<()> {
    case.verify().await?;
    let changed =
        sqlx::query("UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked")
            .bind(case.sql.h.tenant.as_uuid())
            .bind(key.as_uuid())
            .execute(&case.sql.pool)
            .await
            .map_err(sql_error)?;
    assert_eq!(changed.rows_affected(), 1);
    Ok(())
}
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
