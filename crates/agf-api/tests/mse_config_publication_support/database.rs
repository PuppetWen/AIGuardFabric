//! Exclusive database ownership precedes migrations and every DDL or fault-injection write.
use crate::{common::*, configuration_audit_support::SqlCase, transport};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
};
use secrecy::ExposeSecret;
pub(crate) const OWNER_ENV: &str = "AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER";
const PREFIX: &str = "AIGuardFabric MSE config publication SQL ";

pub(crate) fn sql(error: sqlx::Error) -> DomainError {
    DomainError::Internal(format!("owned publication SQL: {error}"))
}
fn identity() -> DomainResult<(String, String)> {
    let owner = std::env::var(OWNER_ENV)
        .map_err(|_| DomainError::PreconditionFailed("owned publication database marker required".into()))?;
    let run = owner
        .strip_prefix(PREFIX)
        .filter(|run| run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .ok_or_else(|| DomainError::PreconditionFailed("invalid publication database owner".into()))?;
    Ok((format!("agf_requirements_test_mse_config_publication_{}", &run[..12]), owner))
}
pub(crate) async fn check(pool: &sqlx::PgPool) -> DomainResult<()> {
    let actual: (String,Option<String>) = sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
        .fetch_one(pool).await.map_err(sql)?;
    let (database, owner) = identity()?;
    if actual != (database, Some(owner)) {
        return Err(DomainError::Forbidden("database does not belong to this publication test run".into()));
    }
    Ok(())
}
pub(crate) async fn open(label: &str) -> DomainResult<SqlCase> {
    assert!(!label.is_empty() && label.len() + 37 <= 64, "owned tenant slug must fit actual validation");
    let url = std::env::var("AGF_TEST_DATABASE_URL")
        .map_err(|_| DomainError::PreconditionFailed("owned publication database URL required".into()))?;
    let (database, _) = identity()?;
    if url::Url::parse(&url)?.path() != format!("/{database}") {
        return Err(DomainError::Forbidden("unexpected publication database URL".into()));
    }
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.map_err(sql)?;
    let result = check(&pool).await;
    pool.close().await;
    result?;
    Ok(SqlCase::open(label).await)
}
pub(crate) async fn chain(h: &Harness) -> DomainResult<()> {
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
pub(crate) async fn key(h: &Harness) -> DomainResult<(String, Id)> {
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned publication editor",
        "scopes":["alicloud:read","alicloud:write","policies:read"]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED); // Never print the plaintext issuance response.
    let value = response.json();
    let token = value["plaintext"].as_str().ok_or_else(|| DomainError::Internal("missing test Key".into()))?.into();
    Ok((token, transport::id(&value["api_key"], "id")?))
}
pub(crate) async fn revoke(pool: &sqlx::PgPool, tenant: TenantId, key: Id, scope_only: bool) -> DomainResult<()> {
    check(pool).await?;
    let statement = if scope_only {
        "UPDATE api_keys SET scopes=scopes-'alicloud:write',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL"
    } else {
        "UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL"
    };
    assert_eq!(
        sqlx::query(statement)
            .bind(tenant.as_uuid())
            .bind(key.as_uuid())
            .execute(pool)
            .await
            .map_err(sql)?
            .rows_affected(),
        1
    );
    Ok(())
}
pub(crate) fn fact_id(tenant: TenantId, request: Id) -> Id {
    deterministic_id("agf.mse.config-publication.fact", &format!("{tenant}:{request}"))
}
pub(crate) fn content_id(tenant: TenantId, request: Id, purpose: &str) -> Id {
    deterministic_id("agf.mse.config-publication.content", &format!("{tenant}:{request}:{purpose}"))
}
pub(crate) async fn row(h: &Harness, kind: &str, id: Id) -> DomainResult<Value> {
    h.state
        .configurations
        .get(h.tenant, kind, id)
        .await?
        .ok_or_else(|| DomainError::Internal("missing owned durable publication row".into()))
}
pub(crate) fn decrypt(h: &Harness, value: &Value) -> DomainResult<String> {
    let secret: SecretMaterial = serde_json::from_value(value.clone())?;
    Ok(agf_api::model_gateway::cipher(&h.state)?.decrypt(&secret)?.expose_secret().to_owned())
}

pub(crate) async fn mock(h: &Harness) -> DomainResult<Value> {
    let response = h.request("PUT",transport::CONFIG,Some(&h.admin),Some(json!({"expected_version":0,"enabled":true,"mock":true,
        "settings":{"engine_origin":"https://mse-agf-demo.invalid","region_id":"cn-hangzhou","instance_id":"inst-demo","namespace_id":"",
        "config_group":"AGF","config_data_id":"agf-policies.json","config_dialect":"nacos-http-v2-cas",
        "managed_upsert_confirmed":true,"account_id":"owned-mse-publication-account"}}))).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    transport::create_policy(h).await
}
pub(crate) async fn ready(h: &Harness, policy: &Value) -> DomainResult<Value> {
    let observation = transport::post(h, &format!("{}/observe", transport::BASE), transport::observe_input()).await?;
    let state = transport::read(h, transport::BASE).await?;
    transport::post(h,&format!("{}/previews",transport::BASE),json!({"request_id":Id::new(),"configuration_version":1,
        "observation_id":transport::id(&observation,"id")?,"expected_state_version":transport::number(&state,"stateVersion")?,
        "change":{"action":"publish","policies":[{"policy_id":transport::id(policy,"id")?,"version":1}]}})).await
}
pub(crate) async fn apply(h: &Harness, preview: &Value, request: Id) -> DomainResult<Value> {
    transport::post(h, &format!("{}/operations", transport::BASE), transport::apply_input(preview, request)?).await
}
pub(crate) async fn archive(h: &Harness, requests: &[Id], generation: u64) -> Resp {
    h.post(
        &format!("{}/operations/archive", transport::BASE),
        json!({"expected_generation":generation,"request_ids":requests}),
    )
    .await
}
pub(crate) async fn mock_content(h: &Harness) -> DomainResult<(u64, String)> {
    let rows = h.state.configurations.list::<Value>(h.tenant, "mse-config-publication-mock").await?;
    assert_eq!(rows.len(), 1);
    Ok((transport::number(&rows[0], "revision")?, decrypt(h, &rows[0]["content"])?))
}
