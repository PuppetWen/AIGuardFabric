//! Durable normal-login state and one explicit source fixture; never seed an observation or adopted proof.
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};
use tokio::time::{Duration, timeout};
use tower::ServiceExt;

mod identity;
mod owned;
mod serve;
use crate::scheduler_native_observation_database_support::provider::Engine;

pub(super) fn fail(stage: &str) -> DomainError {
    DomainError::Internal(format!("Owned Scheduler UI host rejected stage {stage}; private details withheld"))
}
pub(crate) async fn run() -> DomainResult<()> {
    let login = identity::Login::read()?;
    let owner = owned::Owner::open(&login).await?;
    owner.check().await?;
    let database = Database::from_pool(owner.pool.clone());
    database.migrate().await.map_err(|_| fail("migration"))?;
    owner.empty().await?;
    let config = identity::Login::config(&owner.project, &owner.data)?;
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut state = agf_api::AppState::with_database(config, store).map_err(|_| fail("state"))?;
    owner.check().await?;
    let tenant = agf_api::tenant_directory::new(login.tenant_slug(), "Owned Scheduler native browser".into());
    let tenant = agf_api::tenant_directory::save(&state, tenant, true).await.map_err(|_| fail("tenant"))?;
    owner.check().await?;
    let created = state
        .ensure_bootstrap_admin(tenant.id, &login.username, "owned-ui@localhost.invalid", Some(&login.password), false)
        .await
        .map_err(|_| fail("account"))?;
    if !matches!(created, agf_api::BootstrapOutcome::Created { .. }) {
        return Err(fail("account_not_fresh"));
    }
    let engine = Engine::new(101, false).await.map_err(|_| fail("provider"))?;
    let address: SocketAddr =
        engine.server.origin.trim_start_matches("http://").parse().map_err(|_| fail("provider_origin"))?;
    state.scheduler_native_observation = Arc::new(
        agf_api::scheduler_native_observation::Registry::literal_loopback_for_test(tenant.id, address)
            .map_err(|_| fail("provider_capability"))?,
    );
    let router = agf_api::build_router(state.clone());
    prepare(&owner, &login, &state, &router, &engine, tenant.id).await?;
    settle(&state).await?;
    engine.count(0).await.map_err(|_| fail("unexpected_prepare_rpc"))?;
    serve::run(&owner, &login, &state, router, &engine, tenant.id).await
}
async fn prepare(
    owner: &owned::Owner,
    login: &identity::Login,
    state: &agf_api::AppState,
    router: &axum::Router,
    engine: &Engine,
    tenant: TenantId,
) -> DomainResult<()> {
    owner.check().await?;
    let signed = request(
        router,
        "POST",
        "/api/v1/auth/login",
        None,
        json!({
            "tenant_slug":login.tenant_slug(),"username":login.username,"password":login.password,
        }),
    )
    .await?;
    if signed["must_change_password"] != false || signed["user"]["tenant_id"] != json!(tenant) {
        return Err(fail("normal_login_tenant"));
    }
    let token = signed["tokens"]["access_token"].as_str().ok_or_else(|| fail("normal_login_token"))?;
    let me = request(router, "GET", "/api/v1/auth/me", Some(token), Value::Null).await?;
    if me["tenant_id"] != json!(tenant) {
        return Err(fail("normal_me_tenant"));
    }
    owner.check().await?;
    let saved = request(router, "PUT", "/api/v1/alicloud/connections/alicloud-schedulerx3", Some(token), json!({
        "expected_version":0,"enabled":true,"mock":false,
        "settings":{"region_id":"cn-hangzhou","cluster_id":"cluster-agf-demo","app_name":"app-agf-demo","endpoint":engine.server.origin},
        "secrets":{"access_key_id":"agf-owned-scheduler-key-no-cloud","access_key_secret":"agf-owned-scheduler-signing-secret-no-cloud"},
    })).await?;
    if saved["version"] != 1 {
        return Err(fail("prepared_source_version"));
    }
    let local = request(router, "GET", "/api/v1/alicloud/schedulerx3/native", Some(token), Value::Null).await?;
    if local["tenantId"] != json!(tenant)
        || local["sourceTarget"]["transportMode"] != "loopback_test"
        || local["sourceTarget"]["configurationVersion"] != 1
        || !local["latestObservation"].is_null()
        || local["bindings"]["version"] != 0
        || local["callbackBindingEnforced"] != false
    {
        return Err(fail("unseeded_normal_source"));
    }
    let account =
        state.auth_backend.find_user_with_secret(tenant, &login.username).await.map_err(|_| fail("durable_account"))?;
    if account.is_none() {
        return Err(fail("durable_account"));
    }
    Ok(())
}
async fn request(
    router: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> DomainResult<Value> {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let payload = if body.is_null() {
        Body::empty()
    } else {
        builder = builder.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&body).map_err(|_| fail("prepare_encode"))?)
    };
    let mut request = builder.body(payload).map_err(|_| fail("prepare_request"))?;
    request.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 31999))));
    let response = router.clone().oneshot(request).await.map_err(|_| fail("prepare_transport"))?;
    if response.status() != StatusCode::OK {
        return Err(fail("prepare_status"));
    }
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.map_err(|_| fail("prepare_body"))?;
    serde_json::from_slice(&bytes).map_err(|_| fail("prepare_json"))
}
pub(super) async fn settle(state: &agf_api::AppState) -> DomainResult<()> {
    let bridge = state.persistence.as_ref().ok_or_else(|| fail("durable_bridge"))?;
    timeout(Duration::from_secs(20), async {
        loop {
            let report = bridge.report();
            if report.failed > 0 || report.dropped > 0 || !report.hydrate.errors.is_empty() || report.hydrate.deferred {
                return Err(fail("durable_bridge_failure"));
            }
            if report.pending == 0 && report.queued == report.applied {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| fail("durable_bridge_timeout"))?
}
