//! Same-origin static/API dispatch preserves the original full router and all current authentication guards.
use super::*;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use tokio::{net::TcpListener, sync::watch};
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone)]
struct WebHost {
    api: Router,
    files: Router,
}
async fn dispatch(State(host): State<WebHost>, request: Request<Body>) -> Response {
    let path = request.uri().path();
    let api = path == "/api"
        || path.starts_with("/api/")
        || ["/healthz", "/readyz", "/metrics", "/graphql", "/ws"].contains(&path);
    if !api && !matches!(*request.method(), Method::GET | Method::HEAD) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    // Router is infallible. Both branches preserve the request and extensions, including ConnectInfo.
    let result = if api { host.api.oneshot(request).await } else { host.files.oneshot(request).await };
    match result {
        Ok(response) => response,
        Err(never) => match never {},
    }
}
pub(super) async fn run(
    owner: &owned::Owner,
    login: &identity::Login,
    state: &agf_api::AppState,
    router: Router,
    engine: &Engine,
    tenant: TenantId,
) -> DomainResult<()> {
    owner.check().await?;
    let api = TcpListener::bind("127.0.0.1:28080").await.map_err(|_| fail("api_bind"))?;
    let web = TcpListener::bind("127.0.0.1:28081").await.map_err(|_| fail("web_bind"))?;
    let files = Router::new()
        .fallback_service(ServeDir::new(&owner.dist).not_found_service(ServeFile::new(owner.dist.join("index.html"))));
    let web_router = Router::new().fallback(dispatch).with_state(WebHost { api: router.clone(), files });
    let (stop, signal) = watch::channel(false);
    let api_signal = signal.clone();
    let web_signal = signal;
    let mut api_task = tokio::spawn(async move {
        axum::serve(api, router.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(stopped(api_signal))
            .await
    });
    let mut web_task = tokio::spawn(async move {
        axum::serve(web, web_router.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(stopped(web_signal))
            .await
    });
    emit(json!({"kind":"owned-scheduler-native-ui-ready","runId":login.run_id,"owner":login.owner,
        "database":owner.database,"tenantId":tenant,"tenantSlug":login.tenant_slug(),
        "apiOrigin":"http://127.0.0.1:28080","webOrigin":"http://127.0.0.1:28081","providerOrigin":engine.server.origin,
        "totalJobs":101,"sourceVersion":1,"prepareLoginRequests":1,"prepareSourceWrites":1,
        "observationsSeeded":0,"bindingsSeeded":0,"providerRequests":0,"maximumLifetimeSeconds":1200,
        "boundary":"Actual router/AppState; no main workers, cloud registration or callback execution"}))?;
    let mut api_result = None;
    let mut web_result = None;
    let mut stop_rejected = false;
    let mut stop_reason = "ctrl_c";
    let stopped_normally = tokio::select! {
        result = tokio::signal::ctrl_c() => result.is_ok(),
        result = requested_stop(owner) => { stop_reason="owned_marker"; stop_rejected=result.is_err(); result.is_ok() },
        () = tokio::time::sleep(Duration::from_mins(20)) => { stop_reason="lifetime"; false },
        result = &mut api_task => { api_result=Some(result); stop_reason="api_exit"; false },
        result = &mut web_task => { web_result=Some(result); stop_reason="web_exit"; false },
    };
    let _ = stop.send(true);
    let closing = timeout(Duration::from_secs(20), async {
        // Preserve the result of an early exit, and never poll a consumed JoinHandle twice.
        let api_result = match api_result {
            Some(result) => result,
            None => (&mut api_task).await,
        };
        api_result.map_err(|_| fail("api_stop"))?.map_err(|_| fail("api_stop"))?;
        let web_result = match web_result {
            Some(result) => result,
            None => (&mut web_task).await,
        };
        web_result.map_err(|_| fail("web_stop"))?.map_err(|_| fail("web_stop"))?;
        Ok::<_, DomainError>(())
    })
    .await;
    if !matches!(closing, Ok(Ok(()))) {
        api_task.abort();
        web_task.abort();
        return Err(fail("listener_shutdown"));
    }
    if stop_rejected {
        return Err(fail("stop_request_guard"));
    }
    owner.check().await?;
    settle(state).await?;
    let verified = state.store.audit_verify_durable(tenant).await.map_err(|_| fail("audit_chain"))?;
    if !verified.passed {
        return Err(fail("audit_chain_invalid"));
    }
    let reads = engine.received().map_err(|_| fail("provider_count"))?;
    emit(json!({"kind":"owned-scheduler-native-ui-stopped","runId":login.run_id,"owner":login.owner,
        "providerRequests":reads,"auditViolations":0,"graceful":stopped_normally,"stopReason":stop_reason,"browserAcceptance":"not asserted by host"}))?;
    owner.pool.close().await;
    if !stopped_normally {
        return Err(fail("host_lifetime_or_listener"));
    }
    Ok(())
}
async fn requested_stop(owner: &owned::Owner) -> DomainResult<()> {
    loop {
        if owner.stop_requested()? {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
async fn stopped(mut signal: watch::Receiver<bool>) {
    while !*signal.borrow_and_update() {
        if signal.changed().await.is_err() {
            break;
        }
    }
}
fn emit(value: Value) -> DomainResult<()> {
    use std::io::Write;
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value).map_err(|_| fail("control_output"))?;
    output.write_all(b"\n").and_then(|()| output.flush()).map_err(|_| fail("control_output"))
}
