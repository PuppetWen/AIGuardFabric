//! Normal durable login and real HTTP routes. Only an already-committed ACK body can be discarded.
use super::{fail, owned::Owned};
use agf_api::AppState;
use agf_core::{
    config::AppConfig,
    error::DomainResult,
    ids::{Id, TenantId},
};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::oneshot, task::JoinHandle};

#[derive(Default)]
pub(super) struct Tap {
    pub(super) discard_ack: AtomicBool,
    pub(super) committed_responses: AtomicUsize,
}
async fn discard(State(tap): State<Arc<Tap>>, request: Request, next: Next) -> Response {
    let event = request.method() == axum::http::Method::POST
        && request.uri().path().ends_with("/events")
        && request.uri().path().starts_with("/api/v1/alicloud/agentteams/audit-sources/");
    let response = next.run(request).await;
    if event && response.status().is_success() {
        tap.committed_responses.fetch_add(1, Ordering::SeqCst);
        if tap.discard_ack.load(Ordering::SeqCst) {
            let (mut parts, _) = response.into_parts();
            parts.headers.remove(axum::http::header::CONTENT_LENGTH);
            let error = std::io::Error::other("owned postcommit ACK loss");
            return Response::from_parts(
                parts,
                Body::from_stream(futures::stream::iter([Err::<bytes::Bytes, _>(error)])),
            );
        }
    }
    response
}
pub(super) struct Server {
    pub(super) origin: String,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl Server {
    pub(super) async fn start(router: Router) -> DomainResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|_| fail("listener"))?;
        let origin = format!("http://{}", listener.local_addr().map_err(|_| fail("listener address"))?);
        let (stop, wait) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(async {
                    let _ = wait.await;
                })
                .await
                .expect("owned HTTP listener");
        });
        Ok(Self { origin, stop: Some(stop), task: Some(task) })
    }
    pub(super) async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(mut task) = self.task.take() {
            if tokio::time::timeout(Duration::from_secs(5), &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
pub(super) struct Key {
    pub(super) id: Id,
    pub(super) token: String,
}
pub(super) struct Platform {
    pub(super) state: AppState,
    pub(super) tenant: TenantId,
    pub(super) server: Server,
    pub(super) tap: Arc<Tap>,
    admin: String,
    http: reqwest::Client,
    config: AppConfig,
}
impl Platform {
    pub(super) async fn open(owned: &Owned) -> DomainResult<Self> {
        owned.check().await?;
        if std::env::var_os("AGF_RISK_HISTORY_PATH").is_some()
            || std::env::var("AGF_SEED_FIXTURES").is_ok_and(|v| v != "0")
        {
            return Err(fail("inherited runtime override"));
        }
        let config = config(owned)?;
        let state = AppState::with_database(config.clone(), owned.store.clone())?;
        assert_eq!(state.ingest_sink.backend(), "sql");
        let tenant =
            agf_api::tenant_directory::new(format!("zero-code-{}", Id::new()), "Owned zero-code acceptance".into());
        agf_api::tenant_directory::save(&state, tenant.clone(), true).await?;
        state
            .ensure_bootstrap_admin(
                tenant.id,
                "zero-code-admin",
                "zero-code@owned.local",
                Some("Zc7#Sql9!Read2$Once6"),
                false,
            )
            .await?;
        let tap = Arc::new(Tap::default());
        let server = Server::start(
            agf_api::build_router(state.clone()).layer(axum::middleware::from_fn_with_state(tap.clone(), discard)),
        )
        .await?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| fail("HTTP client"))?;
        let login = http
            .post(format!("{}/api/v1/auth/login", server.origin))
            .json(&json!({"tenant_slug":tenant.slug,"username":"zero-code-admin","password":"Zc7#Sql9!Read2$Once6"}))
            .send()
            .await
            .map_err(|_| fail("normal login"))?;
        assert_eq!(login.status().as_u16(), 200, "normal durable account login");
        let value: Value = login.json().await.map_err(|_| fail("login shape"))?;
        let admin = value["tokens"]["access_token"].as_str().ok_or_else(|| fail("login token absent"))?.to_owned();
        Ok(Self { state, tenant: tenant.id, server, tap, admin, http, config })
    }
    pub(super) async fn restart(&self, owned: &Owned) -> DomainResult<Self> {
        owned.check().await?;
        let state = AppState::with_database(self.config.clone(), owned.store.clone())?;
        let tap = Arc::new(Tap::default());
        let server = Server::start(
            agf_api::build_router(state.clone()).layer(axum::middleware::from_fn_with_state(tap.clone(), discard)),
        )
        .await?;
        Ok(Self {
            state,
            tenant: self.tenant,
            server,
            tap,
            admin: self.admin.clone(),
            http: self.http.clone(),
            config: self.config.clone(),
        })
    }
    pub(super) async fn request(
        &self,
        token: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> DomainResult<(u16, Value)> {
        let mut request = self
            .http
            .request(method.parse().map_err(|_| fail("HTTP method"))?, format!("{}{path}", self.server.origin))
            .bearer_auth(token)
            .header("X-AGF-Tenant", self.tenant.to_string());
        if let Some(body) = body {
            request = request.json(&body);
        }
        let reply = request.send().await.map_err(|_| fail("owned HTTP request"))?;
        let status = reply.status().as_u16();
        Ok((status, reply.json().await.map_err(|_| fail("owned HTTP JSON"))?))
    }
    pub(super) async fn admin(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        status: u16,
    ) -> DomainResult<Value> {
        let (actual, body) = self.request(&self.admin, method, path, body).await?;
        assert_eq!(actual, status, "owned admin {method} {path}");
        Ok(body)
    }
    pub(super) async fn key(&self, scopes: &[&str]) -> DomainResult<Key> {
        let reply = self
            .admin(
                "POST",
                "/api/v1/settings/api-keys",
                Some(json!({"name":"owned zero-code key","scopes":scopes})),
                201,
            )
            .await?;
        Ok(Key {
            id: serde_json::from_value(reply["api_key"]["id"].clone())?,
            token: reply["plaintext"].as_str().ok_or_else(|| fail("issued Key absent"))?.to_owned(),
        })
    }
    pub(super) async fn revoke(&self, key: &Key) -> DomainResult<()> {
        self.admin("DELETE", &format!("/api/v1/settings/api-keys/{}", key.id), None, 200).await?;
        Ok(())
    }
    pub(super) async fn chain(&self) -> DomainResult<()> {
        assert!(self.state.store.audit_verify_durable(self.tenant).await?.passed);
        Ok(())
    }
    pub(super) async fn mcp(&self, key: &Key, id: Id, frame: Value) -> DomainResult<(u16, Value)> {
        let method = frame["method"].as_str().ok_or_else(|| fail("MCP method"))?;
        let name = frame["params"]["name"].as_str().ok_or_else(|| fail("MCP tool name"))?;
        let reply = self
            .http
            .post(format!("{}/api/v1/mcp/proxy/{id}", self.server.origin))
            .bearer_auth(&key.token)
            .header("X-AGF-Tenant", self.tenant.to_string())
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method)
            .header("mcp-name", name)
            .header("accept", "application/json, text/event-stream")
            .json(&frame)
            .send()
            .await
            .map_err(|_| fail("MCP proxy request"))?;
        let status = reply.status().as_u16();
        Ok((status, reply.json().await.map_err(|_| fail("MCP proxy JSON"))?))
    }
}
fn config(owned: &Owned) -> DomainResult<AppConfig> {
    let random = agf_core::secret::generate_token;
    let mut values: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "0"),
        // Persist the SQL delivery outbox. This fixture never starts a NATS publisher.
        ("AGF_NATS_ENABLED", "1"),
        ("AGF_LOG_LEVEL", "warn"),
        ("AGF_FORCE_PASSWORD_CHANGE", "0"),
        ("AGF_PASSWORD_MIN_LENGTH", "12"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    values.insert("AGF_PROJECT_ROOT".into(), owned.project.to_string_lossy().into_owned());
    values.insert("AGF_DATA_DIR".into(), owned.root.to_string_lossy().into_owned());
    values.insert("AGF_JWT_SECRET".into(), random());
    values.insert("AGF_FINGERPRINT_SALT".into(), random());
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    values.insert("AGF_MASTER_KEY_BASE64".into(), STANDARD.encode(Sha256::digest(random().as_bytes())));
    agf_core::config::from_env_map(&values).map_err(|_| fail("owned configuration"))
}
