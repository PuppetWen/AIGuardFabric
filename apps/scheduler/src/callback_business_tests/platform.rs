//! Real TCP platform server, durable authentication, and literal provider adoption.
use super::{database::Owned, fixtures};
use agf_api::AppState;
use agf_core::ids::{Id, TenantId};
use axum::{
    Router,
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

pub(super) type Counts = Arc<Mutex<BTreeMap<String, usize>>>;
pub(super) struct Server {
    pub(super) origin: String,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    pub(super) async fn stop(&mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
    pub(super) async fn start(router: Router) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Ok(Self { origin, task })
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn count(State(counts): State<Counts>, request: Request, next: Next) -> Response {
    let key = format!("{} {}", request.method(), request.uri().path());
    if let Ok(mut counts) = counts.lock() {
        *counts.entry(key).or_default() += 1;
    }
    next.run(request).await
}
pub(super) struct Platform {
    pub(super) state: AppState,
    pub(super) server: Server,
    pub(super) tenant: TenantId,
    pub(super) key: String,
    admin: String,
    pub(super) counts: Counts,
    http: reqwest::Client,
}
impl Platform {
    pub(super) async fn close(mut self) {
        self.server.stop().await;
    }
    pub(super) async fn new(owned: &Owned, address: std::net::SocketAddr) -> anyhow::Result<Self> {
        owned.check().await?;
        fixtures::files(&owned.scratch)?;
        let tenant = agf_api::tenant_directory::new(format!("cb-six-{}", Id::new()), "Owned consumer business".into());
        owned.scratch.bind(tenant.id)?;
        let state = Self::state(owned, tenant.id, address)?;
        agf_api::tenant_directory::save(&state, tenant.clone(), true).await?;
        state
            .ensure_bootstrap_admin(
                tenant.id,
                "callback-admin",
                "callback@owned.local",
                Some(fixtures::PASSWORD),
                false,
            )
            .await?;
        let counts = Counts::default();
        let app =
            agf_api::build_router(state.clone()).layer(axum::middleware::from_fn_with_state(counts.clone(), count));
        let server = Server::start(app).await?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .timeout(Duration::from_secs(100))
            .build()?;
        let reply = http
            .post(format!("{}/api/v1/auth/login", server.origin))
            .json(&json!({"tenant_slug":tenant.id,"username":"callback-admin","password":fixtures::PASSWORD}))
            .send()
            .await?;
        anyhow::ensure!(reply.status().is_success(), "real fixture login failed");
        let login: Value = reply.json().await?;
        let admin =
            login["tokens"]["access_token"].as_str().ok_or_else(|| anyhow::anyhow!("login token absent"))?.to_owned();
        let mut platform = Self { state, server, tenant: tenant.id, key: String::new(), admin, counts, http };
        let issued=platform.admin("POST","/api/v1/settings/api-keys",Some(json!({"name":"owned callback service","scopes":["alicloud:read","assets:read","sources:read","sources:write","redteam:read","redteam:execute","policies:write","reports:write"]})),201).await?;
        platform.key = issued["plaintext"].as_str().ok_or_else(|| anyhow::anyhow!("service key absent"))?.to_owned();
        platform.seed_business().await?;
        platform.adopt(address).await?;
        Ok(platform)
    }
    fn state(owned: &Owned, tenant: TenantId, address: std::net::SocketAddr) -> anyhow::Result<AppState> {
        let mut state = AppState::with_database(fixtures::config(&owned.scratch)?, owned.store.clone())?;
        state.scheduler_native_observation =
            Arc::new(agf_api::scheduler_native_observation::Registry::literal_loopback_for_test(tenant, address)?);
        state.redteam_cases = Arc::new(agf_scan::redteam::CaseLibrary::from_cases(vec![fixtures::case()]));
        state.rules =
            Arc::new(crate::RulePackLoader::strict().load_dir(&crate::RulesDir::new(owned.scratch.path("rules")))?);
        anyhow::ensure!(state.ingest_sink.backend() == "sql", "ingestion must use real PostgreSQL");
        Ok(state)
    }
    pub(super) async fn restart(&self, owned: &Owned, address: std::net::SocketAddr) -> anyhow::Result<Self> {
        owned.check().await?;
        let state = Self::state(owned, self.tenant, address)?;
        let counts = Counts::default();
        let app =
            agf_api::build_router(state.clone()).layer(axum::middleware::from_fn_with_state(counts.clone(), count));
        Ok(Self {
            state,
            server: Server::start(app).await?,
            tenant: self.tenant,
            key: self.key.clone(),
            admin: self.admin.clone(),
            counts,
            http: self.http.clone(),
        })
    }
    pub(super) async fn admin(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        expected: u16,
    ) -> anyhow::Result<Value> {
        let mut request = self
            .http
            .request(method.parse()?, format!("{}{path}", self.server.origin))
            .bearer_auth(&self.admin)
            .header("X-AGF-Tenant", self.tenant.to_string());
        if let Some(body) = body {
            request = request.json(&body);
        }
        let reply = request.send().await?;
        anyhow::ensure!(
            reply.status().as_u16() == expected,
            "owned platform {method} {path} unexpected HTTP status {}",
            reply.status().as_u16()
        );
        Ok(reply.json().await?)
    }
    pub(super) async fn snapshot(&self) -> anyhow::Result<Value> {
        let mut records = BTreeMap::new();
        for kind in [
            "scheduler-native-callback-execution",
            "scheduler-native-callback-batch",
            "scheduler-native-callback-progress",
            "scheduler-native-callback-pending",
            "scheduler-native-callback-request",
            "signed-policy-registry",
            "log-source",
            "parser-template",
        ] {
            records.insert(kind, self.state.configurations.list::<Value>(self.tenant, kind).await?);
        }
        Ok(json!({"records":records,"audit":self.state.store.audit_chain_durable(self.tenant,0,i64::MAX).await?}))
    }
    pub(super) fn calls(&self, method: &str, path: &str) -> anyhow::Result<usize> {
        let counts = self.counts.lock().map_err(|_| anyhow::anyhow!("HTTP counter poisoned"))?;
        Ok(counts.get(&format!("{method} {path}")).copied().unwrap_or(0))
    }
    async fn seed_business(&self) -> anyhow::Result<()> {
        self.admin("POST","/api/v1/assets/discovery",Some(json!({"source":"agent-report","assets":[{"kind":"agent","name":"owned-callback-asset","fingerprint":format!("callback-{}",self.tenant),"endpoint":"owned-local-agent"}]})),200).await?;
        self.admin("POST", "/api/v1/policies", Some(fixtures::policy()), 201).await?;
        Ok(())
    }
    async fn adopt(&self, address: std::net::SocketAddr) -> anyhow::Result<()> {
        self.admin("PUT","/api/v1/alicloud/connections/alicloud-schedulerx3",Some(json!({"expected_version":0,"enabled":true,"mock":false,
            "settings":fixtures::settings(&format!("http://{address}"),self.tenant),"secrets":{"access_key_id":super::provider::ACCESS_KEY,"access_key_secret":super::provider::SECRET}})),200).await?;
        let id = Id::new();
        self.admin(
            "POST",
            "/api/v1/alicloud/schedulerx3/native/observe",
            Some(
                json!({"request_id":id,"configuration_version":1,"confirm_live":false,"initialize_mock_fixture":false}),
            ),
            200,
        )
        .await?;
        self.admin("PUT","/api/v1/alicloud/schedulerx3/native/bindings",Some(json!({"action":"replace","request_id":Id::new(),"expected_version":0,"configuration_version":1,
            "observation_id":id,"bindings":fixtures::JOBS.map(|(kind,job)|json!({"kind":kind,"job_id":job})),"confirm_local_only":true})),200).await?;
        Ok(())
    }
}
