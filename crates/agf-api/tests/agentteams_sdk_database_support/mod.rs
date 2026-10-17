//! A real loopback API and SQL fixture; no provider calls, credentials in argv or shared spools.
#![allow(dead_code, reason = "Python and Node acceptance targets use different child launchers")]
use crate::{common::*, configuration_audit_support::SqlCase};
use agf_api::agentteams_audit::binding::Binding;
use agf_core::{asset::Asset, enums::AssetKind, ids::Id};
use agf_ingest::pipeline::SqlSink;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::{io::AsyncWriteExt, process::Command, sync::oneshot, task::JoinHandle};

pub(crate) const SOURCE_BINDINGS: &str = "/api/v1/alicloud/agentteams/audit-sources";
pub(crate) const EVENTS: &str = "/api/v1/alicloud/agentteams/audit-events";
const KEYS: &str = "/api/v1/settings/api-keys";

pub(crate) struct Key {
    pub(crate) id: String,
    pub(crate) plaintext: String,
}

pub(crate) struct Fixture {
    pub(crate) case: SqlCase,
    pub(crate) h: Harness,
    pub(crate) source: Id,
    pub(crate) binding: Binding,
    pub(crate) key: Key,
}

pub(crate) fn sql_router(mut h: Harness, pool: sqlx::PgPool) -> Harness {
    let store = Arc::new(Store::new(Database::from_pool(pool), None, Arc::new(MemoryObjectStore::new())));
    h.state.ingest_sink = Arc::new(SqlSink::new(store).with_event_outbox(true));
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let tenant = h.tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
        async move { request }
    }));
    h
}

impl Fixture {
    pub(crate) async fn open() -> Self {
        verify_database_owner().await;
        let case = SqlCase::open("sdk-platform-owned").await;
        let h = sql_router(case.h.clone(), case.pool.clone());
        let saved = h
            .request(
                "PUT",
                "/api/v1/alicloud/connections/alicloud-agentteams",
                Some(&h.admin),
                Some(json!({"expected_version":0,"enabled":true,"mock":true,
                "settings":{"instance_id":format!("sdk-mock-{}",Id::new()),"account_id":"sdk-owned-mock"}})),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK, "Mock configuration failed");
        let synced = h
            .post(
                "/api/v1/alicloud/agentteams/sync",
                json!({"request_id":Id::new(),
            "configuration_version":1,"confirm_live":false}),
            )
            .await;
        assert_eq!(synced.status, StatusCode::OK, "Mock inventory failed");
        extend_mock_fixture(&h).await;
        let source =
            h.post("/api/v1/ingest/sources", json!({"name":"sdk-owned-webhook","protocol":"http-webhook"})).await;
        assert_eq!(source.status, StatusCode::CREATED, "Source creation failed");
        let source = Id::parse(source.json()["id"].as_str().unwrap()).unwrap();
        let bound = h
            .request(
                "PUT",
                &format!("{SOURCE_BINDINGS}/{source}"),
                Some(&h.admin),
                Some(json!({"expected_version":0,"enabled":true})),
            )
            .await;
        assert_eq!(bound.status, StatusCode::OK, "Audit source binding failed");
        let binding = agf_api::agentteams_audit::binding::load(&h.state, h.tenant, source).await.unwrap().unwrap();
        assert!(binding.mocked && binding.members.len() == 2);
        let key = issue_key(&h).await;
        Self { case, h, source, binding, key }
    }

    pub(crate) async fn revoke(&self) {
        let response = self.h.request("DELETE", &format!("{KEYS}/{}", self.key.id), Some(&self.h.admin), None).await;
        assert_eq!(response.status, StatusCode::OK, "Owned collector Key revocation failed");
    }

    pub(crate) async fn disable_binding(&self) {
        let response = self
            .h
            .request(
                "PUT",
                &format!("{SOURCE_BINDINGS}/{}", self.source),
                Some(&self.h.admin),
                Some(json!({"expected_version":self.binding.version,"enabled":false})),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "Owned source binding disable failed");
    }

    pub(crate) async fn ledger(&self) -> Vec<Value> {
        let db = self.h.state.store.database().unwrap();
        let mut tx = db.db().begin_tenant(self.h.tenant).await.unwrap();
        let rows = sqlx::query_scalar("SELECT payload FROM agentteams_audit WHERE source_id=$1 ORDER BY id")
            .bind(self.source.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        rows
    }

    pub(crate) async fn evidence(&self) -> (Vec<String>, Vec<Value>, i64) {
        let db = self.h.state.store.database().unwrap();
        let mut tx = db.db().begin_tenant(self.h.tenant).await.unwrap();
        let raw = sqlx::query_scalar("SELECT payload_b64 FROM raw_logs WHERE source_id=$1")
            .bind(self.source.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        let events = sqlx::query_scalar("SELECT jsonb_build_object('raw',raw,'message',message,'extra',extra,'ai',ai) FROM events WHERE source_id=$1")
            .bind(self.source.as_uuid()).fetch_all(&mut *tx).await.unwrap();
        let outbox = sqlx::query_scalar("SELECT count(*) FROM event_delivery_outbox o JOIN events e ON o.tenant_id=e.tenant_id AND o.event_id=e.id WHERE e.source_id=$1")
            .bind(self.source.as_uuid()).fetch_one(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        (raw, events, outbox)
    }
}

async fn verify_database_owner() {
    let expected = std::env::var("AGF_SDK_DATABASE_OWNER").expect("Set the SDK SQL case's database ownership comment");
    let nonce = expected.strip_prefix("AIGuardFabric SDK platform SQL ").unwrap();
    assert!(nonce.len() == 32 && nonce.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    let actual: Option<String> = sqlx::query_scalar(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    pool.close().await;
    assert!(actual.as_deref() == Some(expected.as_str()), "Unowned database: no migrations or fixture writes allowed");
}

pub(crate) async fn issue_key(h: &Harness) -> Key {
    let response = h.post(KEYS, json!({"name":"sdk-owned-collector","scopes":["sources:write"]})).await;
    // Do not print this response: the successful issuance contains the one-time plaintext Key.
    assert_eq!(response.status, StatusCode::CREATED, "Collector Key issuance failed");
    Key {
        id: response.json()["api_key"]["id"].as_str().unwrap().to_owned(),
        plaintext: response.json()["plaintext"].as_str().unwrap().to_owned(),
    }
}

async fn extend_mock_fixture(h: &Harness) {
    // Explicit test-only Mock identities. This does not claim an actual provider Worker or Team.
    let mut snapshot = agf_api::cloud_inventory::load(&h.state, h.tenant).await.unwrap().unwrap();
    assert!(snapshot.mocked && snapshot.workers.len() == 1 && snapshot.teams.len() == 1);
    let mut team = snapshot.teams[0].clone();
    team["Name"] = json!("sdk-receiving-team");
    team["WorkerNames"] = json!(["sdk-receiver"]);
    snapshot.teams.push(team);
    snapshot.teams[0]["WorkerNames"] = json!(["worker-demo"]);
    let mut worker = snapshot.workers[0].clone();
    worker["Name"] = json!("sdk-receiver");
    worker["Groups"] = json!([{ "Type":"team","Name":"sdk-receiving-team","Role":"member" }]);
    snapshot.workers.push(worker);
    snapshot.workers[0]["Groups"] = json!([{ "Type":"team","Name":"my-team","Role":"member" }]);
    let asset = Asset::new(h.tenant, AssetKind::Agent, "sdk-receiver", "sdk-owned-mock-receiver");
    asset_upsert_durable(h, &asset).await;
    snapshot.assets.insert("sdk-receiver".into(), asset.id);
    for asset in snapshot.assets.values() {
        assert!(h.state.store.asset_get_durable(h.tenant, *asset).await.unwrap().is_some());
    }
    let cfg = agf_api::cloud_store::load(&h.state, h.tenant, agf_api::cloud_inventory::NAME).await.unwrap().unwrap();
    let mut private = agf_api::integration_store::Private::default();
    private.settings.insert("snapshot".into(), serde_json::to_value(&snapshot).unwrap());
    let sealed = agf_api::integration_store::Stored {
        private: agf_api::model_gateway::encrypt(&h.state, h.tenant, cfg.id, serde_json::to_string(&private).unwrap())
            .unwrap(),
        updated_at: snapshot.checked_at,
        ..cfg
    };
    h.state.configurations.put(h.tenant, "cloud-inventory", sealed.id, &sealed).await.unwrap();
}

async fn asset_upsert_durable(h: &Harness, asset: &Asset) {
    let db = h.state.store.database().unwrap();
    let mut tx = db.db().begin_tenant(h.tenant).await.unwrap();
    let saved = agf_storage::AssetRepo::upsert(&mut tx, asset).await.unwrap();
    assert_eq!(saved, asset.id);
    tx.commit().await.unwrap();
    assert!(h.state.store.asset_get_durable(h.tenant, saved).await.unwrap().is_some());
}

pub(crate) struct Server {
    pub(crate) origin: String,
    stop: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}
impl Server {
    pub(crate) async fn start(app: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (stop, shutdown) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(async {
                    let _ = shutdown.await;
                })
                .await
                .unwrap();
        });
        Self { origin, stop: Some(stop), handle: Some(handle) }
    }
    pub(crate) async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(mut handle) = self.handle.take() {
            if tokio::time::timeout(std::time::Duration::from_secs(5), &mut handle).await.is_err() {
                handle.abort();
                let _ = handle.await;
            }
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

pub(crate) struct Scratch {
    root: PathBuf,
    pub(crate) run_id: String,
}
impl Scratch {
    pub(crate) fn new() -> Self {
        let root = PathBuf::from(std::env::var("AGF_SDK_TEST_DIR").expect("Set the owned fixed task scratch root"));
        assert!(root.is_absolute());
        let name = root.file_name().unwrap().to_str().unwrap();
        assert!(["requirements-20260920", "codex-requirements-20260920"].contains(&name));
        for ancestor in root.ancestors() {
            assert_no_reparse(ancestor);
        }
        let owner = std::fs::read_to_string(root.join("task-owner.txt")).unwrap();
        assert!(
            ["AIGuardFabric requirements completion 20260920", "AIGuardFabric requirements completion local 20260920"]
                .contains(&owner.trim_start_matches('\u{feff}').trim())
        );
        Self { root, run_id: Id::new().as_uuid().simple().to_string() }
    }
    pub(crate) async fn python(&self, mut input: Value) -> Value {
        input["run_id"] = json!(self.run_id);
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/agentteams/python/tests/platform_roundtrip.py")
            .canonicalize()
            .unwrap();
        let executable =
            PathBuf::from(std::env::var_os("AGF_SDK_PYTHON").expect("Set an existing absolute Python executable"));
        assert!(
            executable.is_absolute() && executable.is_file(),
            "AGF_SDK_PYTHON must be an existing absolute executable file"
        );
        let mut child = Command::new(executable)
            .args(["-I", "-B"])
            .arg(script)
            .env("AGF_SDK_TEST_DIR", &self.root)
            .env_remove("AGF_TEST_DATABASE_URL")
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("The existing Python runtime must be available on PATH");
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&serde_json::to_vec(&input).unwrap()).await.unwrap();
        drop(stdin);
        let output = tokio::time::timeout(std::time::Duration::from_mins(1), child.wait_with_output())
            .await
            .expect("SDK platform probe exceeded its bound")
            .unwrap();
        assert!(output.stdout.len() < 16 * 1024 && output.stderr.len() < 16 * 1024, "Unexpected child output size");
        let report: Value = serde_json::from_slice(&output.stdout).expect("SDK probe must return safe JSON metrics");
        assert!(
            output.status.success() && report["ok"] == true,
            "SDK probe failed: safe error type {}",
            report["error_type"]
        );
        report
    }
    pub(crate) async fn clean(&self) {
        let report = self.python(json!({"action":"cleanup"})).await;
        assert_eq!(report["cleaned"], true);
        assert!(!self.root.join(format!("agentteams-sdk-case-{}", self.run_id)).exists());
    }

    pub(crate) async fn node(&self, mut input: Value) -> Value {
        input["run_id"] = json!(self.run_id);
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/agentteams/node/tests/platform_roundtrip.mjs");
        // Node 24 rejects Windows verbatim paths returned by canonicalize().
        assert!(script.is_absolute() && script.is_file(), "The owned Node probe must exist");
        let executable =
            PathBuf::from(std::env::var_os("AGF_SDK_NODE").expect("Set an existing absolute Node executable"));
        assert!(
            executable.is_absolute() && executable.is_file(),
            "AGF_SDK_NODE must be an existing absolute executable file"
        );
        let mut child = Command::new(executable)
            .arg(script)
            .env("AGF_SDK_TEST_DIR", &self.root)
            .env_remove("AGF_TEST_DATABASE_URL")
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("The existing native Node runtime must be executable");
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&serde_json::to_vec(&input).unwrap()).await.unwrap();
        drop(stdin);
        let output = tokio::time::timeout(std::time::Duration::from_mins(1), child.wait_with_output())
            .await
            .expect("Node SDK platform probe exceeded its bound")
            .unwrap();
        assert!(output.stdout.len() < 16 * 1024 && output.stderr.len() < 16 * 1024, "Unexpected child output size");
        let report: Value =
            serde_json::from_slice(&output.stdout).expect("Node SDK probe must return safe JSON metrics");
        assert!(
            output.status.success() && report["ok"] == true,
            "Node SDK probe failed: safe error type {}",
            report["error_type"]
        );
        report
    }

    pub(crate) async fn clean_node(&self) {
        let report = self.node(json!({"action":"cleanup"})).await;
        assert_eq!(report["cleaned"], true);
        assert!(!self.root.join(format!("agentteams-sdk-case-{}", self.run_id)).exists());
    }
}

fn assert_no_reparse(path: &Path) {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(!metadata.file_type().is_symlink(), "Task scratch must not traverse links");
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        assert_eq!(metadata.file_attributes() & 0x400, 0, "Task scratch must not traverse reparse points");
    }
}
