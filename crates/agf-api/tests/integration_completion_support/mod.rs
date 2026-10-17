//! Owned completion fixtures, loopback gates and tenant-scoped SQL fault helpers.
#![allow(dead_code)]
use crate::common::*;
use agf_api::integration_receipts::Run;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget},
    ids::{Id, deterministic_id},
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{sync::Semaphore, task::JoinHandle};

pub(crate) const RUNS: &str = "integration-operation";
pub(crate) const PENDING: &str = "integration-completion";
pub(crate) const CLOUD: &str = "/api/v1/alicloud/connections/alicloud-cms";
pub(crate) const VENDOR: &str = "/api/v1/integrations/adapters/webhook";

pub(crate) fn name(cloud: bool) -> &'static str {
    if cloud { "alicloud-cms" } else { "webhook" }
}
pub(crate) fn base(cloud: bool) -> &'static str {
    if cloud { CLOUD } else { VENDOR }
}
pub(crate) fn configuration_path(cloud: bool) -> String {
    if cloud { CLOUD.into() } else { format!("{VENDOR}/configuration") }
}
pub(crate) fn body(cloud: bool) -> Value {
    let request_id = Id::new();
    if cloud {
        json!({"request_id":request_id,"configuration_version":1,"confirm_live":true,
            "action":"PutCustomEvent","parameters":{"EventInfo":[{"EventName":"owned-completion","Content":"synthetic event"}]}})
    } else {
        json!({"request_id":request_id,"configuration_version":1,"confirm_live":true,"operation":"send",
            "payload":{"kind":"notification","event_type":"notify.alert","title":"Owned completion",
            "summary":"Synthetic local delivery","severity":"medium","idempotency_key":request_id.to_string(),
            "occurred_at":"2026-09-30T10:00:00Z","body":{},"labels":{}}})
    }
}
pub(crate) fn claim(h: &Harness, cloud: bool, body: &Value) -> Run {
    let encoded = if cloud {
        serde_json::to_vec(&serde_json::from_value::<agf_api::cloud_runtime::Request>(body.clone()).unwrap()).unwrap()
    } else {
        serde_json::to_vec(&serde_json::from_value::<agf_api::integration_runtime::Request>(body.clone()).unwrap())
            .unwrap()
    };
    let request_id: Id = serde_json::from_value(body["request_id"].clone()).unwrap();
    Run {
        id: deterministic_id("agf.integration.run", &format!("{}:{}:{request_id}", h.tenant, name(cloud))),
        request_id,
        adapter: name(cloud).into(),
        operation: if cloud { "PutCustomEvent" } else { "send" }.into(),
        configuration_version: 1,
        request_hash: format!("{:x}", Sha256::digest(encoded)),
        actor: "owned-original-actor".into(),
        started_at: Timestamp::now(),
        finished_at: None,
        status: "started".into(),
        mocked: true,
        result: None,
    }
}
pub(crate) fn completion_audit(h: &Harness, run: &Run) -> AuditLog {
    let mut audit = AppState::audit_entry(
        h.tenant,
        AuditAction::Execute,
        if run.status == "succeeded" { AuditOutcome::Success } else { AuditOutcome::Failure },
        AuditActor::system("owned-original-actor"),
        AuditTarget::new(RUNS, Some(run.id.to_string()), Some(run.adapter.clone())),
        "Owned known completion",
    );
    audit.id = deterministic_id("agf.integration.completion.audit", &format!("{}:{}", h.tenant, run.id));
    audit.request_id = Some(run.request_id.to_string());
    audit.after = Some(json!({"run_id":run.id,"request_id":run.request_id,"adapter":run.adapter,
        "operation":run.operation,"configuration_version":run.configuration_version,"mocked":run.mocked,"status":run.status}));
    audit
}
pub(crate) async fn seed_pending(h: &Harness, cloud: bool, status: &str) -> (Run, Value) {
    let body = body(cloud);
    let run = claim(h, cloud, &body);
    let mut terminal = run.clone();
    terminal.status = status.into();
    terminal.finished_at = Some(Timestamp::now());
    terminal.result = Some(
        agf_api::model_gateway::encrypt(
            &h.state,
            h.tenant,
            run.id,
            json!({"accepted":status=="succeeded","detail":"private-receipt-marker"}).to_string(),
        )
        .unwrap(),
    );
    let audit = completion_audit(h, &terminal);
    h.state.configurations.put(h.tenant, RUNS, run.id, &run).await.unwrap();
    h.state.configurations.put(h.tenant, PENDING, run.id, &json!({"run":terminal,"audit":audit})).await.unwrap();
    (run, body)
}
pub(crate) async fn rows(h: &Harness, kind: &str) -> Vec<Value> {
    let mut rows: Vec<Value> = h.state.configurations.list(h.tenant, kind).await.unwrap();
    rows.sort_by_key(Value::to_string);
    rows
}
pub(crate) async fn operation_audits(h: &Harness, id: Id) -> Vec<AuditLog> {
    let id = id.to_string();
    h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await
        .unwrap()
        .into_iter()
        .filter(|audit| audit.target.kind == RUNS && audit.target.id.as_deref() == Some(id.as_str()))
        .collect()
}
pub(crate) fn assert_safe_audit(audit: &AuditLog, run: &Run) {
    assert_eq!(audit.action, AuditAction::Execute);
    assert_eq!(audit.request_id, Some(run.request_id.to_string()));
    let after = audit.after.as_ref().unwrap().as_object().unwrap();
    assert_eq!(after.len(), 7);
    for key in ["run_id", "request_id", "adapter", "operation", "configuration_version", "mocked", "status"] {
        assert!(after.contains_key(key), "missing safe field {key}");
    }
    assert_eq!(after["run_id"], json!(run.id));
    assert_eq!(after["request_id"], json!(run.request_id));
    assert_eq!(after["adapter"], run.adapter);
    assert_eq!(after["operation"], run.operation);
    assert_eq!(after["configuration_version"], run.configuration_version);
    assert_eq!(after["mocked"], run.mocked);
    let text = serde_json::to_string(audit).unwrap();
    for private in ["private-receipt-marker", "ciphertext_b64", "owned-signing-secret", "owned-webhook-secret"] {
        assert!(!text.contains(private), "audit leaked private receipt/configuration");
    }
}
pub(crate) fn live(h: &mut Harness) {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let tenant = h.tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        if !request.headers().contains_key("x-agf-tenant") {
            request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
        }
        async move { request }
    }));
}
pub(crate) async fn configure(h: &Harness, cloud: bool, mocked: bool, endpoint: &str) {
    let (settings, secrets) = if cloud {
        (
            json!({"endpoint":endpoint,"region_id":"cn-hangzhou"}),
            json!({"access_key_id":"owned-access-key","access_key_secret":"owned-signing-secret"}),
        )
    } else {
        (json!({}), json!({"webhook_url":format!("{endpoint}/hook")}))
    };
    let response = h
        .request(
            "PUT",
            &configuration_path(cloud),
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":mocked,"settings":settings,"secrets":secrets})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
}
pub(crate) async fn read_key(h: &Harness, cloud: bool) -> String {
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw(if cloud { "alicloud:read" } else { "integrations:read" })],
        ..ApiKeyIssueRequest::named(h.tenant, "completion-reader", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&issued.record).await.unwrap();
    issued.plaintext
}

#[derive(Clone)]
struct Rpc {
    calls: Arc<AtomicUsize>,
    gate: Arc<Semaphore>,
    blocked: bool,
}
async fn respond(axum::extract::State(rpc): axum::extract::State<Rpc>) -> axum::Json<Value> {
    rpc.calls.fetch_add(1, Ordering::SeqCst);
    if rpc.blocked {
        rpc.gate.acquire().await.unwrap().forget();
    }
    axum::Json(json!({"id":"owned-receipt","Code":"200","RequestId":"owned-cloud-receipt",
        "AlarmHistoryList":{"AlarmHistory":[]}}))
}
pub(crate) struct Loopback {
    pub(crate) endpoint: String,
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) gate: Arc<Semaphore>,
    job: JoinHandle<()>,
}
impl Drop for Loopback {
    fn drop(&mut self) {
        self.job.abort();
    }
}
impl Loopback {
    pub(crate) async fn new(blocked: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(0));
        let router = Router::new()
            .route("/", axum::routing::get(respond).post(respond))
            .route("/hook", axum::routing::post(respond))
            .with_state(Rpc { calls: calls.clone(), gate: gate.clone(), blocked });
        let job = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self { endpoint, calls, gate, job }
    }
    pub(crate) fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    pub(crate) async fn observed(&self, count: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while self.count() < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

pub(crate) async fn fault(pool: &sqlx::PgPool, tenant: TenantId, table: &str, predicate: &str) -> String {
    assert!(matches!(table, "audit_logs" | "console_configurations"));
    let name = format!("agf_test_completion_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE {table} ADD CONSTRAINT {name} CHECK (NOT (tenant_id='{tenant}'::uuid AND ({predicate}))) NOT VALID"
    ))
    .execute(pool)
    .await
    .unwrap();
    name
}
pub(crate) async fn unfault(pool: &sqlx::PgPool, table: &str, name: &str) {
    assert!(matches!(table, "audit_logs" | "console_configurations"));
    assert!(name.starts_with("agf_test_completion_") && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'));
    sqlx::query(&format!("ALTER TABLE {table} DROP CONSTRAINT {name}")).execute(pool).await.unwrap();
}
pub(crate) struct SqlGate {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
    tenant: TenantId,
    key: String,
}
impl SqlGate {
    pub(crate) async fn acquire(pool: &sqlx::PgPool, tenant: TenantId, key: String) -> Self {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SELECT set_config('agf.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))").bind(&key).execute(&mut *tx).await.unwrap();
        Self { tx, tenant, key }
    }
    pub(crate) async fn waiting(&self, pool: &sqlx::PgPool) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted
                    AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1
                    AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295)
                    AND objid::bigint=(hashtextextended($1,0)&4294967295))",
                )
                .bind(&self.key)
                .fetch_one(pool)
                .await
                .unwrap();
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    pub(crate) async fn rewrite(&mut self, kind: &str, id: Id, payload: Value) {
        let updated = sqlx::query("UPDATE console_configurations SET payload=$1 WHERE tenant_id=$2 AND kind=$3 AND id=$4 AND deleted_at IS NULL")
            .bind(payload).bind(self.tenant.as_uuid()).bind(kind).bind(id.as_uuid()).execute(&mut *self.tx).await.unwrap();
        assert_eq!(updated.rows_affected(), 1);
    }
    pub(crate) async fn release(self) {
        self.tx.commit().await.unwrap();
    }
}
pub(crate) async fn wait_complete(h: &Harness, id: Id) -> Run {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let run: Run = h.state.configurations.get(h.tenant, RUNS, id).await.unwrap().unwrap();
            if run.finished_at.is_some()
                && h.state.configurations.get::<Value>(h.tenant, PENDING, id).await.unwrap().is_none()
            {
                return run;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}
