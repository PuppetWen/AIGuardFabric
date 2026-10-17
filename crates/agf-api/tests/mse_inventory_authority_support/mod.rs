//! Owned SQL audit gates stop precisely after the old authority check, without blocking provider receipts.
use crate::common::*;
use agf_core::ids::Id;
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe, pin::Pin, time::Duration};
use tokio::task::JoinHandle;

const WAIT: Duration = Duration::from_secs(20);

pub(crate) enum Target {
    Claim(Id),
    Publication(Id),
    Cancel(Id),
    Archive { cloud_id: Id, request: Id },
}

impl Target {
    fn predicate(&self) -> String {
        let (kind, id, action, extra) = match self {
            Self::Claim(id) => ("mse-inventory-run", *id, "create", String::new()),
            Self::Publication(id) => ("mse-inventory-run", *id, "execute", String::new()),
            Self::Cancel(id) => ("mse-inventory-run", *id, "update", String::new()),
            Self::Archive { cloud_id, request } => (
                "mse-inventory",
                *cloud_id,
                "update",
                format!(" AND NEW.after->'request_ids'='[\"{request}\"]'::jsonb"),
            ),
        };
        assert!(!id.is_nil());
        format!(
            "NEW.target->>'kind'='{kind}' AND NEW.target->>'id'='{id}' AND NEW.action='{action}' AND NEW.outcome='success'{extra}"
        )
    }
}

pub(crate) async fn key(h: &Harness) -> (String, Id) {
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned-mse-audit-authority",
        "scopes":["alicloud:read","alicloud:write","assets:write"]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    let body = response.json();
    (body["plaintext"].as_str().unwrap().into(), serde_json::from_value(body["api_key"]["id"].clone()).unwrap())
}

pub(crate) async fn revoke(pool: &sqlx::PgPool, tenant: TenantId, id: Id) {
    // Fault injection touches this test's exact durable key only. HTTP revocation would
    // itself need the audit-chain lock currently held by the blocked publication.
    let result = sqlx::query("UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL")
        .bind(tenant.as_uuid()).bind(id.as_uuid()).execute(pool).await.unwrap();
    assert_eq!(result.rows_affected(), 1);
}

pub(crate) async fn assets(h: &Harness) -> Value {
    serde_json::to_value(h.state.store.asset_list_all_durable(h.tenant).await.unwrap()).unwrap()
}

pub(crate) async fn successes(h: &Harness, target: &str, id: Id, action: &str) -> usize {
    let id = id.to_string();
    h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await
        .unwrap()
        .into_iter()
        .filter(|audit| {
            audit.target.kind == target
                && audit.target.id.as_deref() == Some(id.as_str())
                && audit.action.as_str() == action
                && audit.outcome == agf_core::audit::AuditOutcome::Success
        })
        .count()
}

/// Aborts unfinished client work even when assertions unwind, including a timeout.
pub(crate) struct Pending(Option<JoinHandle<Resp>>);
impl Pending {
    pub(crate) fn start(h: Harness, path: String, token: String, body: Value) -> Self {
        Self(Some(tokio::spawn(async move { h.request("POST", &path, Some(&token), Some(body)).await })))
    }
    pub(crate) async fn finish(mut self) -> Resp {
        let result = tokio::time::timeout(WAIT, self.0.as_mut().unwrap()).await.unwrap().unwrap();
        drop(self.0.take());
        result
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

/// Any failed assertion also releases the owned loopback response before runtime shutdown.
pub(crate) struct ProviderRelease {
    blocked: Arc<std::sync::atomic::AtomicU64>,
    permits: Arc<tokio::sync::Semaphore>,
}
impl ProviderRelease {
    pub(crate) fn new(f: &crate::mse_inventory_support::Fixture) -> Self {
        Self { blocked: f.blocked.clone(), permits: f.gate.clone() }
    }
}
impl Drop for ProviderRelease {
    fn drop(&mut self) {
        self.blocked.store(0, std::sync::atomic::Ordering::SeqCst);
        self.permits.add_permits(1);
    }
}

pub(crate) struct AuditGate {
    pool: sqlx::PgPool,
    database: String,
    owner: String,
    name: String,
    lock_key: String,
    held: Option<sqlx::Transaction<'static, sqlx::Postgres>>,
    function_created: bool,
    trigger_created: bool,
}

impl AuditGate {
    async fn new(pool: &sqlx::PgPool) -> Self {
        let owner = std::env::var("AGF_MSE_DATABASE_OWNER").unwrap();
        let run = owner.strip_prefix("AIGuardFabric MSE inventory SQL ").unwrap();
        assert!(run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        let database = format!("agf_requirements_test_mse_{}", &run[..12]);
        let name = format!("agf_test_mse_authority_{}", Id::new().as_uuid().simple());
        let gate = Self {
            pool: pool.clone(),
            database,
            owner,
            lock_key: name.clone(),
            name,
            held: None,
            function_created: false,
            trigger_created: false,
        };
        gate.check_owner().await;
        gate
    }
    async fn install(&mut self, tenant: TenantId, target: Target) {
        // Installation is inside the same finally protection as the assertions.
        let function = format!(
            "CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $gate$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND ({}) THEN PERFORM pg_advisory_xact_lock(hashtextextended('{}',0)); END IF; RETURN NEW; END; $gate$",
            self.name,
            target.predicate(),
            self.lock_key
        );
        sqlx::query(&function).execute(&self.pool).await.unwrap();
        self.function_created = true;
        sqlx::query(&format!(
            "CREATE TRIGGER {} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION {}()",
            self.name, self.name
        ))
        .execute(&self.pool)
        .await
        .unwrap();
        self.trigger_created = true;
        let mut tx = self.pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&self.lock_key)
            .execute(&mut *tx)
            .await
            .unwrap();
        self.held = Some(tx);
    }
    async fn check_owner(&self) {
        let identity: (String, Option<String>) = sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
            .fetch_one(&self.pool).await.unwrap();
        assert_eq!(identity, (self.database.clone(), Some(self.owner.clone())));
        assert!(
            self.name.starts_with("agf_test_mse_authority_")
                && self.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
    }
    pub(crate) async fn waiting(&self) {
        tokio::time::timeout(WAIT, async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1 AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295) AND objid::bigint=(hashtextextended($1,0)&4294967295))")
                    .bind(&self.lock_key).fetch_one(&self.pool).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("owned audit INSERT did not reach its exact gate");
    }
    pub(crate) async fn release(&mut self) {
        if let Some(tx) = self.held.take() {
            tx.rollback().await.unwrap();
        }
    }
    async fn clean(&mut self) {
        self.release().await;
        self.check_owner().await;
        tokio::time::timeout(WAIT, async {
            if self.trigger_created {
                sqlx::query(&format!("DROP TRIGGER {} ON audit_logs", self.name)).execute(&self.pool).await.unwrap();
                self.trigger_created = false;
            }
            if self.function_created {
                sqlx::query(&format!("DROP FUNCTION {}()", self.name)).execute(&self.pool).await.unwrap();
                self.function_created = false;
            }
        })
        .await
        .expect("owned audit gate cleanup timed out");
    }
}

pub(crate) async fn with_gate<F>(pool: &sqlx::PgPool, tenant: TenantId, target: Target, action: F)
where
    F: for<'a> FnOnce(&'a mut AuditGate) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>,
{
    let mut gate = AuditGate::new(pool).await;
    let result = AssertUnwindSafe(async {
        gate.install(tenant, target).await;
        action(&mut gate).await;
    })
    .catch_unwind()
    .await;
    // The callback's Pending guards drop on panic before locks and owned DDL are removed.
    gate.clean().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
