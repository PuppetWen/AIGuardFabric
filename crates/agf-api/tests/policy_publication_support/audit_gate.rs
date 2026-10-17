//! Exact policy audit INSERT faults and deterministic revocation windows in an owned database.
use crate::{common::*, policy_sql};
use agf_core::ids::Id;
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe, pin::Pin, time::Duration};
use tokio::task::JoinHandle;

const WAIT: Duration = Duration::from_secs(20);

pub(crate) struct Target {
    pub(crate) id: Option<Id>,
    pub(crate) name: String,
    pub(crate) action: &'static str,
}
impl Target {
    fn predicate(&self) -> String {
        assert!(!self.name.is_empty() && self.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        assert!(["create", "update", "delete"].contains(&self.action));
        let identity = self
            .id
            .map_or_else(|| format!("NEW.target->>'name'='{}'", self.name), |id| format!("NEW.target->>'id'='{id}'"));
        format!(
            "NEW.target->>'kind'='policy' AND ({identity}) AND NEW.action='{}' AND NEW.outcome='success'",
            self.action
        )
    }
}

pub(crate) struct Pending(Option<JoinHandle<Resp>>);
impl Pending {
    pub(crate) fn start(h: Harness, method: &str, path: String, token: String, body: Option<Value>) -> Self {
        let method = method.to_string();
        Self(Some(tokio::spawn(async move { h.request(&method, &path, Some(&token), body).await })))
    }
    pub(crate) async fn finish(mut self) -> Resp {
        let response = tokio::time::timeout(WAIT, self.0.as_mut().unwrap()).await.unwrap().unwrap();
        self.0.take();
        response
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Reject,
    Wait,
}

pub(crate) struct AuditGate {
    pool: sqlx::PgPool,
    name: String,
    held: Option<sqlx::Transaction<'static, sqlx::Postgres>>,
    function_created: bool,
    trigger_created: bool,
}
impl AuditGate {
    async fn new(pool: &sqlx::PgPool) -> Self {
        policy_sql::check(pool).await;
        Self {
            pool: pool.clone(),
            name: format!("agf_test_policy_gate_{}", Id::new().as_uuid().simple()),
            held: None,
            function_created: false,
            trigger_created: false,
        }
    }
    async fn install(&mut self, tenant: TenantId, target: Target, mode: Mode) {
        policy_sql::check(&self.pool).await;
        let operation = match mode {
            Mode::Reject => "RAISE EXCEPTION 'owned policy audit rejection';".to_string(),
            Mode::Wait => format!("PERFORM pg_advisory_xact_lock(hashtextextended('{}',0));", self.name),
        };
        let sql = format!(
            "CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $gate$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND ({}) THEN {operation} END IF; RETURN NEW; END; $gate$",
            self.name,
            target.predicate()
        );
        sqlx::query(&sql).execute(&self.pool).await.unwrap();
        self.function_created = true;
        sqlx::query(&format!(
            "CREATE TRIGGER {} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION {}()",
            self.name, self.name
        ))
        .execute(&self.pool)
        .await
        .unwrap();
        self.trigger_created = true;
        if matches!(mode, Mode::Wait) {
            let mut tx = self.pool.begin().await.unwrap();
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(&self.name)
                .execute(&mut *tx)
                .await
                .unwrap();
            self.held = Some(tx);
        }
    }
    pub(crate) async fn waiting(&self) {
        tokio::time::timeout(WAIT,async {
            loop {
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1 AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295) AND objid::bigint=(hashtextextended($1,0)&4294967295))")
                    .bind(&self.name).fetch_one(&self.pool).await.unwrap();
                if blocked {break;}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("owned policy success audit did not reach its exact INSERT gate");
    }
    pub(crate) async fn release(&mut self) {
        if let Some(tx) = self.held.take() {
            tx.rollback().await.unwrap();
        }
    }
    async fn clean(&mut self) {
        self.release().await;
        policy_sql::check(&self.pool).await;
        assert!(
            self.name.starts_with("agf_test_policy_gate_")
                && self.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
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
        .expect("owned policy audit gate cleanup timed out");
    }
}

pub(crate) async fn with_audit<F>(pool: &sqlx::PgPool, tenant: TenantId, target: Target, mode: Mode, action: F)
where
    F: for<'a> FnOnce(&'a mut AuditGate) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>,
{
    let mut gate = AuditGate::new(pool).await;
    let result = AssertUnwindSafe(async {
        gate.install(tenant, target, mode).await;
        action(&mut gate).await;
    })
    .catch_unwind()
    .await;
    // A callback's Pending aborts on panic before its audit lock and owned DDL are removed.
    gate.clean().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

pub(crate) async fn key(h: &Harness) -> (String, Id) {
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned-policy-editor",
        "scopes":["policies:read","policies:write","policies:delete"]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    (
        response.json()["plaintext"].as_str().unwrap().into(),
        serde_json::from_value(response.json()["api_key"]["id"].clone()).unwrap(),
    )
}

pub(crate) async fn revoke(pool: &sqlx::PgPool, tenant: TenantId, key: Id) {
    policy_sql::check(pool).await;
    // Fault injection avoids normal audited Key revocation queuing behind this test's audit tail.
    let result=sqlx::query("UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL")
        .bind(tenant.as_uuid()).bind(key.as_uuid()).execute(pool).await.unwrap();
    assert_eq!(result.rows_affected(), 1);
}
