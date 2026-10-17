//! Exact callback audit fault, with owner checks before each DDL and cleanup on failures and panic.
use super::*;
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe, pin::Pin};
use tokio::time::{Duration, timeout};

#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Wait,
    Reject,
}
pub(crate) struct Target {
    pub(crate) kind: &'static str,
    pub(crate) id: Id,
    pub(crate) action: &'static str,
}
impl Target {
    fn predicate(&self) -> String {
        assert!(["scheduler-native-callback-claim", "scheduler-native-callback-start", EXECUTION].contains(&self.kind));
        assert!(["create", "execute"].contains(&self.action) && !self.id.is_nil());
        format!(
            "NEW.target->>'kind'='{}' AND NEW.target->>'id'='{}' AND NEW.action='{}'",
            self.kind, self.id, self.action
        )
    }
}
pub(crate) struct Gate {
    owner: native::Owner,
    name: String,
    held: Option<sqlx::Transaction<'static, sqlx::Postgres>>,
    function: bool,
    trigger: bool,
}
impl Gate {
    async fn install(&mut self, tenant: TenantId, target: Target, mode: Mode) -> DomainResult<()> {
        self.owner.check().await?;
        let operation = match mode {
            Mode::Wait => format!("PERFORM pg_advisory_xact_lock(hashtextextended('{}',0));", self.name),
            Mode::Reject => "RAISE EXCEPTION 'owned callback audit fault';".into(),
        };
        sqlx::query(&format!("CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $gate$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND ({}) THEN {operation} END IF; RETURN NEW; END; $gate$", self.name, target.predicate()))
            .execute(&self.owner.pool).await.map_err(native::sql)?;
        self.function = true;
        self.owner.check().await?;
        sqlx::query(&format!(
            "CREATE TRIGGER {} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION {}()",
            self.name, self.name
        ))
        .execute(&self.owner.pool)
        .await
        .map_err(native::sql)?;
        self.trigger = true;
        if matches!(mode, Mode::Wait) {
            let mut tx = self.owner.pool.begin().await.map_err(native::sql)?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(&self.name)
                .execute(&mut *tx)
                .await
                .map_err(native::sql)?;
            self.held = Some(tx);
        }
        Ok(())
    }
    pub(crate) async fn waiting(&self) -> DomainResult<()> {
        wait_advisory(&self.owner, &self.name).await
    }
    pub(crate) async fn release(&mut self) -> DomainResult<()> {
        if let Some(tx) = self.held.take() {
            tx.rollback().await.map_err(native::sql)?;
        }
        Ok(())
    }
    async fn clean(&mut self) -> DomainResult<()> {
        self.release().await?;
        assert!(
            self.name.starts_with("agf_test_callback_")
                && self.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        timeout(Duration::from_secs(20), async {
            if self.trigger {
                self.owner.check().await?;
                sqlx::query(&format!("DROP TRIGGER {} ON audit_logs", self.name))
                    .execute(&self.owner.pool)
                    .await
                    .map_err(native::sql)?;
                self.trigger = false;
            }
            if self.function {
                self.owner.check().await?;
                sqlx::query(&format!("DROP FUNCTION {}()", self.name))
                    .execute(&self.owner.pool)
                    .await
                    .map_err(native::sql)?;
                self.function = false;
            }
            Ok::<_, DomainError>(())
        })
        .await
        .map_err(|_| native::wire::fixture_error("callback fault cleanup timed out"))?
    }
}
pub(crate) async fn wait_advisory(owner: &native::Owner, name: &str) -> DomainResult<()> {
    owner.check().await?;
    timeout(Duration::from_secs(20), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1 AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295) AND objid::bigint=(hashtextextended($1,0)&4294967295))")
                .bind(name).fetch_one(&owner.pool).await.map_err(native::sql)?;
            if blocked { return Ok::<_, DomainError>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_| native::wire::fixture_error("exact owned callback lock never blocked"))?
}
pub(crate) async fn with_gate<T, F>(
    owner: &native::Owner,
    tenant: TenantId,
    target: Target,
    mode: Mode,
    action: F,
) -> DomainResult<T>
where
    F: for<'a> FnOnce(&'a mut Gate) -> Pin<Box<dyn Future<Output = DomainResult<T>> + Send + 'a>>,
{
    owner.check().await?;
    let mut gate = Gate {
        owner: owner.clone(),
        name: format!("agf_test_callback_{}", Id::new().as_uuid().simple()),
        held: None,
        function: false,
        trigger: false,
    };
    let result = AssertUnwindSafe(async {
        gate.install(tenant, target, mode).await?;
        action(&mut gate).await
    })
    .catch_unwind()
    .await;
    let cleaned = gate.clean().await;
    match result {
        Ok(value) => {
            cleaned?;
            value
        }
        Err(panic) => {
            if cleaned.is_err() {
                tracing::error!("Owned callback audit gate cleanup failed; raw details withheld");
            }
            std::panic::resume_unwind(panic)
        }
    }
}
