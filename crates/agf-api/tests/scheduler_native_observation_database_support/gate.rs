//! Only an exact owned successful audit INSERT can wait or fail; cleanup runs on errors and panic.
use crate::{
    common::*,
    scheduler_native_observation_database_support::{Owner, sql},
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe, pin::Pin, time::Duration};
const WAIT: Duration = Duration::from_secs(20);

pub(crate) struct Target {
    pub(crate) kind: &'static str,
    pub(crate) id: Id,
    pub(crate) action: &'static str,
}
impl Target {
    fn predicate(&self) -> String {
        assert!(
            [
                "scheduler-native-read-claim",
                "scheduler-native-observation",
                "scheduler-native-archive",
                "scheduler-native-bindings",
                "scheduler-native-mock"
            ]
            .contains(&self.kind)
        );
        assert!(["configure", "create", "read"].contains(&self.action) && !self.id.is_nil());
        format!(
            "NEW.target->>'kind'='{}' AND NEW.target->>'id'='{}' AND NEW.action='{}' AND NEW.outcome='success'",
            self.kind, self.id, self.action
        )
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Wait,
    Reject,
}
pub(crate) struct Gate {
    owner: Owner,
    name: String,
    table: &'static str,
    held: Option<sqlx::Transaction<'static, sqlx::Postgres>>,
    function_created: bool,
    trigger_created: bool,
}
impl Gate {
    async fn install(&mut self, tenant: TenantId, target: Target, mode: Mode) -> DomainResult<()> {
        self.owner.check().await?;
        let operation = match mode {
            Mode::Wait => format!("PERFORM pg_advisory_xact_lock(hashtextextended('{}',0));", self.name),
            Mode::Reject => "RAISE EXCEPTION 'owned publication audit rejection';".into(),
        };
        sqlx::query(&format!("CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $gate$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND ({}) THEN {operation} END IF; RETURN NEW; END; $gate$",self.name,target.predicate()))
            .execute(&self.owner.pool).await.map_err(sql)?;
        self.function_created = true;
        sqlx::query(&format!(
            "CREATE TRIGGER {} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION {}()",
            self.name, self.name
        ))
        .execute(&self.owner.pool)
        .await
        .map_err(sql)?;
        self.trigger_created = true;
        if matches!(mode, Mode::Wait) {
            let mut tx = self.owner.pool.begin().await.map_err(sql)?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(&self.name)
                .execute(&mut *tx)
                .await
                .map_err(sql)?;
            self.held = Some(tx);
        }
        Ok(())
    }
    pub(crate) async fn waiting(&self) -> DomainResult<()> {
        tokio::time::timeout(WAIT,async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1 AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295) AND objid::bigint=(hashtextextended($1,0)&4294967295))")
                    .bind(&self.name).fetch_one(&self.owner.pool).await.map_err(sql)?;
                if blocked { return Ok::<_,DomainError>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.map_err(|_| DomainError::Internal("exact publication audit INSERT never reached the owned gate".into()))?
    }
    pub(crate) async fn release(&mut self) -> DomainResult<()> {
        if let Some(tx) = self.held.take() {
            tx.rollback().await.map_err(sql)?;
        }
        Ok(())
    }
    async fn clean(&mut self) -> DomainResult<()> {
        self.release().await?;
        self.owner.check().await?;
        assert!(
            self.name.starts_with("agf_test_sched_gate_")
                && self.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        tokio::time::timeout(WAIT, async {
            if self.trigger_created {
                sqlx::query(&format!("DROP TRIGGER {} ON {}", self.name, self.table))
                    .execute(&self.owner.pool)
                    .await
                    .map_err(sql)?;
                self.trigger_created = false;
            }
            if self.function_created {
                sqlx::query(&format!("DROP FUNCTION {}()", self.name)).execute(&self.owner.pool).await.map_err(sql)?;
                self.function_created = false;
            }
            Ok::<_, DomainError>(())
        })
        .await
        .map_err(|_| DomainError::Internal("owned publication DDL cleanup timed out".into()))?
    }
}
pub(crate) async fn with_gate<T, F>(
    owner: &Owner,
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
        name: format!("agf_test_sched_gate_{}", Id::new().as_uuid().simple()),
        table: "audit_logs",
        held: None,
        function_created: false,
        trigger_created: false,
    };
    let result = AssertUnwindSafe(async {
        gate.install(tenant, target, mode).await?;
        action(&mut gate).await
    })
    .catch_unwind()
    .await;
    // Pending request guards in the callback abort before releasing its tail wait and dropping this DDL.
    let cleaned = gate.clean().await;
    match result {
        Ok(value) => {
            cleaned?;
            value
        }
        Err(panic) => {
            if let Err(error) = cleaned {
                tracing::error!(%error,"owned publication gate cleanup failed");
            }
            std::panic::resume_unwind(panic)
        }
    }
}
