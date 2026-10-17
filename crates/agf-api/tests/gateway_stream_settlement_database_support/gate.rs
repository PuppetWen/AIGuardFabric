//! Exact terminal UUID INSERT wait, with owned pg_locks evidence and finally cleanup.
use super::*;
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe, pin::Pin};
pub(crate) struct Gate {
    pool: PgPool,
    owner: owner::Owner,
    tenant: TenantId,
    name: String,
    held: Option<sqlx::Transaction<'static, sqlx::Postgres>>,
    function: bool,
    trigger: bool,
    revoked: Option<Id>,
}
impl Gate {
    async fn install(&mut self, tenant: TenantId, id: Id) -> DomainResult<()> {
        self.owner.verify(&self.pool).await?;
        let absent:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_proc WHERE proname=$1) AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname=$1)")
            .bind(&self.name).fetch_one(&self.pool).await.map_err(sql)?;
        if !absent {
            return Err(invalid());
        }
        sqlx::query(&format!("CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $gate$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND NEW.target->>'kind'='gateway-attempt' AND NEW.target->>'id'='{id}' AND NEW.action='execute' AND NEW.outcome='failure' THEN PERFORM pg_advisory_xact_lock(hashtextextended('{}',0)); END IF; RETURN NEW; END; $gate$",self.name,self.name)).execute(&self.pool).await.map_err(sql)?;
        self.function = true;
        sqlx::query(&format!(
            "CREATE TRIGGER {} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION {}()",
            self.name, self.name
        ))
        .execute(&self.pool)
        .await
        .map_err(sql)?;
        self.trigger = true;
        let mut held = self.pool.begin().await.map_err(sql)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&self.name)
            .execute(&mut *held)
            .await
            .map_err(sql)?;
        self.held = Some(held);
        Ok(())
    }
    pub(crate) async fn waiting(&self) -> DomainResult<()> {
        tokio::time::timeout(WAIT,async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1 AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295) AND objid::bigint=(hashtextextended($1,0)&4294967295))")
                    .bind(&self.name).fetch_one(&self.pool).await.map_err(sql)?;
                if waiting {return Ok(());}tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.map_err(|_|invalid())?
    }
    pub(crate) async fn release(&mut self) -> DomainResult<()> {
        if let Some(held) = self.held.take() {
            held.rollback().await.map_err(sql)?;
        }
        Ok(())
    }
    pub(crate) async fn revoke(&mut self, key: Id) -> DomainResult<()> {
        self.owner.verify(&self.pool).await?;
        if self.revoked.is_some() {
            return Err(invalid());
        }
        // An owned fault bypasses the shared audit tail only to invalidate this exact Key
        // while publication is proved waiting on the gate. This is not an API grant.
        let updated=sqlx::query("UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL")
            .bind(self.tenant.as_uuid()).bind(key.as_uuid()).execute(&self.pool).await.map_err(sql)?;
        if updated.rows_affected() != 1 {
            return Err(invalid());
        }
        self.revoked = Some(key);
        Ok(())
    }
    async fn close(&mut self) -> DomainResult<()> {
        self.release().await?;
        self.owner.verify(&self.pool).await?;
        if let Some(key) = self.revoked.take() {
            let restored=sqlx::query("UPDATE api_keys SET revoked=false,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND revoked AND deleted_at IS NULL")
                .bind(self.tenant.as_uuid()).bind(key.as_uuid()).execute(&self.pool).await.map_err(sql)?;
            if restored.rows_affected() != 1 {
                return Err(invalid());
            }
        }
        if !self.name.starts_with("agf_stream_gate_")
            || !self.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(invalid());
        }
        tokio::time::timeout(WAIT, async {
            if self.trigger {
                sqlx::query(&format!("DROP TRIGGER {} ON audit_logs", self.name))
                    .execute(&self.pool)
                    .await
                    .map_err(sql)?;
                self.trigger = false;
            }
            if self.function {
                sqlx::query(&format!("DROP FUNCTION {}()", self.name)).execute(&self.pool).await.map_err(sql)?;
                self.function = false;
            }
            Ok(())
        })
        .await
        .map_err(|_| invalid())?
    }
}
pub(crate) async fn with_gate<T, F>(owned: &Owned, id: Id, action: F) -> DomainResult<T>
where
    F: for<'a> FnOnce(&'a mut Gate) -> Pin<Box<dyn Future<Output = DomainResult<T>> + Send + 'a>>,
{
    owned.verify().await?;
    let mut gate = Gate {
        pool: owned.case.pool.clone(),
        owner: owned.owner.clone(),
        tenant: owned.case.h.tenant,
        name: format!("agf_stream_gate_{}", Id::new().as_uuid().simple()),
        held: None,
        function: false,
        trigger: false,
        revoked: None,
    };
    let result = AssertUnwindSafe(async {
        gate.install(owned.case.h.tenant, id).await?;
        action(&mut gate).await
    })
    .catch_unwind()
    .await;
    gate.close().await?;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
pub(crate) struct Reading(Option<tokio::task::JoinHandle<DomainResult<String>>>);
impl Reading {
    pub(crate) fn start(response: axum::response::Response) -> Self {
        Self(Some(tokio::spawn(async move {
            let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024).await.map_err(|_| invalid())?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        })))
    }
    pub(crate) async fn finish(mut self) -> DomainResult<String> {
        let result = tokio::time::timeout(WAIT, self.0.as_mut().ok_or_else(invalid)?)
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())?;
        self.0.take();
        result
    }
}
impl Drop for Reading {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}
