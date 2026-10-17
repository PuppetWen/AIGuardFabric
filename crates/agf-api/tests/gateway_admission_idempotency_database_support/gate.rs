//! Hold only this owned tenant/actor's genuine admission Configure audit INSERT.
use super::*;
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe, time::Duration};
pub(crate) struct Gate {
    function: String,
    trigger: String,
    key: String,
}
impl Gate {
    pub(crate) async fn install(owned: &Owned, actor: Id) -> DomainResult<Self> {
        owned.ownership.verify(&owned.case.pool).await?;
        let suffix = Id::new().as_uuid().simple().to_string();
        let function = format!("agf_gw_key_fn_{suffix}");
        let trigger = format!("agf_gw_key_tr_{suffix}");
        let key = format!("owned-gateway-key-audit:{suffix}");
        let tenant = owned.case.h.tenant;
        sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND NEW.actor->>'id'='{actor}' AND NEW.target->>'kind'='gateway-admission' AND NEW.target->>'id'=NEW.request_id AND NEW.action='configure' AND NEW.outcome='success' THEN PERFORM pg_advisory_xact_lock(hashtextextended('{key}',0)); END IF; RETURN NEW; END $$"))
            .execute(&owned.case.pool).await.map_err(sql_error)?;
        let created = sqlx::query(&format!(
            "CREATE TRIGGER {trigger} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION {function}()"
        ))
        .execute(&owned.case.pool)
        .await;
        if let Err(error) = created {
            sqlx::query(&format!("DROP FUNCTION {function}()")).execute(&owned.case.pool).await.map_err(sql_error)?;
            return Err(sql_error(error));
        }
        Ok(Self { function, trigger, key })
    }
    pub(crate) async fn invoke<F, Fut>(
        self,
        owned: &Owned,
        h: Harness,
        token: String,
        key: &'static str,
        during: F,
    ) -> DomainResult<Resp>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = DomainResult<()>>,
    {
        owned.ownership.verify(&owned.case.pool).await?;
        let mut holder = owned.case.pool.begin().await.map_err(sql_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&self.key)
            .execute(&mut *holder)
            .await
            .map_err(sql_error)?;
        let mut request =
            tokio::spawn(async move { post(&h, &token, key, "/v1/chat/completions", body("audit-wait")).await });
        let result = AssertUnwindSafe(async {
            self.waiting(owned).await?;
            during().await
        })
        .catch_unwind()
        .await;
        holder.rollback().await.map_err(sql_error)?;
        let response = tokio::time::timeout(Duration::from_secs(20), &mut request).await;
        if response.is_err() {
            request.abort();
            let _ = request.await;
        }
        owned.ownership.verify(&owned.case.pool).await?;
        sqlx::query(&format!("DROP TRIGGER {} ON audit_logs", self.trigger))
            .execute(&owned.case.pool)
            .await
            .map_err(sql_error)?;
        sqlx::query(&format!("DROP FUNCTION {}()", self.function))
            .execute(&owned.case.pool)
            .await
            .map_err(sql_error)?;
        match result {
            Ok(result) => result?,
            Err(panic) => std::panic::resume_unwind(panic),
        }
        response.map_err(|_| invalid())?.map_err(|_| invalid())
    }
    async fn waiting(&self, owned: &Owned) -> DomainResult<()> {
        tokio::time::timeout(Duration::from_secs(8),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1 AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295) AND objid::bigint=(hashtextextended($1,0)&4294967295))")
                    .bind(&self.key).fetch_one(&owned.case.pool).await.map_err(sql_error)?;
                if waiting {return Ok::<(),agf_core::error::DomainError>(())}
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.map_err(|_|invalid())?
    }
}
fn sql_error(error: sqlx::Error) -> agf_core::error::DomainError {
    agf_storage::map_sqlx_err("owned_gateway_admission_key_gate", &error)
}
