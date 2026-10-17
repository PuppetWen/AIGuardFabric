//! Exact tenant/blacklist Configure Success audit gate, always removed after a caught panic.
use super::{Case, sql_error};
use agf_core::{error::DomainResult, ids::Id};
pub(crate) struct Gate {
    function: String,
    trigger: String,
    key: String,
}
impl Gate {
    pub(crate) async fn install(case: &Case) -> DomainResult<Self> {
        case.verify().await?;
        let suffix = Id::new().as_uuid().simple().to_string();
        let function = format!("agf_bl_fn_{suffix}");
        let trigger = format!("agf_bl_tr_{suffix}");
        let key = format!("owned-blacklist-audit:{suffix}");
        let tenant = case.sql.h.tenant;
        sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND NEW.target->>'kind'='blacklist' AND NEW.action='configure' AND NEW.outcome='success' THEN PERFORM pg_advisory_xact_lock(hashtextextended('{key}',0)); END IF; RETURN NEW; END $$"))
            .execute(&case.sql.pool).await.map_err(sql_error)?;
        let created = sqlx::query(&format!(
            "CREATE TRIGGER {trigger} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION {function}()"
        ))
        .execute(&case.sql.pool)
        .await;
        if let Err(error) = created {
            sqlx::query(&format!("DROP FUNCTION {function}()")).execute(&case.sql.pool).await.map_err(sql_error)?;
            return Err(sql_error(error));
        }
        Ok(Self { function, trigger, key })
    }
    pub(crate) async fn hold(&self, case: &Case) -> DomainResult<(sqlx::Transaction<'_, sqlx::Postgres>, i32)> {
        let mut tx = case.sql.pool.begin().await.map_err(sql_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&self.key)
            .execute(&mut *tx)
            .await
            .map_err(sql_error)?;
        let pid = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *tx).await.map_err(sql_error)?;
        Ok((tx, pid))
    }
    pub(crate) async fn clean(&self, case: &Case) -> DomainResult<()> {
        case.verify().await?;
        sqlx::query(&format!("DROP TRIGGER {} ON audit_logs", self.trigger))
            .execute(&case.sql.pool)
            .await
            .map_err(sql_error)?;
        sqlx::query(&format!("DROP FUNCTION {}()", self.function)).execute(&case.sql.pool).await.map_err(sql_error)?;
        Ok(())
    }
}
