//! Owned exact-target BEFORE INSERT gate; current authority is tested after the audit wait.
use super::{Case, sql_error};
use crate::agentteams_task_handling_support::{id, invalid, ok};
use crate::common::*;
use agf_core::{error::DomainResult, ids::Id};
pub(crate) struct Gate {
    function: String,
    trigger: String,
    key: String,
}
impl Gate {
    pub(crate) async fn install(case: &Case, request: Id) -> DomainResult<Self> {
        case.owner.verify(&case.sql.pool).await?;
        let suffix = Id::new().as_uuid().simple().to_string();
        let function = format!("agf_wp4_fn_{suffix}");
        let trigger = format!("agf_wp4_tr_{suffix}");
        let key = format!("owned-wp4-audit:{suffix}");
        let tenant = case.fixture.h.tenant;
        sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND NEW.target->>'kind'='agentteams-task-handling' AND NEW.target->>'id'='{request}' AND NEW.action='update' AND NEW.outcome='success' THEN PERFORM pg_advisory_xact_lock(hashtextextended('{key}',0)); END IF; RETURN NEW; END $$"))
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
        case.owner.verify(&case.sql.pool).await?;
        sqlx::query(&format!("DROP TRIGGER {} ON audit_logs", self.trigger))
            .execute(&case.sql.pool)
            .await
            .map_err(sql_error)?;
        sqlx::query(&format!("DROP FUNCTION {}()", self.function)).execute(&case.sql.pool).await.map_err(sql_error)?;
        Ok(())
    }
}
pub(crate) async fn key(h: &Harness) -> DomainResult<(String, Id)> {
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"wp4-owned-audit-editor",
        "scopes":["alicloud:read","sources:read","alicloud:write","sources:write"]}),
        )
        .await;
    ok(&response, StatusCode::CREATED);
    let value = response.json();
    Ok((value["plaintext"].as_str().ok_or_else(invalid)?.into(), id(&value["api_key"]["id"])?))
}
pub(crate) async fn revoke(case: &Case, key: Id) -> DomainResult<()> {
    case.owner.verify(&case.sql.pool).await?;
    let changed =
        sqlx::query("UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked")
            .bind(case.fixture.h.tenant.as_uuid())
            .bind(key.as_uuid())
            .execute(&case.sql.pool)
            .await
            .map_err(sql_error)?;
    assert_eq!(changed.rows_affected(), 1);
    Ok(())
}
