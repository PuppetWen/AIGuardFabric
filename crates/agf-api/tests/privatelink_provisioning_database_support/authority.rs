use super::{Case, error, p, sql, wire::Pending};
use crate::common::*;
use agf_core::{error::DomainResult, ids::Id};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::time::{Duration, timeout};
pub(crate) async fn revoke_while_claim_waits(
    case: &Case,
    h: &Harness,
    body: Value,
    key: Id,
    token: &str,
) -> DomainResult<()> {
    let request = p::id(&body, "request_id")?;
    let name = format!("privatelink_wait_{}", Id::new().as_uuid().simple());
    case.check().await?;
    sqlx::query(&format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $cms$ BEGIN IF NEW.tenant_id='{}'::uuid AND NEW.target->>'kind'='privatelink-provisioning-claim' AND NEW.target->>'id'='{request}' THEN PERFORM pg_advisory_xact_lock(hashtextextended('{name}',0)); END IF; RETURN NEW; END; $cms$",h.tenant)).execute(&case.inner.pool).await.map_err(sql)?;
    case.check().await?;
    sqlx::query(&format!("CREATE TRIGGER {name} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION {name}()"))
        .execute(&case.inner.pool)
        .await
        .map_err(sql)?;
    let mut held = case.inner.pool.begin().await.map_err(sql)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(&name)
        .execute(&mut *held)
        .await
        .map_err(sql)?;
    let mut pending = None;
    let before = p::snapshot(h).await?;
    let result=AssertUnwindSafe(async {
        pending=Some(Pending::start(h.clone(),format!("{}/apply",p::BASE),token.into(),body));
        timeout(Duration::from_secs(10),async {
            loop {
                case.check().await?;
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND objid=(hashtextextended($1,0)&4294967295)::oid AND classid=((hashtextextended($1,0)>>32)&4294967295)::oid)").bind(&name).fetch_one(&case.inner.pool).await.map_err(sql)?;
                if waiting { return Ok::<_,agf_core::error::DomainError>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.map_err(|_|error("claim did not reach real audit-tail lock"))??;
        case.check().await?;
        assert_eq!(sqlx::query("UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL")
            .bind(h.tenant.as_uuid()).bind(key.as_uuid()).execute(&case.inner.pool).await.map_err(sql)?.rows_affected(),1);
        Ok::<(), agf_core::error::DomainError>(())
    }).catch_unwind().await;
    held.rollback().await.map_err(sql)?;
    let reply = if let Some(pending) = pending { Some(pending.finish().await?) } else { None };
    case.check().await?;
    sqlx::query(&format!("DROP TRIGGER {name} ON audit_logs")).execute(&case.inner.pool).await.map_err(sql)?;
    case.check().await?;
    sqlx::query(&format!("DROP FUNCTION {name}()")).execute(&case.inner.pool).await.map_err(sql)?;
    result.map_err(|_| error("claim fixture panicked after gate cleanup"))??;
    assert_eq!(reply.ok_or_else(|| error("claim reply absent"))?.status, StatusCode::FORBIDDEN);
    assert!(p::snapshot(h).await? == before, "post-audit revoked Key published claim");
    Ok(())
}
