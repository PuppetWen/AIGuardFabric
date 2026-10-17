//! Precise owned-tenant/intent success-audit gate; no source update inside held publication locks.
use super::Case;
use crate::{KIND, common::*};
use agf_core::ids::Id;
use futures::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe, time::Duration};
pub(super) struct Gate {
    function: String,
    trigger: String,
    key: String,
}
impl Gate {
    pub(super) async fn install(case: &Case, input: &Value) -> Self {
        case.check().await;
        let suffix = Id::new().as_uuid().simple().to_string();
        let function = format!("agf_orch_fn_{suffix}");
        let trigger = format!("agf_orch_tr_{suffix}");
        let key = format!("owned-orchestration-audit:{suffix}");
        let tenant = case.h.tenant;
        let request = Id::parse(input["request_id"].as_str().unwrap()).unwrap();
        assert!(!request.is_nil());
        sqlx::query(&format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='{tenant}'::uuid AND NEW.target->>'kind'='{KIND}' AND NEW.request_id='{request}' AND NEW.action='update' AND NEW.outcome='success' THEN PERFORM pg_advisory_xact_lock(hashtextextended('{key}',0)); END IF; RETURN NEW; END $$"))
            .execute(&case.pool).await.unwrap();
        case.check().await;
        let installed = sqlx::query(&format!(
            "CREATE TRIGGER {trigger} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION {function}()"
        ))
        .execute(&case.pool)
        .await;
        if installed.is_err() {
            case.check().await;
            sqlx::query(&format!("DROP FUNCTION {function}()")).execute(&case.pool).await.unwrap();
        }
        installed.unwrap();
        Self { function, trigger, key }
    }
    async fn waiting(&self, case: &Case) {
        case.check().await;
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND objsubid=1 AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295) AND objid::bigint=(hashtextextended($1,0)&4294967295))")
                    .bind(&self.key).fetch_one(&case.pool).await.unwrap();
                if blocked { break; } tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.expect("exact orchestration audit gate was not reached");
    }
    async fn clean(&self, case: &Case) {
        case.check().await;
        sqlx::query(&format!("DROP TRIGGER {} ON audit_logs", self.trigger)).execute(&case.pool).await.unwrap();
        case.check().await;
        sqlx::query(&format!("DROP FUNCTION {}()", self.function)).execute(&case.pool).await.unwrap();
    }
    pub(super) async fn invoke<F, Fut>(&self, case: &Case, path: String, input: Value, token: String, during: F) -> Resp
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        case.check().await;
        let mut holder = case.pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(&self.key)
            .execute(&mut *holder)
            .await
            .unwrap();
        let h = case.h.clone();
        let mut pending = tokio::spawn(async move { h.request("PUT", &path, Some(&token), Some(input)).await });
        let result = AssertUnwindSafe(async {
            self.waiting(case).await;
            during().await;
        })
        .catch_unwind()
        .await;
        holder.rollback().await.unwrap();
        let finished = tokio::time::timeout(Duration::from_secs(20), &mut pending).await;
        if finished.is_err() {
            pending.abort();
            let _ = pending.await;
        }
        self.clean(case).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
        finished.expect("orchestration request did not finish after releasing audit gate").unwrap()
    }
}
