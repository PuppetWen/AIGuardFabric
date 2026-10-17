use super::{
    gate::{Mode, Target, with_gate},
    publication::global_fact,
    *,
};
use native::provider::Pending;
use tokio::time::{Duration, timeout};

pub(crate) async fn key_withdrawal(scope_only: bool) -> DomainResult<()> {
    for phase in ["claim", "start", "complete"] {
        let f = Fixture::new("cb-current-key").await?;
        let input = f.input("asset-inventory", "owned-key-wait", 0, 1);
        let fact =
            if phase == "claim" { json!({"factId":global_fact(&f, &input)?}) } else { f.admit(input.clone()).await? };
        if phase == "complete" {
            f.start(&fact).await?;
        }
        let kind = match phase {
            "claim" => "scheduler-native-callback-claim",
            "start" => "scheduler-native-callback-start",
            _ => EXECUTION,
        };
        let h = f.h.clone();
        let token = f.token.clone();
        let owner = f.case.owner.clone();
        let key = f.key;
        let original = fact.clone();
        with_gate(&f.case.owner, h.tenant, Target { kind, id: native::identifier(&fact, "factId")?,
            action: if phase == "claim" { "create" } else { "execute" } }, Mode::Wait, move |gate| Box::pin(async move {
            let path = match phase {
                "claim" => ROOT.into(), "start" => format!("{}/validate", fact_path(&original)?),
                _ => format!("{}/complete", fact_path(&original)?),
            };
            let body = match phase { "claim" => input, "start" => claim(&original), _ => complete(&original, good()) };
            let mut pending = Pending::start(&h, "POST", path, token, Some(body));
            gate.waiting().await?;
            // For complete this already includes the committed authenticated pending stage.
            let before = snapshot(&h).await?;
            owner.check().await?;
            let query = if scope_only {
                "UPDATE api_keys SET scopes=scopes-'assets:read',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL"
            } else {
                "UPDATE api_keys SET revoked=true,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND deleted_at IS NULL"
            };
            assert_eq!(sqlx::query(query).bind(h.tenant.as_uuid()).bind(key.as_uuid()).execute(&owner.pool).await.map_err(native::sql)?.rows_affected(), 1);
            gate.release().await?;
            assert_eq!(pending.finish().await?.status, StatusCode::FORBIDDEN);
            assert_eq!(snapshot(&h).await?, before);
            assert_eq!(audit_count(&h, &original, kind).await?, 0);
            Ok(())
        })).await?;
        if phase == "complete" {
            assert_eq!(native::rows(&f.h, PENDING).await?.len(), 1);
            assert_eq!(native::rows(&f.h, EXECUTION).await?[0]["state"], "running");
        }
        f.engine.count(2).await?;
        f.clean().await?;
    }
    Ok(())
}

pub(crate) async fn tenant_wait() -> DomainResult<()> {
    for start in [false, true] {
        let f = Fixture::new("cb-tenant-wait").await?;
        let input = f.input("asset-inventory", "owned-tenant-current", 0, 1);
        let fact = if start { f.admit(input.clone()).await? } else { json!({"factId":global_fact(&f, &input)?}) };
        let before = snapshot(&f.h).await?;
        f.case.owner.check().await?;
        let mut tx = f.case.owner.pool.begin().await.map_err(native::sql)?;
        sqlx::query("SELECT id FROM tenants WHERE id=$1 AND enabled AND deleted_at IS NULL FOR UPDATE")
            .bind(f.h.tenant.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .map_err(native::sql)?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *tx).await.map_err(native::sql)?;
        let path = if start { format!("{}/validate", fact_path(&fact)?) } else { ROOT.into() };
        let body = if start { claim(&fact) } else { input };
        let mut pending = Pending::start(&f.h, "POST", path, f.token.clone(), Some(body));
        // The exact immutable tenant row is held before the API's FOR SHARE guard, not after audit.
        timeout(Duration::from_secs(20), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%agf_agentteams_lock_tenant%')")
                    .bind(pid).fetch_one(&f.case.owner.pool).await.map_err(native::sql)?;
                if waiting { return Ok::<_, DomainError>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.map_err(|_| native::wire::fixture_error("callback never waited on exact tenant guard"))??;
        assert_eq!(sqlx::query("UPDATE tenants SET enabled=false,version=version+1,updated_at=now() WHERE id=$1 AND enabled AND deleted_at IS NULL")
            .bind(f.h.tenant.as_uuid()).execute(&mut *tx).await.map_err(native::sql)?.rows_affected(), 1);
        tx.commit().await.map_err(native::sql)?;
        assert_eq!(pending.finish().await?.status, StatusCode::FORBIDDEN);
        assert_eq!(snapshot(&f.h).await?, before);
        assert_eq!(
            audit_count(
                &f.h,
                &fact,
                if start { "scheduler-native-callback-start" } else { "scheduler-native-callback-claim" }
            )
            .await?,
            0
        );
        f.engine.count(2).await?;
        f.clean().await?;
    }
    Ok(())
}

pub(crate) async fn current_wait() -> DomainResult<()> {
    source_wait().await?;
    super::negative::qualification_wait().await
}
async fn source_wait() -> DomainResult<()> {
    let f = Fixture::new("cb-source-fence").await?;
    let fact = f.admit(f.input("asset-inventory", "owned-source-fence", 0, 1)).await?;
    let source = native::row(&f.h, "cloud-integration", native::main_id(&f.h))
        .await?
        .ok_or_else(|| native::wire::fixture_error("source record absent"))?;
    // Prepare a real valid next-version source through its public API, then use only those exact snapshots.
    native::provider::configure(&f.h, &f.engine, 1, true).await?;
    let changed = native::row(&f.h, "cloud-integration", native::main_id(&f.h))
        .await?
        .ok_or_else(|| native::wire::fixture_error("changed source absent"))?;
    f.case.owner.check().await?;
    f.h.state.configurations.put(f.h.tenant, "cloud-integration", native::main_id(&f.h), &source).await?;
    let before = snapshot(&f.h).await?;
    let mut tx = f.case.owner.pool.begin().await.map_err(native::sql)?;
    let lock = format!("{}:cloud-integration:{}", f.h.tenant, native::main_id(&f.h));
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(&lock)
        .execute(&mut *tx)
        .await
        .map_err(native::sql)?;
    let mut pending =
        Pending::start(&f.h, "POST", format!("{}/validate", fact_path(&fact)?), f.token.clone(), Some(claim(&fact)));
    gate::wait_advisory(&f.case.owner, &lock).await?;
    assert_eq!(sqlx::query("UPDATE console_configurations SET payload=$4,updated_at=now() WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL")
        .bind(f.h.tenant.as_uuid()).bind("cloud-integration").bind(native::main_id(&f.h).as_uuid()).bind(changed)
        .execute(&mut *tx).await.map_err(native::sql)?.rows_affected(), 1);
    tx.commit().await.map_err(native::sql)?;
    assert_eq!(pending.finish().await?.status, StatusCode::CONFLICT);
    assert_eq!(serde_json::to_value(native::rows(&f.h, EXECUTION).await?)?, before["callback"][EXECUTION]);
    assert_eq!(audit_count(&f.h, &fact, "scheduler-native-callback-start").await?, 0);
    f.engine.count(2).await?;
    f.clean().await
}
