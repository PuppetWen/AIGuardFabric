use super::{
    gate::{Mode, Target, with_gate},
    provider::{self, Engine, Pending},
    *,
};
use tokio::time::{Duration, timeout};

async fn configuration_wait(owner: &Owner, h: &Harness) -> DomainResult<()> {
    owner.check().await?;
    let key = format!("{}:cloud-integration:{}", h.tenant, main_id(h));
    timeout(Duration::from_secs(10),async {
        loop {
            let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.locktype='advisory' AND NOT l.granted AND a.datid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND l.objsubid=1 AND l.classid::bigint=((hashtextextended($1,0)>>32)&4294967295) AND l.objid::bigint=(hashtextextended($1,0)&4294967295))")
                .bind(&key).fetch_one(&owner.pool).await.map_err(sql)?;
            if blocked {return Ok::<_,DomainError>(());} tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_|wire::fixture_error("source writer did not queue behind publication"))?
}
pub(crate) async fn source_lock_order() -> DomainResult<()> {
    let case = SqlCase::open("sch-source-lock-order").await?;
    let engine = Engine::new(101, false).await?;
    let h = provider::attach(case.h.clone(), &engine)?;
    provider::configure(&h, &engine, 0, true).await?;
    let id = Id::new();
    let owner = case.owner.clone();
    with_gate(
        &case.owner,
        h.tenant,
        Target { kind: "scheduler-native-observation", id, action: "read" },
        Mode::Wait,
        move |gate| {
            Box::pin(async move {
                let mut observe_task = provider::start(&h, id, h.admin.clone());
                gate.waiting().await?;
                let mut configured = settings();
                configured["endpoint"] = json!(engine.server.origin);
                let mut save = Pending::start(
                    &h,
                    "PUT",
                    CONFIG.into(),
                    h.admin.clone(),
                    Some(json!({"expected_version":1,"enabled":true,"mock":false,"settings":configured,
            "secrets":{"access_key_id":provider::ACCESS_KEY,"access_key_secret":provider::SECRET}})),
                );
                configuration_wait(&owner, &h).await?;
                assert!(!save.is_finished());
                gate.release().await?;
                assert_eq!(observe_task.finish().await?.status, StatusCode::OK);
                assert_eq!(save.finish().await?.status, StatusCode::OK);
                assert_eq!(agf_api::cloud_store::load(&h.state, h.tenant, NAME).await?.map(|row| row.version), Some(2));
                let result = read(&h, &receipt(id)).await?;
                assert_eq!(result["status"], "observed");
                assert_eq!(result["current"], false);
                assert_eq!(result["originalTarget"]["configurationVersion"], 1);
                let before = snapshot(&h).await?;
                assert_eq!(post(&h, &format!("{BASE}/observe"), observe(id, false)).await?, result);
                assert_eq!(
                    h.post(&format!("{BASE}/observe"), observe(Id::new(), false)).await.status,
                    StatusCode::CONFLICT
                );
                assert_eq!(snapshot(&h).await?, before);
                terminal(&h, id, AuditOutcome::Success).await?;
                engine.count(3).await
            })
        },
    )
    .await?;
    case.owner.pool.close().await;
    Ok(())
}
pub(crate) async fn cancelled_read() -> DomainResult<()> {
    let case = SqlCase::open("sch-cancelled-read").await?;
    let engine = Engine::new(101, false).await?;
    let h = provider::attach(case.h.clone(), &engine)?;
    provider::configure(&h, &engine, 0, true).await?;
    let id = Id::new();
    let (gate, _release) = engine.hold("GetApp", 1)?;
    let mut pending = provider::start(&h, id, h.admin.clone());
    gate.wait_entered().await?;
    pending.cancel().await?;
    gate.release();
    timeout(Duration::from_secs(5), async {
        loop {
            if row(&h, FACT, record_id(&h, FACT, id)).await?.is_some_and(|value| value["status"] == "failed") {
                return Ok::<_, DomainError>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| wire::fixture_error("cancelled read did not finish locally"))??;
    terminal(&h, id, AuditOutcome::Failure).await?;
    engine.count(1).await?;
    let second = provider::attach(case.second().await?, &engine)?;
    let failed = read(&second, &receipt(id)).await?;
    assert_eq!(failed["observation"], Value::Null);
    assert_eq!(failed["total"], Value::Null);
    let before = snapshot(&second).await?;
    assert_eq!(post(&second, &format!("{BASE}/observe"), observe(id, false)).await?, failed);
    assert_eq!(snapshot(&second).await?, before);
    archive(&second, &[id]).await?;
    let archived = read(&h, &receipt(id)).await?;
    assert_eq!(archived["status"], "archived");
    assert_eq!(archived["originalStatus"], "failed");
    engine.count(1).await?;
    chain(&second).await?;
    case.owner.pool.close().await;
    Ok(())
}
async fn expired_crash(owner: &Owner, h: &Harness, id: Id) -> DomainResult<Value> {
    owner.check().await?;
    let fact_id = record_id(h, FACT, id);
    let mut fact = row(h, FACT, fact_id).await?.ok_or_else(|| wire::fixture_error("crash claim missing"))?;
    let mut journal = row(h, STATE, main_id(h)).await?.ok_or_else(|| wire::fixture_error("crash journal missing"))?;
    assert_eq!(fact["status"], "reading");
    assert_eq!(journal["active"]["request_id"], json!(id));
    // A durable crash fixture, not a changed process clock: preserve UUID, hash, target, claim and generation.
    // Its original 120-second lease is historical and valid; both records change in one owned SQL transaction.
    let started = Timestamp::now().offset_secs(-121);
    let expires = started.offset_secs(120);
    fact["submitted_at"] = json!(started);
    fact["started_at"] = json!(started);
    fact["expires_at"] = json!(expires);
    journal["active"]["expires_at"] = json!(expires);
    let mut tx = owner.pool.begin().await.map_err(sql)?;
    for (kind, key, value) in [(STATE, main_id(h), &journal), (FACT, fact_id, &fact)] {
        assert_eq!(sqlx::query("UPDATE console_configurations SET payload=$4,updated_at=now() WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL")
            .bind(h.tenant.as_uuid()).bind(kind).bind(key.as_uuid()).bind(value).execute(&mut *tx).await.map_err(sql)?.rows_affected(),1);
    }
    tx.commit().await.map_err(sql)?;
    Ok(fact)
}
pub(crate) async fn expired_read_archive() -> DomainResult<()> {
    let case = SqlCase::open("sch-expired-marker").await?;
    let engine = Engine::new(101, false).await?;
    let h = provider::attach(case.h.clone(), &engine)?;
    provider::configure(&h, &engine, 0, true).await?;
    let id = Id::new();
    let (gate, _release) = engine.hold("GetApp", 1)?;
    let mut pending = provider::start(&h, id, h.admin.clone());
    gate.wait_entered().await?;
    let fact = expired_crash(&case.owner, &h, id).await?;
    let second = provider::attach(case.second().await?, &engine)?;
    let interrupted = read(&second, &receipt(id)).await?;
    assert_eq!(interrupted["status"], "interrupted");
    assert_eq!(interrupted["archivable"], true);
    archive(&second, &[id]).await?;
    let marker = row(&second, BODY, record_id(&second, BODY, id)).await?;
    assert_eq!(marker.as_ref().map(|v| v["class"].clone()), Some(json!("archived")));
    let committed = snapshot(&second).await?;
    gate.release();
    assert_eq!(pending.finish().await?.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&second).await?, committed);
    assert_eq!(row(&second, FACT, record_id(&second, FACT, id)).await?, Some(fact));
    assert_eq!(row(&second, BODY, record_id(&second, BODY, id)).await?, marker);
    let archived = read(&h, &receipt(id)).await?;
    assert_eq!(archived["originalStatus"], "interrupted");
    assert_eq!(post(&h, &format!("{BASE}/observe"), observe(id, false)).await?, archived);
    assert_eq!(snapshot(&h).await?, committed);
    assert!(audits(&h, id, "scheduler-native-observation").await?.is_empty());
    engine.count(1).await?;
    chain(&h).await?;
    case.owner.pool.close().await;
    Ok(())
}
pub(crate) async fn disabled_and_isolated() -> DomainResult<()> {
    let case = SqlCase::open("sch-disabled-local").await?;
    mock(&case.h, 0, true).await?;
    let id = Id::new();
    post(&case.h, &format!("{BASE}/observe"), observe(id, true)).await?;
    let binding = bindings(&case.h, Id::new(), id, 0).await?;
    assert_eq!(binding["version"], 1);
    mock(&case.h, 1, false).await?;
    let second = case.second().await?;
    let before = snapshot(&second).await?;
    assert_eq!(read(&second, BASE).await?["canObserve"], false);
    assert_eq!(snapshot(&second).await?, before);
    let reply = second
        .request(
            "PUT",
            &format!("{BASE}/bindings"),
            Some(&second.admin),
            Some(json!({"action":"disable","request_id":Id::new(),"expected_version":1})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["locallyEnabled"], false);
    assert_eq!(reply.json()["version"], 2);
    archive(&second, &[id]).await?;
    let archived = read(&second, &receipt(id)).await?;
    assert_eq!(archived["status"], "archived");
    assert_eq!(archived["current"], false);
    let before = snapshot(&second).await?;
    assert_eq!(post(&second, &format!("{BASE}/observe"), observe(id, true)).await?, archived);
    archive(&second, &[id]).await?;
    assert_eq!(snapshot(&second).await?, before);
    let foreign = case.foreign().await?;
    let foreign_before = snapshot(&foreign).await?;
    assert_eq!(foreign.get(&receipt(id)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        foreign
            .post(&format!("{BASE}/observations/archive"), json!({"expected_generation":0,"request_ids":[id]}))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(snapshot(&foreign).await?, foreign_before);
    assert_eq!(snapshot(&second).await?, before);
    chain(&second).await?;
    chain(&foreign).await?;
    case.owner.pool.close().await;
    Ok(())
}
