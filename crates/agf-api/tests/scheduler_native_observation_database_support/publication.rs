use super::{
    gate::{Mode, Target, with_gate},
    provider::{self, Engine},
    *,
};

pub(crate) async fn durable_uuid() -> DomainResult<()> {
    let case = SqlCase::open("sch-durable-uuid").await?;
    let engine = Engine::new(101, false).await?;
    let h = provider::attach(case.h.clone(), &engine)?;
    provider::configure(&h, &engine, 0, true).await?;
    let second = provider::attach(case.second().await?, &engine)?;
    let id = Id::new();
    let input = observe(id, false);
    let (gate, _release) = engine.hold("GetApp", 1)?;
    let mut pending = provider::start(&h, id, h.admin.clone());
    gate.wait_entered().await?;
    let replay = post(&second, &format!("{BASE}/observe"), input.clone()).await?;
    assert_eq!(replay["status"], "reading");
    assert_eq!(engine.received()?, 1);
    gate.release();
    let response = pending.finish().await?;
    assert_eq!(response.status, StatusCode::OK);
    let complete = response.json();
    assert_eq!(complete["total"], 101);
    engine.count(3).await?;
    let before = snapshot(&h).await?;
    assert_eq!(post(&second, &format!("{BASE}/observe"), input.clone()).await?, complete);
    assert_eq!(read(&second, &receipt(id)).await?, complete);
    assert_eq!(
        read(&second, &format!("{}?page=2", receipt(id))).await?["observation"]["jobs"].as_array().map(Vec::len),
        Some(1)
    );
    let mut changed = input;
    changed["confirm_live"] = json!(true);
    assert_eq!(second.post(&format!("{BASE}/observe"), changed).await.status, StatusCode::CONFLICT);
    let purpose = second
        .request(
            "PUT",
            &format!("{BASE}/bindings"),
            Some(&second.admin),
            Some(json!({"action":"disable","request_id":id,"expected_version":0})),
        )
        .await;
    assert_eq!(purpose.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&h).await?, before);
    assert_eq!(snapshot(&second).await?, before);
    engine.count(3).await?;
    assert_eq!(audits(&h, id, "scheduler-native-read-claim").await?.len(), 1);
    terminal(&h, id, AuditOutcome::Success).await?;
    case.owner.pool.close().await;
    Ok(())
}
pub(crate) async fn claim_rollback() -> DomainResult<()> {
    let case = SqlCase::open("sch-claim-rollback").await?;
    let engine = Engine::new(101, false).await?;
    let h = provider::attach(case.h.clone(), &engine)?;
    provider::configure(&h, &engine, 0, true).await?;
    let before = snapshot(&h).await?;
    let id = Id::new();
    let owned = h.clone();
    with_gate(
        &case.owner,
        h.tenant,
        Target { kind: "scheduler-native-read-claim", id, action: "create" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let response = owned.post(&format!("{BASE}/observe"), observe(id, false)).await;
                assert!(!response.status.is_success());
                assert_eq!(snapshot(&owned).await?, before);
                assert_eq!(owned.get(&receipt(id)).await.status, StatusCode::NOT_FOUND);
                assert!(audits(&owned, id, "scheduler-native-read-claim").await?.is_empty());
                engine.count(0).await?;
                chain(&owned).await
            })
        },
    )
    .await?;
    case.owner.pool.close().await;
    Ok(())
}
pub(crate) async fn terminal_rollback() -> DomainResult<()> {
    let case = SqlCase::open("sch-final-rollback").await?;
    let engine = Engine::new(101, false).await?;
    let h = provider::attach(case.h.clone(), &engine)?;
    provider::configure(&h, &engine, 0, true).await?;
    let old = Id::new();
    post(&h, &format!("{BASE}/observe"), observe(old, false)).await?;
    let associated = bindings(&h, Id::new(), old, 0).await?;
    assert_eq!(associated["status"], "partial");
    let old_body = row(&h, BODY, record_id(&h, BODY, old)).await?;
    let old_binding = row(&h, BINDING, main_id(&h)).await?;
    let latest = read(&h, BASE).await?["latestObservation"].clone();
    let id = Id::new();
    let owned = h.clone();
    let second = provider::attach(case.second().await?, &engine)?;
    with_gate(
        &case.owner,
        h.tenant,
        Target { kind: "scheduler-native-observation", id, action: "read" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let response = owned.post(&format!("{BASE}/observe"), observe(id, false)).await;
                assert!(!response.status.is_success());
                let fact = row(&owned, FACT, record_id(&owned, FACT, id))
                    .await?
                    .ok_or_else(|| wire::fixture_error("claim missing after failed publication"))?;
                assert_eq!(fact["status"], "reading");
                assert_eq!(fact["body_bytes"], 0);
                assert!(row(&owned, BODY, record_id(&owned, BODY, id)).await?.is_none());
                assert_eq!(row(&owned, BODY, record_id(&owned, BODY, old)).await?, old_body);
                assert_eq!(row(&owned, BINDING, main_id(&owned)).await?, old_binding);
                assert_eq!(read(&owned, BASE).await?["latestObservation"], latest);
                assert!(audits(&owned, id, "scheduler-native-observation").await?.is_empty());
                assert_eq!(audits(&owned, id, "scheduler-native-read-claim").await?.len(), 1);
                let before = snapshot(&owned).await?;
                assert_eq!(post(&second, &format!("{BASE}/observe"), observe(id, false)).await?["status"], "reading");
                assert_eq!(snapshot(&owned).await?, before);
                engine.count(6).await?;
                chain(&owned).await
            })
        },
    )
    .await?;
    case.owner.pool.close().await;
    Ok(())
}
pub(crate) async fn association_and_archive_rollback() -> DomainResult<()> {
    let case = SqlCase::open("sch-local-rollback").await?;
    mock(&case.h, 0, true).await?;
    let id = Id::new();
    post(&case.h, &format!("{BASE}/observe"), observe(id, true)).await?;
    let binding_id = Id::new();
    let before = snapshot(&case.h).await?;
    let h = case.h.clone();
    with_gate(&case.owner,h.tenant,Target {kind:"scheduler-native-bindings",id:binding_id,action:"configure"},Mode::Reject,move |_|Box::pin(async move {
        let result=h.request("PUT",&format!("{BASE}/bindings"),Some(&h.admin),Some(json!({"action":"replace","request_id":binding_id,"expected_version":0,"configuration_version":1,
            "observation_id":id,"bindings":[{"kind":"report","job_id":"9007199254741002"}],"confirm_local_only":true}))).await;
        assert!(!result.status.is_success()); assert_eq!(snapshot(&h).await?,before); chain(&h).await
    })).await?;
    bindings(&case.h, binding_id, id, 0).await?;
    let before = snapshot(&case.h).await?;
    let view = read(&case.h, BASE).await?;
    let h = case.h.clone();
    with_gate(
        &case.owner,
        h.tenant,
        Target { kind: "scheduler-native-archive", id: main_id(&h), action: "configure" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let response = h
                    .post(
                        &format!("{BASE}/observations/archive"),
                        json!({"expected_generation":number(&view,"generation")?,"request_ids":[id]}),
                    )
                    .await;
                assert!(!response.status.is_success());
                assert_eq!(snapshot(&h).await?, before);
                assert_eq!(read(&h, &receipt(id)).await?["archived"], false);
                chain(&h).await
            })
        },
    )
    .await?;
    case.owner.pool.close().await;
    Ok(())
}
