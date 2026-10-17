use super::{
    gate::{Mode, Target, with_gate},
    *,
};
use tokio::time::{Duration, Instant, timeout};

pub(crate) async fn rollback() -> DomainResult<()> {
    for start in [false, true] {
        let f = Fixture::new("cb-atomic-audit").await?;
        let input = f.input("asset-inventory", "owned-audit-failure", 0, 1);
        let fact = if start { f.admit(input.clone()).await? } else { json!({"factId":global_fact(&f, &input)?}) };
        let prior = snapshot(&f.h).await?;
        let h = f.h.clone();
        let token = f.token.clone();
        let fact_copy = fact.clone();
        with_gate(
            &f.case.owner,
            h.tenant,
            Target {
                kind: if start { "scheduler-native-callback-start" } else { "scheduler-native-callback-claim" },
                id: native::identifier(&fact, "factId")?,
                action: if start { "execute" } else { "create" },
            },
            Mode::Reject,
            move |_| {
                Box::pin(async move {
                    let path = if start { format!("{}/validate", fact_path(&fact_copy)?) } else { ROOT.into() };
                    let body = if start { claim(&fact_copy) } else { input };
                    assert!(!h.request("POST", &path, Some(&token), Some(body)).await.status.is_success());
                    assert_eq!(snapshot(&h).await?, prior);
                    assert_eq!(
                        audit_count(
                            &h,
                            &fact_copy,
                            if start { "scheduler-native-callback-start" } else { "scheduler-native-callback-claim" }
                        )
                        .await?,
                        0
                    );
                    Ok(())
                })
            },
        )
        .await?;
        if start {
            assert_eq!(f.get(&fact).await?["state"], "admitted");
            assert_eq!(f.start(&fact).await?["mayExecute"], true);
        } else {
            assert_eq!(
                f.h.request("GET", &fact_path(&fact)?, Some(&f.token), None).await.status,
                StatusCode::NOT_FOUND
            );
            assert!(native::rows(&f.h, EXECUTION).await?.is_empty());
            assert!(native::rows(&f.h, BATCH).await?.is_empty());
            assert!(native::rows(&f.h, REQUEST).await?.is_empty());
        }
        f.engine.count(2).await?;
        f.clean().await?;
    }
    Ok(())
}

pub(crate) async fn recover() -> DomainResult<()> {
    let f = Fixture::new("cb-known-recovery").await?;
    let admitted = f.admit(f.input("asset-inventory", "owned-known", 0, 1)).await?;
    f.start(&admitted).await?;
    let before = native::rows(&f.h, EXECUTION).await?;
    let batches = native::rows(&f.h, BATCH).await?;
    let progress = native::rows(&f.h, PROGRESS).await?;
    let h = f.h.clone();
    let token = f.token.clone();
    let fact = admitted.clone();
    with_gate(
        &f.case.owner,
        h.tenant,
        Target { kind: EXECUTION, id: native::identifier(&fact, "factId")?, action: "execute" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let result =
                    call(&h, &token, "POST", &format!("{}/complete", fact_path(&fact)?), Some(complete(&fact, good())))
                        .await?;
                assert_eq!(result["completionState"], "pending_audit");
                assert_eq!(result["state"], "running");
                passive(&result);
                assert_eq!(native::rows(&h, EXECUTION).await?, before);
                assert_eq!(native::rows(&h, BATCH).await?, batches);
                assert_eq!(native::rows(&h, PROGRESS).await?, progress);
                let pending = native::rows(&h, PENDING).await?;
                assert_eq!(pending.len(), 1);
                assert!(pending[0]["secret"].is_object());
                assert!(pending[0].get("outcome").is_none());
                assert_eq!(audit_count(&h, &fact, EXECUTION).await?, 0);
                Ok(())
            })
        },
    )
    .await?;
    let second = f.second().await?;
    let prior = snapshot(&f.h).await?;
    let known = call(&second, &f.token, "GET", &fact_path(&admitted)?, None).await?;
    assert_eq!(known["completionState"], "pending_audit");
    assert_eq!(known["outcome"], good());
    passive(&known);
    assert_eq!(snapshot(&f.h).await?, prior);
    let mut different = good();
    different["degraded"] = json!(true);
    assert_eq!(
        f.h.request(
            "POST",
            &format!("{}/complete", fact_path(&admitted)?),
            Some(&f.token),
            Some(complete(&admitted, different))
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&f.h).await?, prior);
    let done = call(
        &second,
        &f.token,
        "POST",
        &format!("{}/complete", fact_path(&admitted)?),
        Some(complete(&admitted, good())),
    )
    .await?;
    assert_eq!(done["completionState"], "complete");
    assert_eq!(done["state"], "succeeded");
    assert_eq!(done["outcome"], good());
    passive(&done);
    assert_eq!(audit_count(&f.h, &admitted, "scheduler-native-callback-start").await?, 1);
    assert_eq!(audit_count(&f.h, &admitted, EXECUTION).await?, 1);
    let before = snapshot(&f.h).await?;
    assert_eq!(f.complete(&admitted, good()).await?, done);
    assert_eq!(snapshot(&f.h).await?, before);
    f.engine.count(2).await?;
    f.clean().await
}

pub(crate) async fn expired() -> DomainResult<()> {
    let f = Fixture::new("cb-real-lease").await?;
    let input = f.input("asset-inventory", "owned-real-expiry", 0, 1);
    let fact = f.admit(input.clone()).await?;
    let expires: Timestamp = serde_json::from_value(fact["startLeaseExpiresAt"].clone())?;
    let began = Instant::now();
    timeout(Duration::from_secs(114), async {
        while Timestamp::now() < expires {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| native::wire::fixture_error("original real lease did not expire"))?;
    assert!(began.elapsed() >= Duration::from_secs(108));
    let original = snapshot(&f.h).await?;
    let second = f.second().await?;
    for _ in 0..3 {
        let dto = call(&second, &f.token, "GET", &fact_path(&fact)?, None).await?;
        assert_eq!(dto["state"], "uncertain");
        assert_eq!(dto["startLeaseExpiresAt"], fact["startLeaseExpiresAt"]);
        assert_eq!(dto["claimId"], fact["claimId"]);
        passive(&dto);
    }
    passive(&f.admit(input).await?);
    assert_eq!(
        f.h.request("POST", &format!("{}/validate", fact_path(&fact)?), Some(&f.token), Some(claim(&fact)))
            .await
            .status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(snapshot(&f.h).await?, original);
    assert_eq!(audit_count(&f.h, &fact, "scheduler-native-callback-start").await?, 0);
    f.engine.count(2).await?;
    f.clean().await
}

pub(crate) fn global_fact(f: &Fixture, input: &Value) -> DomainResult<Id> {
    let value =
        json!([f.h.tenant, input["app_id"], input["job_id"], input["job_execution_id"], input["partition_index"]]);
    let hash = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&value)?));
    Ok(deterministic_id("agf.scheduler.callback.fact.v1", &hash))
}
