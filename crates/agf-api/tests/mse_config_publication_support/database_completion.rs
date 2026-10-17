//! Provider truth, pending encrypted evidence and local transactional publication remain separate.
use crate::{
    common::*,
    publication_db as db,
    publication_gate::{Mode, Target, with_gate},
    transport::*,
};
use agf_core::{error::DomainResult, ids::Id};

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn terminal_audit_failure_survives_restart_and_disabled_config_recovery_is_pure_local() -> DomainResult<()> {
    let case = db::open("mse-pub-pending-restart").await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let h = f.h.clone();
    let (f, preview) = with_gate(
        &case.pool,
        h.tenant,
        Target { kind: "mse-config-publication", id: request, action: "execute" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let result = f.apply(&preview, request).await?;
                assert_eq!(result["completionState"], "pending_audit");
                assert_eq!(result["cloudWrite"]["status"], "accepted");
                assert_eq!(result["readback"]["status"], "matched");
                assert_eq!(f.engine.counts().await, (3, 1));
                assert!(audits(&f.h, request, "mse-config-publication").await?.is_empty());
                let before = snapshot(&f.h).await?;
                read(&f.h, &receipt(request)).await?;
                assert_eq!(snapshot(&f.h).await?, before);
                configure(&f.h, f.engine.address, 1, false).await?;
                Ok((f, preview))
            })
        },
    )
    .await?;
    // The returned fixture is kept below so the actual engine remains alive while proving no network replay.
    // A fresh local registry alone is insufficient; this uses a new AppState sharing the owned SQL database.
    let pending_rows = h.state.configurations.list::<Value>(h.tenant, PENDING).await?;
    assert_eq!(pending_rows.len(), 1);
    let second = case.second_instance().await;
    let original = read(&second, &receipt(request)).await?;
    assert_eq!(original["completionState"], "pending_audit");
    let before = snapshot(&second).await?;
    read(&second, &receipt(request)).await?;
    assert_eq!(snapshot(&second).await?, before);
    let recovered = post(&second, &format!("{}/recover", receipt(request)), json!({})).await?;
    assert_eq!(recovered["target"], original["target"]);
    assert_eq!(recovered["status"], "verified");
    assert_eq!(recovered["completionState"], "complete");
    assert_eq!(recovered["sourceCurrent"], false);
    assert_eq!(f.engine.counts().await, (3, 1));
    assert!(second.state.configurations.list::<Value>(second.tenant, PENDING).await?.is_empty());
    assert_eq!(audits(&second, request, "mse-config-publication").await?.len(), 1);
    let committed = snapshot(&second).await?;
    post(&second, &format!("{}/recover", receipt(request)), json!({})).await?;
    post(&second, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?;
    assert_eq!(snapshot(&second).await?, committed);
    assert_eq!(f.engine.counts().await, (3, 1));
    db::chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn cancelling_the_parent_during_owned_audit_publish_cannot_cancel_or_repeat_the_known_completion()
-> DomainResult<()> {
    let case = db::open("mse-pub-owned-completion").await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let pool = case.pool.clone();
    let tenant = f.h.tenant;
    let pending_id = db::content_id(tenant, request, "pending");
    crate::publication_gate::with_pending_cleanup_fault(&case.pool, tenant, pending_id, move || {
        Box::pin(async move {
            with_gate(
                &pool,
                f.h.tenant,
                Target { kind: "mse-config-publication", id: request, action: "execute" },
                Mode::Wait,
                move |gate| {
                    Box::pin(async move {
                        let pending = Pending::start(
                            f.h.clone(),
                            format!("{BASE}/operations"),
                            f.h.admin.clone(),
                            apply_input(&preview, request)?,
                        );
                        gate.waiting().await?;
                        assert_eq!(f.engine.counts().await, (3, 1));
                        drop(pending);
                        let before = snapshot(&f.h).await?;
                        let staged = read(&f.h, &receipt(request)).await?;
                        assert_eq!(staged["completionState"], "pending_audit");
                        assert_eq!(snapshot(&f.h).await?, before);
                        gate.release().await?;
                        tokio::time::timeout(std::time::Duration::from_secs(5), async {
                            loop {
                                if !audits(&f.h, request, "mse-config-publication").await?.is_empty() {
                                    return Ok::<_, agf_core::error::DomainError>(());
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                            }
                        })
                        .await
                        .map_err(|_| {
                            agf_core::error::DomainError::Timeout(
                                "owned completion did not finish after parent cancellation".into(),
                            )
                        })??;
                        verified(&read(&f.h, &receipt(request)).await?);
                        assert_eq!(audits(&f.h, request, "mse-config-publication").await?.len(), 1);
                        assert_eq!(f.engine.counts().await, (3, 1));
                        assert_eq!(db::row(&f.h, PENDING, pending_id).await?["request_id"], json!(request));
                        let committed = snapshot(&f.h).await?;
                        f.apply(&preview, request).await?;
                        post(&f.h, &format!("{}/recover", receipt(request)), json!({})).await?;
                        assert_eq!(snapshot(&f.h).await?, committed);
                        assert_eq!(f.engine.counts().await, (3, 1));
                        db::chain(&f.h).await
                    })
                },
            )
            .await
        })
    })
    .await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn corrupt_pending_aad_is_rejected_without_state_audit_or_provider_changes() -> DomainResult<()> {
    let case = db::open("mse-pub-pending-aad").await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    f.engine.hold("POST", 1).await;
    let pending =
        Pending::start(f.h.clone(), format!("{BASE}/operations"), f.h.admin.clone(), apply_input(&preview, request)?);
    f.engine.waiting("POST", 1).await?;
    drop(pending);
    wait_pending(&f.h).await?;
    f.engine.release();
    let id = db::content_id(f.h.tenant, request, "pending");
    let trusted = db::row(&f.h, PENDING, id).await?;
    let mut row = trusted.clone();
    row["completion"]["aad"] = json!("owned foreign identity");
    db::check(&case.pool).await?;
    f.h.state.configurations.put(f.h.tenant, PENDING, id, &row).await?;
    let second = route(case.second_instance().await, f.engine.address)?;
    let before = snapshot(&second).await?;
    assert!(second.get(&receipt(request)).await.status.is_server_error());
    assert!(second.post(&format!("{}/recover", receipt(request)), json!({})).await.status.is_server_error());
    assert_eq!(snapshot(&second).await?, before);
    assert_eq!(f.engine.counts().await, (2, 1));
    // Restoring the original authenticated record is a test-only repair; it does not contact the engine.
    second.state.configurations.put(second.tenant, PENDING, id, &trusted).await?;
    let original = post(&second, &format!("{}/recover", receipt(request)), json!({})).await?;
    assert_eq!(original["status"], "uncertain");
    assert_eq!(original["cloudWrite"]["status"], "unknown");
    let scope_id = crate::transport::id(&original["target"], "targetScopeId")?;
    let risk_id =
        agf_core::ids::deterministic_id("agf.mse.config-publication.risk", &format!("{}:{scope_id}", second.tenant));
    let risk = db::row(&second, MAIN, risk_id).await?;
    let fact = db::row(&second, FACT, db::fact_id(second.tenant, request)).await?;
    let generation = number(&read(&second, BASE).await?, "generation")?;
    let archived = db::archive(&second, &[request], generation).await;
    assert_eq!(archived.status, StatusCode::OK);
    assert_eq!(db::row(&second, MAIN, risk_id).await?, risk, "archiving body must not remove unknown-delivery risk");
    assert_eq!(db::row(&second, FACT, db::fact_id(second.tenant, request)).await?, fact);
    assert_eq!(read(&second, &receipt(request)).await?["originalStatus"], "uncertain");
    let immutable = snapshot(&second).await?;
    post(&second, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?;
    assert_eq!(snapshot(&second).await?, immutable);
    assert_eq!(f.engine.counts().await, (2, 1));
    let observation = post(&second, &format!("{BASE}/observe"), observe_input()).await?;
    let state = read(&second, BASE).await?;
    let blocked = second.post(&format!("{BASE}/previews"), json!({"request_id":Id::new(),"configuration_version":1,
        "observation_id":crate::transport::id(&observation,"id")?,"expected_state_version":number(&state,"stateVersion")?,
        "acknowledge_unknown_operation_id":request,"change":{"action":"publish","policies":[{"policy_id":crate::transport::id(&f.policy,"id")?,"version":1}]}})).await;
    assert_eq!(
        blocked.status,
        StatusCode::PRECONDITION_FAILED,
        "a matched observation before old lease expiry cannot authorize an overlapping intent"
    );
    assert_eq!(f.engine.counts().await, (3, 1));
    db::chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_MSE_CONFIG_PUBLICATION_DATABASE_OWNER"]
async fn trusted_history_rollback_after_restart_creates_a_new_write_and_never_downgrades_platform_policy()
-> DomainResult<()> {
    let case = db::open("mse-pub-trusted-rollback").await?;
    let f = Fixture::attach(case.h.clone()).await?;
    let first = f.ready().await?;
    let original = Id::new();
    verified(&f.apply(&first, original).await?);
    let original_content = f.engine.content().await;
    let policy_id = id(&f.policy, "id")?;
    let response =
        f.h.request(
            "PUT",
            &format!("/api/v1/policies/{policy_id}"),
            Some(&f.h.admin),
            Some(json!({"expected_version":1,
        "name":f.policy["name"],"language":"cel","source":"{\"action\":\"deny\"}","action":"deny","enabled":true,
        "priority":1,"intercept_points":["ai-gateway","mcp-proxy"]})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let second = route(case.second_instance().await, f.engine.address)?;
    let current_observation = post(&second, &format!("{BASE}/observe"), observe_input()).await?;
    let state = read(&second, BASE).await?;
    let current_preview = post(
        &second,
        &format!("{BASE}/previews"),
        json!({"request_id":Id::new(),"configuration_version":1,
        "observation_id":id(&current_observation,"id")?,"expected_state_version":number(&state,"stateVersion")?,
        "change":{"action":"publish","policies":[{"policy_id":policy_id,"version":2}]}}),
    )
    .await?;
    verified(&post(&second, &format!("{BASE}/operations"), apply_input(&current_preview, Id::new())?).await?);
    assert_ne!(
        f.engine.content().await,
        original_content,
        "the second signed policy must really replace cloud content before rollback"
    );
    let observation = post(&second, &format!("{BASE}/observe"), observe_input()).await?;
    let state = read(&second, BASE).await?;
    let rollback = post(
        &second,
        &format!("{BASE}/previews"),
        json!({"request_id":Id::new(),"configuration_version":1,
        "observation_id":id(&observation,"id")?,"expected_state_version":number(&state,"stateVersion")?,
        "change":{"action":"rollback","publication_id":original}}),
    )
    .await?;
    let registry_id = agf_api::model_routes::tenant_record_id(second.tenant);
    let registry = db::row(&second, "signed-policy-registry", registry_id).await?;
    let request = Id::new();
    let result = post(&second, &format!("{BASE}/operations"), apply_input(&rollback, request)?).await?;
    verified(&result);
    assert_eq!(result["action"], "rollback");
    assert_eq!(result["sourcePublicationId"], json!(original));
    assert_ne!(request, original);
    assert_eq!(f.engine.content().await, original_content);
    assert_eq!(f.engine.counts().await, (9, 3));
    assert_eq!(db::row(&second, "signed-policy-registry", registry_id).await?, registry);
    assert_eq!(second.get(&format!("/api/v1/policies/{policy_id}")).await.json()["policy"]["version"], 2);
    assert_eq!(audits(&second, request, "mse-config-publication").await?.len(), 1);
    db::chain(&second).await?;
    case.pool.close().await;
    Ok(())
}
