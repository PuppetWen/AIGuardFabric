//! Independent process locks cannot forget an unknown shared-policy write or an archived request fact.
use super::{
    gate::{Mode, Target, with_gate},
    *,
};
use agf_core::{
    audit::AuditOutcome,
    error::DomainResult,
    ids::{Id, deterministic_id},
};

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn lost_error_and_false_put_responses_keep_shared_policy_unknown_across_restart_account_region_mode_and_slot()
-> DomainResult<()> {
    for (label, outcome, changed) in [
        ("apig-unknown-lost", Outcome::Lost, true),
        ("apig-unknown-error", Outcome::Error, false),
        ("apig-unknown-false", Outcome::False, false),
    ] {
        let case = SqlCase::open(label).await?;
        let engine = Engine::start().await?;
        let f = loopback(case.h.clone(), &engine).await?;
        let preview = f.ready().await?;
        let request = Id::new();
        engine.reply(outcome)?;
        let result = f.apply(&preview, request).await?;
        assert_eq!(result["status"], "uncertain");
        assert_eq!(result["cloudWrite"]["status"], "unknown");
        assert_eq!(result["readback"]["status"], "not_attempted");
        assert_eq!(result["completionState"], "complete");
        assert_eq!(result["target"]["mocked"], false);
        assert_eq!(result["consumerApplied"], Value::Null);
        assert_eq!(engine.counts()?, (6, 1));
        assert_eq!(engine.config()?["globalRules"][0]["limitValue"], if changed { 1250 } else { 1000 });
        let old_fact = row(&f.h, FACT, fact_id(f.h.tenant, request)).await?;
        let resource = identifier(&result["target"], "writeResourceId")?;
        let risk_id = deterministic_id("agf.apig.policy-publication.risk", &format!("{}:{resource}", f.h.tenant));
        let risk = row(&f.h, MAIN, risk_id).await?;
        assert_eq!(risk["scope_id"], json!(resource));
        assert_eq!(risk["latest_unknown"], json!(request));
        assert_eq!(risk["unknown_count"], 1);
        let second = route(case.second_instance().await?, engine.address)?;
        let committed = snapshot(&second).await?;
        assert_eq!(read(&second, &receipt_path(request)).await?, result);
        assert_eq!(post(&second, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?, result);
        assert_eq!(post(&second, &format!("{}/recover", receipt_path(request)), json!({})).await?, result);
        assert_eq!(snapshot(&second).await?, committed);
        assert_eq!(engine.counts()?, (6, 1));

        let mut new_settings = settings();
        new_settings["endpoint"] = json!(format!("http://{}", engine.address));
        new_settings["account_id"] = json!("a-different-owned-account");
        new_settings["region_id"] = json!("cn-beijing");
        configure_live(&second, 2, true, new_settings.clone()).await?;
        let mut quota = quota_body(&text(&f.quota, "name")?, 1, 31);
        quota["dimension"] = json!("requests");
        save_quota(&second, quota).await?;
        let state = read(&second, BASE).await?;
        assert_ne!(state["binding"]["targetScopeId"], result["target"]["targetScopeId"]);
        assert_eq!(state["binding"]["writeResourceId"], json!(resource));
        assert_eq!(state["unresolvedOperationId"], json!(request));
        engine.reply(Outcome::Normal)?;
        let observed = post(&second, &format!("{BASE}/observe"), observe_input(Id::new(), 3, false)).await?;
        let current = read(&second, BASE).await?;
        let blocked = preview_input(&observed, selection(&f.policy)?, number(&current, "stateVersion")?)?;
        let before = snapshot(&second).await?;
        assert_eq!(second.post(&format!("{BASE}/previews"), blocked).await.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(snapshot(&second).await?, before);
        assert_eq!(engine.counts()?, (9, 1));
        assert_eq!(row(&second, MAIN, risk_id).await?, risk);

        // Changing to Mock does not turn the old delivered request into a new isolated risk domain.
        configure(&second, 3, true, new_settings).await?;
        let state = read(&second, BASE).await?;
        assert_eq!(state["binding"]["mocked"], true);
        assert_eq!(state["binding"]["writeResourceId"], json!(resource));
        assert_eq!(state["unresolvedOperationId"], json!(request));
        assert_eq!(
            second.post(&format!("{BASE}/observe"), observe_input(Id::new(), 4, false)).await.status,
            StatusCode::PRECONDITION_FAILED
        );
        assert!(second.state.configurations.list::<Value>(second.tenant, "apig-policy-driver-mock").await?.is_empty());
        archive(&second, request).await?;
        assert_eq!(row(&second, MAIN, risk_id).await?, risk);
        assert_eq!(row(&second, FACT, fact_id(second.tenant, request)).await?, old_fact);
        let archived = read(&second, &receipt_path(request)).await?;
        assert_eq!(archived["status"], "archived");
        assert_eq!(archived["originalStatus"], "uncertain");
        assert_eq!(archived["cloudWrite"]["status"], "unknown");
        assert_eq!(archived["consumerApplied"], Value::Null);
        let before = snapshot(&second).await?;
        assert_eq!(post(&second, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?, archived);
        assert_eq!(snapshot(&second).await?, before);
        assert_eq!(engine.counts()?, (9, 1));
        let terminal = audits(&second, request, "apig-policy-publication").await?;
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0].outcome, AuditOutcome::Failure);
        chain(&second).await?;
        case.pool.close().await;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn archive_is_atomic_and_preserves_permanent_fact_and_authenticated_observation_on_a_new_instance()
-> DomainResult<()> {
    let case = SqlCase::open("apig-archive-atomic").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    assert_package(&f.h, &preview, &f.policy).await?;
    let request = Id::new();
    f.apply(&preview, request).await?;
    let fact = row(&f.h, FACT, fact_id(f.h.tenant, request)).await?;
    let observation = identifier(&preview, "observationId")?;
    let observation_body = row(&f.h, DETAIL, content_id(f.h.tenant, observation, "observation")).await?;
    let before = snapshot(&f.h).await?;
    let h = f.h.clone();
    let main = agf_api::integration_store::id(h.tenant, "alicloud-apig");
    with_gate(
        &case.pool,
        h.tenant,
        Target { kind: "apig-policy-publication-archive", id: main, action: "update" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let state = read(&h, BASE).await?;
                assert!(
                    h.post(
                        &format!("{BASE}/operations/archive"),
                        json!({"expected_generation":number(&state,"generation")?,"request_ids":[request]})
                    )
                    .await
                    .status
                    .is_server_error()
                );
                assert_eq!(snapshot(&h).await?, before);
                chain(&h).await
            })
        },
    )
    .await?;
    archive(&f.h, request).await?;
    let second = case.second_instance().await?;
    assert_eq!(row(&second, FACT, fact_id(second.tenant, request)).await?, fact);
    assert_eq!(row(&second, DETAIL, content_id(second.tenant, observation, "observation")).await?, observation_body);
    let detail = row(&second, DETAIL, content_id(second.tenant, request, "operation")).await?;
    assert_eq!(detail["class"], "archived");
    assert!(detail.get("data").is_none());
    let original = read(&second, &receipt_path(request)).await?;
    assert_eq!(original["status"], "archived");
    assert_eq!(original["originalStatus"], "verified");
    let committed = snapshot(&second).await?;
    assert_eq!(post(&second, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?, original);
    assert_eq!(archive(&second, request).await?["unchanged"], true);
    assert_eq!(snapshot(&second).await?, committed);
    assert_eq!(provider(&second).await?.calls("UpdatePolicy"), 1);
    let observed = post(&second, &format!("{BASE}/observe"), observe_input(Id::new(), 1, false)).await?;
    let state = read(&second, BASE).await?;
    let input = preview_input(
        &observed,
        json!({"action":"rollback","publication_id":request}),
        number(&state, "stateVersion")?,
    )?;
    let committed = snapshot(&second).await?;
    assert_eq!(second.post(&format!("{BASE}/previews"), input).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(snapshot(&second).await?, committed);
    chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn trusted_durable_history_restores_only_its_threshold_onto_fresh_external_rules_after_restart()
-> DomainResult<()> {
    let case = SqlCase::open("apig-history-restart").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    let source = Id::new();
    f.apply(&preview, source).await?;
    external_edit(&f.h).await?;
    let cloud = provider(&f.h).await?;
    let external = cloud.config()?;
    let attachment = cloud.response("GetPolicyAttachment")?.clone();
    let registry = configurations(&f.h).await?["signed-policy-registry"].clone();
    let second = case.second_instance().await?;
    let fresh = Fixture { h: second, quota: f.quota.clone(), policy: f.policy.clone() };
    let observed = fresh.observe(false).await?;
    let preview = fresh.prepare_change(&observed, json!({"action":"rollback","publication_id":source})).await?;
    assert_eq!(preview["previousLimit"], 1250);
    assert_eq!(preview["desiredLimit"], 1000);
    let result = fresh.apply(&preview, Id::new()).await?;
    assert_verified(&result);
    let after = provider(&fresh.h).await?;
    let mut expected = external;
    expected["globalRules"][0]["limitValue"] = json!(1000);
    assert_eq!(after.config()?, expected);
    assert_eq!(after.response("GetPolicyAttachment")?, &attachment);
    assert_eq!(after.calls("UpdatePolicy"), 3);
    assert_eq!(configurations(&fresh.h).await?["signed-policy-registry"], registry);
    assert_eq!(fresh.state().await?["history"].as_array().map(Vec::len), Some(2));
    chain(&fresh.h).await?;
    case.pool.close().await;
    Ok(())
}
