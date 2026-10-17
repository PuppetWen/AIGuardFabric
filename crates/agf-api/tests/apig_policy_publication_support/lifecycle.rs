use super::*;
use agf_core::{audit::AuditAction, credential::SecretMaterial};
use agf_storage::crypto::FieldCipher;
use records::{content_id, fact_id};

#[tokio::test]
async fn rollback_restores_only_the_historic_threshold_onto_new_current_provider_rules() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let preview = f.ready().await?;
    let first = Id::new();
    assert_verified(&f.apply(&preview, first).await?);
    let registry = configurations(&f.h).await?["signed-policy-registry"].clone();
    let external = external_edit(&f.h).await?;
    assert_eq!(external["globalRules"][0]["limitValue"], 1250);
    assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 2);
    let observed = f.observe(false).await?;
    let before = provider(&f.h).await?;
    let rollback = f.prepare_change(&observed, json!({"action":"rollback","publication_id":first})).await?;
    assert_eq!(rollback["action"], "rollback");
    assert_eq!(rollback["sourcePublicationId"], json!(first));
    assert_eq!(rollback["previousLimit"], 1250);
    assert_eq!(rollback["desiredLimit"], 1000);
    assert_eq!(provider(&f.h).await?.row, before.row);
    let request = Id::new();
    assert_verified(&f.apply(&rollback, request).await?);
    let after = provider(&f.h).await?;
    let mut expected = external;
    expected["globalRules"][0]["limitValue"] = json!(1000);
    assert_eq!(after.config()?, expected);
    assert_eq!(after.response("GetPolicy")?["data"]["description"], "a later external description");
    assert_eq!(after.response("GetPolicyAttachment")?, before.response("GetPolicyAttachment")?);
    assert_eq!(after.calls("UpdatePolicy"), 3);
    assert_eq!(configurations(&f.h).await?["signed-policy-registry"], registry);
    assert_eq!(workflow_audits(&f.h, request, AuditAction::Execute).await?.len(), 1);
    let state = f.state().await?;
    assert_eq!(state["history"].as_array().map(Vec::len), Some(2));
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn archive_removes_only_content_and_keeps_permanent_claims_and_observation_aad() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let preview = f.ready().await?;
    assert_package(&f.h, &preview, &f.policy).await?;
    let request = Id::new();
    let input = apply_input(&preview, request)?;
    assert_verified(&f.apply(&preview, request).await?);
    let fact =
        f.h.state
            .configurations
            .get::<Value>(f.h.tenant, "apig-policy-publication-fact", fact_id(f.h.tenant, request))
            .await?
            .ok_or_else(|| DomainError::Internal("missing original operation fact".into()))?;
    let observation_id = identifier(&preview, "observationId")?;
    let observation =
        f.h.state
            .configurations
            .get::<Value>(
                f.h.tenant,
                "apig-policy-publication-detail",
                content_id(f.h.tenant, observation_id, "observation"),
            )
            .await?
            .ok_or_else(|| DomainError::Internal("missing authenticated observation".into()))?;
    let encrypted: SecretMaterial = serde_json::from_value(observation["content"].clone())?;
    let aad = format!(
        "{}|kind:apig-policy-publication:v1",
        FieldCipher::make_aad(&f.h.tenant, &content_id(f.h.tenant, observation_id, "observation"))
    );
    assert_eq!(encrypted.aad.as_deref(), Some(aad.as_str()));
    agf_api::model_gateway::cipher(&f.h.state)?.decrypt(&encrypted)?;
    let state = f.state().await?;
    let archive = post(
        &f.h,
        &format!("{BASE}/operations/archive"),
        json!({"expected_generation":number(&state,"generation")?,"request_ids":[request]}),
    )
    .await?;
    assert_eq!(archive["archivedCount"], 1);
    let archived = read(&f.h, &receipt_path(request)).await?;
    assert_eq!(archived["status"], "archived");
    assert_eq!(archived["originalStatus"], "verified");
    assert_eq!(archived["completionState"], "complete");
    assert_eq!(
        f.h.state
            .configurations
            .get::<Value>(f.h.tenant, "apig-policy-publication-fact", fact_id(f.h.tenant, request))
            .await?,
        Some(fact)
    );
    assert_eq!(
        f.h.state
            .configurations
            .get::<Value>(
                f.h.tenant,
                "apig-policy-publication-detail",
                content_id(f.h.tenant, observation_id, "observation")
            )
            .await?,
        Some(observation)
    );
    let marker: Value =
        f.h.state
            .configurations
            .get(f.h.tenant, "apig-policy-publication-detail", content_id(f.h.tenant, request, "operation"))
            .await?
            .ok_or_else(|| DomainError::Internal("missing lightweight archive marker".into()))?;
    assert_eq!(marker["class"], "archived");
    assert_eq!(marker["marker"]["tenant"], json!(f.h.tenant));
    assert_eq!(marker["marker"]["request_id"], json!(request));
    assert!(!marker.to_string().contains("ciphertext_b64"));
    let before = snapshot(&f.h).await?;
    assert_eq!(post(&f.h, &format!("{BASE}/operations"), input).await?, archived);
    let repeated = post(
        &f.h,
        &format!("{BASE}/operations/archive"),
        json!({"expected_generation":number(&archive,"generation")?,"request_ids":[request]}),
    )
    .await?;
    assert_eq!(repeated["unchanged"], true);
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(
        f.h.post(
            &format!("{BASE}/operations/archive"),
            json!({"expected_generation":number(&state,"generation")?,"request_ids":[request]})
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    let current = f.state().await?;
    let attempted = preview_input(
        &current["observation"],
        json!({"action":"rollback","publication_id":request}),
        number(&current, "stateVersion")?,
    )?;
    assert_eq!(f.h.post(&format!("{BASE}/previews"), attempted).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 1);
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn rotating_source_identity_or_selecting_foreign_mock_ids_cannot_reuse_or_invent_provider_data()
-> DomainResult<()> {
    let f = Fixture::new().await?;
    let preview = f.ready().await?;
    let baseline = provider(&f.h).await?.row;
    let old_binding = f.state().await?["binding"].clone();
    let mut changed = settings();
    changed["account_id"] = json!("a separately configured owned source");
    configure(&f.h, 1, true, changed.clone()).await?;
    let state = f.state().await?;
    assert_ne!(state["binding"]["targetScopeId"], old_binding["targetScopeId"]);
    assert_eq!(
        state["binding"]["writeResourceId"], old_binding["writeResourceId"],
        "rotating accounts must not erase shared-policy Unknown risk"
    );
    assert_eq!(state["observation"]["usable"], false);
    let before = snapshot(&f.h).await?;
    assert_eq!(
        f.h.post(&format!("{BASE}/operations"), apply_input(&preview, Id::new())?).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(
        f.h.post(&format!("{BASE}/observe"), observe_input(Id::new(), 2, false)).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(provider(&f.h).await?.row, baseline);
    changed["policy_http_api_id"] = json!("a-foreign-api");
    configure(&f.h, 2, true, changed).await?;
    assert_eq!(
        f.h.post(&format!("{BASE}/observe"), observe_input(Id::new(), 3, true)).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(provider(&f.h).await?.row, baseline);
    assert_eq!(configurations(&f.h).await?["apig-policy-driver-mock"].len(), 1);
    assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 0);
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await?.passed);
    Ok(())
}
