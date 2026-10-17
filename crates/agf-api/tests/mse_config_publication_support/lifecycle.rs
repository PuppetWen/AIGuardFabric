//! Explicit source changes, archive and trusted rollback never imply a consumer reload.
use super::*;
use agf_core::audit::AuditAction;

#[tokio::test]
async fn source_identity_and_effective_mode_changes_preserve_original_receipts_without_moving_content()
-> DomainResult<()> {
    let f = Fixture::new().await?;
    let first_preview = f.ready().await?;
    let request = Id::new();
    let original = f.apply(&first_preview, request).await?;
    let old_scope = identifier(&original["target"], "targetScopeId")?;
    let old_provider = provider(&f.h).await?;
    let mut source = settings();
    source["account_id"] = json!("a-different-owned-mse-account");
    configure(&f.h, 1, true, true, source.clone()).await?;
    let after_save = snapshot(&f.h).await?;
    let state = f.state().await?;
    let new_scope = identifier(&state["binding"], "targetScopeId")?;
    assert_ne!(new_scope, old_scope);
    assert_eq!(state["history"], json!([]));
    let receipt = read(&f.h, &receipt_path(request)).await?;
    assert_eq!(receipt["target"], original["target"]);
    assert_eq!(receipt["sourceCurrent"], false);
    assert_eq!(snapshot(&f.h).await?, after_save);
    let observed = f.observe().await?;
    assert_eq!(observed["contentHash"], hash_text("{}"));
    assert_eq!(provider_at(&f.h, new_scope).await?.plaintext, "{}");
    assert_eq!(provider_at(&f.h, old_scope).await?.row, old_provider.row);
    let candidate = preview_input(
        &observed,
        json!({"action":"rollback","publication_id":request}),
        number(&f.state().await?, "stateVersion")?,
    )?;
    let before = snapshot(&f.h).await?;
    assert_eq!(f.h.post(&format!("{BASE}/previews"), candidate).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(snapshot(&f.h).await?, before);
    configure(&f.h, 2, true, false, source).await?;
    let live = effective_live(f.h.clone())?;
    let before_mode_get = snapshot(&live).await?;
    let state = read(&live, BASE).await?;
    assert_eq!(state["binding"]["transportMode"], "live");
    assert_eq!(state["binding"]["mocked"], false);
    assert_ne!(state["binding"]["targetScopeId"], json!(new_scope));
    assert_eq!(state["history"], json!([]));
    let receipt = read(&live, &receipt_path(request)).await?;
    assert_eq!(receipt["target"], original["target"]);
    assert_eq!(receipt["sourceCurrent"], false);
    assert_eq!(snapshot(&live).await?, before_mode_get, "mode checks must never contact the configured origin");
    assert_eq!(provider_at(&live, old_scope).await?.row, old_provider.row);
    Ok(())
}

#[tokio::test]
async fn reviewed_archive_releases_only_content_and_keeps_uuid_tombstones_when_configuration_is_disabled()
-> DomainResult<()> {
    let f = Fixture::new().await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let original_input = apply_input(&preview, request)?;
    f.apply(&preview, request).await?;
    let saved = provider(&f.h).await?;
    configure(&f.h, 1, false, true, settings()).await?;
    let state = f.state().await?;
    let generation = number(&state, "generation")?;
    let old_content_bytes = number(&state, "storedContentBytes")?;
    let facts = configurations(&f.h).await?["mse-config-publication-fact"].len();
    let archived = post(
        &f.h,
        &format!("{BASE}/operations/archive"),
        json!({"expected_generation":generation,"request_ids":[request]}),
    )
    .await?;
    assert_eq!(archived["archivedCount"], 1);
    assert_eq!(archived["archivedRequestIds"], json!([request]));
    assert_eq!(archived["unchanged"], false);
    let state = f.state().await?;
    assert_eq!(state["archivedCount"], 1);
    assert!(number(&state, "storedContentBytes")? < old_content_bytes);
    assert_eq!(configurations(&f.h).await?["mse-config-publication-fact"].len(), facts);
    let receipt = read(&f.h, &receipt_path(request)).await?;
    assert_eq!(receipt["status"], "archived");
    assert_eq!(receipt["originalStatus"], "verified");
    assert_eq!(receipt["archived"], true);
    assert_private(&receipt);
    let before = snapshot(&f.h).await?;
    let noop = post(
        &f.h,
        &format!("{BASE}/operations/archive"),
        json!({"expected_generation":number(&state,"generation")?,"request_ids":[request]}),
    )
    .await?;
    assert_eq!(noop["unchanged"], true);
    assert_eq!(post(&f.h, &format!("{BASE}/operations"), original_input.clone()).await?["status"], "archived");
    assert_eq!(snapshot(&f.h).await?, before);
    let mut changed = original_input;
    changed["preview_id"] = json!(Id::new());
    assert_eq!(f.h.post(&format!("{BASE}/operations"), changed).await.status, StatusCode::CONFLICT);
    assert_eq!(
        f.h.post(
            &format!("{BASE}/operations/archive"),
            json!({"expected_generation":generation,"request_ids":[request]})
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(provider(&f.h).await?.row, saved.row);
    assert_eq!(workflow_audits(&f.h, request, AuditAction::Execute).await?.len(), 1);
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn rollback_copies_trusted_history_into_a_new_operation_without_downgrading_platform_policies() -> DomainResult<()>
{
    let mut f = Fixture::new().await?;
    let first_policy = f.policy.clone();
    let first = Id::new();
    let first_preview = f.ready().await?;
    f.apply(&first_preview, first).await?;
    let first_content = provider(&f.h).await?;
    f.policy = update_policy(&f, "deny").await?;
    assert_eq!(f.policy["version"], 2);
    let second = Id::new();
    let second_preview = f.ready().await?;
    f.apply(&second_preview, second).await?;
    assert_ne!(provider(&f.h).await?.plaintext, first_content.plaintext);
    let registry = configurations(&f.h).await?["signed-policy-registry"].clone();
    let observed = f.observe().await?;
    let preview = f
        .prepare_change(
            &observed,
            json!({"action":"rollback","publication_id":first}),
            number(&f.state().await?, "stateVersion")?,
        )
        .await?;
    assert_eq!(preview["action"], "rollback");
    assert_eq!(preview["sourcePublicationId"], json!(first));
    assert_eq!(preview["sourcePolicyVersions"], json!([{"policyId":identifier(&first_policy,"id")?,"version":1}]));
    assert_eq!(preview["currentPolicyVersions"], json!([{"policyId":identifier(&f.policy,"id")?,"version":2}]));
    let rollback = Id::new();
    let receipt = f.apply(&preview, rollback).await?;
    assert_verified(&receipt);
    assert_eq!(receipt["sourcePublicationId"], json!(first));
    assert_eq!(receipt["consumerApplied"], Value::Null);
    let saved = provider(&f.h).await?;
    assert_eq!(saved.revision, 4);
    assert_eq!(saved.plaintext, first_content.plaintext, "rollback must copy exact authenticated history bytes");
    assert_bundle(&f.h, &saved, &first_policy, &receipt)?;
    assert_eq!(configurations(&f.h).await?["signed-policy-registry"], registry);
    let current = read(&f.h, &format!("/api/v1/policies/{}", identifier(&f.policy, "id")?)).await?;
    assert_eq!(current["policy"], f.policy);
    assert_policy(&f.h, &current["policy"])?;
    assert_eq!(workflow_audits(&f.h, rollback, AuditAction::Execute).await?.len(), 1);
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await?.passed);
    Ok(())
}

fn hash_text(value: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(value.as_bytes()))
}
