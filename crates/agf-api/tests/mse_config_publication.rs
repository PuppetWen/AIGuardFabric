//! Future native workflow acceptance: actual HTTP configuration, signed policies and persisted Mock.
//! No public workflow registration exists yet; execution is intentionally deferred to root.
mod common;
mod mse_config_publication_support;

use agf_core::{audit::AuditAction, error::DomainResult, ids::Id};
use common::*;
use mse_config_publication_support::*;

#[tokio::test]
async fn initial_and_configured_gets_never_initialize_workflow_or_mock_records() -> DomainResult<()> {
    let h = setup().await;
    let original = snapshot(&h).await?;
    for _ in 0..2 {
        let state = read(&h, BASE).await?;
        assert_eq!(state["configured"], false);
        assert_eq!(state["binding"], Value::Null);
        assert_eq!(state["stateVersion"], 0);
        assert_eq!(state["consumerApplied"], Value::Null);
        assert_private(&state);
    }
    let missing = h.get(&receipt_path(Id::new())).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(snapshot(&h).await?, original);
    configure(&h, 0, true, true, settings()).await?;
    let configured = snapshot(&h).await?;
    let state = read(&h, BASE).await?;
    assert_eq!(state["configured"], true);
    assert_eq!(state["binding"]["configurationVersion"], 1);
    assert_eq!(state["binding"]["namespaceId"], "");
    assert_eq!(state["binding"]["transportMode"], "mock");
    assert_eq!(state["observation"], Value::Null);
    assert_eq!(snapshot(&h).await?, configured);
    Ok(())
}

#[tokio::test]
async fn actual_api_setup_preview_and_single_publish_produce_vetted_content_and_three_honest_stages() -> DomainResult<()>
{
    let f = Fixture::new().await?;
    let policy_registry = configurations(&f.h).await?["signed-policy-registry"].clone();
    let observed = f.observe().await?;
    assert_eq!(observed["target"]["configurationVersion"], 1);
    assert_eq!(observed["target"]["mocked"], true);
    assert_eq!(observed["contentEmpty"], false);
    assert_private(&observed);
    let baseline = provider(&f.h).await?;
    assert_eq!(baseline.revision, 1);
    assert_eq!(baseline.plaintext, "{}");
    let preview = f.prepare(&observed).await?;
    assert_eq!(preview["previewUsable"], true);
    assert_eq!(preview["casSemantics"], "content-md5-upsert");
    assert_eq!(preview["baselineMd5"], agf_alicloud::mse::config_cas::content_md5("{}"));
    assert_private(&preview);
    assert_eq!(provider(&f.h).await?.row, baseline.row, "preview must not change the provider");
    let request = Id::new();
    let operation = f.apply(&preview, request).await?;
    assert_verified(&operation);
    assert_private(&operation);
    let saved = provider(&f.h).await?;
    assert_eq!(saved.revision, 2);
    assert_bundle(&f.h, &saved, &f.policy, &operation)?;
    assert_eq!(workflow_audits(&f.h, request, AuditAction::Configure).await?.len(), 1);
    assert_eq!(workflow_audits(&f.h, request, AuditAction::Execute).await?.len(), 1);
    assert_eq!(configurations(&f.h).await?["signed-policy-registry"], policy_registry);
    let before = snapshot(&f.h).await?;
    let receipt = read(&f.h, &receipt_path(request)).await?;
    assert_verified(&receipt);
    let state = f.state().await?;
    assert_eq!(state["history"].as_array().map(Vec::len), Some(1));
    assert_private(&state);
    assert_eq!(snapshot(&f.h).await?, before);
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn same_uuid_and_finished_recovery_are_read_only_and_changed_input_conflicts() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let input = apply_input(&preview, request)?;
    let first = post(&f.h, &format!("{BASE}/operations"), input.clone()).await?;
    assert_verified(&first);
    let before = snapshot(&f.h).await?;
    assert_verified(&post(&f.h, &format!("{BASE}/operations"), input.clone()).await?);
    assert_verified(&post(&f.h, &format!("{}/recover", receipt_path(request)), json!({})).await?);
    assert_eq!(snapshot(&f.h).await?, before);
    let mut changed = input;
    changed["confirm_live"] = json!(true);
    let response = f.h.post(&format!("{BASE}/operations"), changed).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(provider(&f.h).await?.revision, 2);
    assert_eq!(workflow_audits(&f.h, request, AuditAction::Execute).await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn two_confirming_actors_cannot_claim_the_same_preview_twice() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let preview = f.ready().await?;
    let scopes = ["alicloud:read", "alicloud:write", "policies:read"];
    let first = key(&f.h, &scopes).await?;
    let second = key(&f.h, &scopes).await?;
    let a = Id::new();
    let b = Id::new();
    let path = format!("{BASE}/operations");
    let input_a = apply_input(&preview, a)?;
    let input_b = apply_input(&preview, b)?;
    let (ra, rb) = tokio::join!(
        f.h.request("POST", &path, Some(&first), Some(input_a)),
        f.h.request("POST", &path, Some(&second), Some(input_b)),
    );
    let (winner, loser) = if ra.status == StatusCode::OK { (a, b) } else { (b, a) };
    assert!(matches!(
        (ra.status, rb.status),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    assert_verified(&read(&f.h, &receipt_path(winner)).await?);
    assert_eq!(provider(&f.h).await?.revision, 2);
    assert_eq!(workflow_audits(&f.h, winner, AuditAction::Configure).await?.len(), 1);
    assert_eq!(workflow_audits(&f.h, winner, AuditAction::Execute).await?.len(), 1);
    assert_eq!(workflow_audits(&f.h, loser, AuditAction::Execute).await?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn capabilities_are_checked_individually_and_read_only_keys_cannot_prepare_or_apply() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let preview = f.ready().await?;
    for scopes in [&["policies:read"][..], &["alicloud:read"][..]] {
        let token = key(&f.h, scopes).await?;
        let before = configurations(&f.h).await?;
        assert_eq!(f.h.request("GET", BASE, Some(&token), None).await.status, StatusCode::FORBIDDEN);
        assert_eq!(configurations(&f.h).await?, before);
    }
    let reader = key(&f.h, &["alicloud:read", "policies:read"]).await?;
    assert_eq!(f.h.request("GET", BASE, Some(&reader), None).await.status, StatusCode::OK);
    let before = configurations(&f.h).await?;
    let request = Id::new();
    assert_eq!(
        f.h.request("POST", &format!("{BASE}/operations"), Some(&reader), Some(apply_input(&preview, request)?))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let observed = f.state().await?["observation"].clone();
    let candidate = preview_input(&observed, selection(&f.policy)?, number(&preview, "stateVersion")?)?;
    assert_eq!(
        f.h.request("POST", &format!("{BASE}/previews"), Some(&reader), Some(candidate)).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.h.request("GET", BASE, Some(&f.h.viewer), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(configurations(&f.h).await?, before);
    assert_eq!(provider(&f.h).await?.revision, 1);
    assert_eq!(workflow_audits(&f.h, request, AuditAction::Configure).await?.len(), 0);
    Ok(())
}
