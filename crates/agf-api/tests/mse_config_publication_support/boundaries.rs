//! Requests cannot supply content, targets, alternate scopes or bypass current revision fences.
use super::*;
use agf_core::audit::AuditAction;

#[tokio::test]
async fn strict_inputs_and_missing_confirmations_leave_the_preview_and_provider_intact() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let observed = f.observe().await?;
    let state = f.state().await?;
    let candidate = preview_input(&observed, selection(&f.policy)?, number(&state, "stateVersion")?)?;
    let before = snapshot(&f.h).await?;
    let mut raw = candidate.clone();
    raw["content"] = json!("untrusted business body");
    let mut target = candidate.clone();
    target["engine_origin"] = json!("http://127.0.0.1:1");
    let mut optional_null = candidate.clone();
    optional_null["acknowledge_unknown_operation_id"] = Value::Null;
    let mut duplicate = candidate.clone();
    duplicate["change"]["policies"] = json!([candidate["change"]["policies"][0], candidate["change"]["policies"][0]]);
    for invalid in [raw, target, optional_null, duplicate, json!([])] {
        assert_eq!(f.h.post(&format!("{BASE}/previews"), invalid).await.status, StatusCode::BAD_REQUEST);
        assert_eq!(snapshot(&f.h).await?, before);
    }
    for invalid in [observe_input(Id::nil(), 1), observe_input(Id::new(), 0)] {
        assert_eq!(f.h.post(&format!("{BASE}/observe"), invalid).await.status, StatusCode::BAD_REQUEST);
        assert_eq!(snapshot(&f.h).await?, before);
    }
    let preview = post(&f.h, &format!("{BASE}/previews"), candidate).await?;
    let original = snapshot(&f.h).await?;
    for confirmation in ["confirm_apply", "confirm_upsert"] {
        let mut invalid = apply_input(&preview, Id::new())?;
        invalid[confirmation] = json!(false);
        assert_eq!(f.h.post(&format!("{BASE}/operations"), invalid).await.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(snapshot(&f.h).await?, original);
    }
    assert_eq!(provider(&f.h).await?.revision, 1);
    assert_verified(&f.apply(&preview, Id::new()).await?);
    Ok(())
}

#[tokio::test]
async fn policy_and_cloud_revisions_invalidate_previews_before_any_provider_write() -> DomainResult<()> {
    let mut f = Fixture::new().await?;
    let preview = f.ready().await?;
    f.policy = update_policy(&f, "deny").await?;
    let before = snapshot(&f.h).await?;
    let request = Id::new();
    assert_eq!(
        f.h.post(&format!("{BASE}/operations"), apply_input(&preview, request)?).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(workflow_audits(&f.h, request, AuditAction::Configure).await?.len(), 0);
    let current = f.ready().await?;
    configure(&f.h, 1, true, true, settings()).await?;
    let after_save = snapshot(&f.h).await?;
    assert_eq!(
        f.h.post(&format!("{BASE}/operations"), apply_input(&current, Id::new())?).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&f.h).await?, after_save);
    assert_eq!(provider(&f.h).await?.revision, 1);
    assert_verified(&f.apply(&f.ready().await?, Id::new()).await?);
    assert_eq!(provider(&f.h).await?.revision, 2);
    Ok(())
}

#[tokio::test]
async fn tenant_receipts_previews_content_and_rollback_sources_remain_isolated() -> DomainResult<()> {
    let a = Fixture::new().await?;
    let preview = a.ready().await?;
    let request = Id::new();
    a.apply(&preview, request).await?;
    let a_original = snapshot(&a.h).await?;
    let b = Fixture::with_harness(for_tenant(a.h.clone(), a.h.other_tenant)?).await?;
    assert_eq!(b.h.get(&receipt_path(request)).await.status, StatusCode::NOT_FOUND);
    let b_preview = b.ready().await?;
    assert_ne!(b_preview["target"]["targetScopeId"], preview["target"]["targetScopeId"]);
    let before = snapshot(&b.h).await?;
    assert_eq!(
        b.h.post(&format!("{BASE}/operations"), apply_input(&preview, Id::new())?).await.status,
        StatusCode::CONFLICT
    );
    let observed = b.state().await?["observation"].clone();
    let invalid = preview_input(
        &observed,
        json!({"action":"rollback","publication_id":request}),
        number(&b_preview, "stateVersion")?,
    )?;
    assert_eq!(b.h.post(&format!("{BASE}/previews"), invalid).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&b.h).await?, before);
    assert_eq!(provider(&b.h).await?.plaintext, "{}");
    assert_verified(&b.apply(&b_preview, request).await?);
    assert_eq!(snapshot(&a.h).await?, a_original);
    assert_eq!(provider(&a.h).await?.revision, 2);
    assert_eq!(provider(&b.h).await?.revision, 2);
    Ok(())
}

#[tokio::test]
async fn global_request_facts_prevent_reusing_observation_or_preview_ids_for_other_actions() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let request = Id::new();
    let observed = post(&f.h, &format!("{BASE}/observe"), observe_input(request, 1)).await?;
    let before = snapshot(&f.h).await?;
    let repeated = post(&f.h, &format!("{BASE}/observe"), observe_input(request, 1)).await?;
    assert_eq!(repeated, observed);
    assert_eq!(snapshot(&f.h).await?, before);
    let mut candidate = preview_input(&observed, selection(&f.policy)?, number(&f.state().await?, "stateVersion")?)?;
    candidate["request_id"] = json!(request);
    assert_eq!(f.h.post(&format!("{BASE}/previews"), candidate).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&f.h).await?, before);
    let preview = f.prepare(&observed).await?;
    let original = snapshot(&f.h).await?;
    for used in [request, identifier(&preview, "id")?] {
        assert_eq!(
            f.h.post(&format!("{BASE}/operations"), apply_input(&preview, used)?).await.status,
            StatusCode::CONFLICT
        );
        assert_eq!(snapshot(&f.h).await?, original);
    }
    assert_eq!(provider(&f.h).await?.revision, 1);
    assert_verified(&f.apply(&preview, Id::new()).await?);
    Ok(())
}
