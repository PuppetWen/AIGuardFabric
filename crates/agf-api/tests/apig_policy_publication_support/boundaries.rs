use super::*;

#[tokio::test]
async fn every_explicit_confirmation_and_strict_body_is_required_before_claim() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let preview = f.ready().await?;
    let path = format!("{BASE}/operations");
    let before = snapshot(&f.h).await?;
    for field in ["confirm_apply", "confirm_scope_difference", "confirm_shared_policy_impact", "confirm_no_cloud_cas"] {
        let mut missing = apply_input(&preview, Id::new())?;
        missing
            .as_object_mut()
            .ok_or_else(|| DomainError::Internal("invalid owned apply fixture".into()))?
            .remove(field);
        assert_eq!(f.h.post(&path, missing).await.status, StatusCode::BAD_REQUEST, "missing {field}");
        let mut declined = apply_input(&preview, Id::new())?;
        declined[field] = json!(false);
        assert_eq!(f.h.post(&path, declined).await.status, StatusCode::PRECONDITION_FAILED, "declined {field}");
        assert_eq!(snapshot(&f.h).await?, before);
    }
    for (endpoint, mut input) in [
        (format!("{BASE}/observe"), observe_input(Id::new(), 1, false)),
        (path.clone(), apply_input(&preview, Id::new())?),
    ] {
        input["endpoint"] = json!("https://unrequested.invalid");
        assert_eq!(f.h.post(&endpoint, input).await.status, StatusCode::BAD_REQUEST);
        assert_eq!(snapshot(&f.h).await?, before);
    }
    assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 0);
    assert_verified(&f.apply(&preview, Id::new()).await?);
    Ok(())
}

#[tokio::test]
async fn ordinary_policy_defaults_and_nonrepresentable_scopes_are_not_silently_projected() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let observed = f.observe(true).await?;
    let default_policy = create_policy(&f.h, json!({"name":format!("owned-default-{}",Id::new())})).await?;
    let mut policies = vec![default_policy];
    for (field, value) in [
        ("dry_run", json!(true)),
        ("scope_departments", json!(["Finance"])),
        ("intercept_points", json!(["ai-gateway", "mcp-proxy"])),
    ] {
        let mut body = policy_body(&format!("owned-unsupported-{}", Id::new()), identifier(&f.quota, "id")?, 0);
        body[field] = value;
        policies.push(create_policy(&f.h, body).await?);
    }
    for (field, value) in
        [("window", json!("day")), ("soft_threshold", json!(100)), ("dimension", json!("cost")), ("limit", json!(0))]
    {
        let mut body = quota_body(&format!("owned-unsupported-quota-{}", Id::new()), 0, 100);
        body[field] = value;
        let quota = save_quota(&f.h, body).await?;
        policies.push(
            create_policy(
                &f.h,
                policy_body(&format!("owned-unsupported-policy-{}", Id::new()), identifier(&quota, "id")?, 0),
            )
            .await?,
        );
    }
    for policy in policies {
        let before = snapshot(&f.h).await?;
        let state = f.state().await?;
        let entries = state["sources"]["items"]
            .as_array()
            .ok_or_else(|| DomainError::Internal("missing source choices".into()))?;
        let entry = entries
            .iter()
            .find(|row| row["policyId"] == policy["id"])
            .ok_or_else(|| DomainError::Internal("persisted unsupported policy absent from choices".into()))?;
        assert_eq!(entry["eligible"], false);
        assert!(entry["source"].is_null());
        assert!(!text(entry, "reason")?.is_empty());
        let input = preview_input(&observed, selection(&policy)?, number(&state, "stateVersion")?)?;
        assert_eq!(f.h.post(&format!("{BASE}/previews"), input).await.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(snapshot(&f.h).await?, before);
        assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 0);
    }
    Ok(())
}

#[tokio::test]
async fn changing_current_source_quota_or_signed_policy_invalidates_a_prepared_intent_without_dispatch()
-> DomainResult<()> {
    for change in ["source", "quota", "policy"] {
        let f = Fixture::new().await?;
        let preview = f.ready().await?;
        match change {
            "source" => {
                configure(&f.h, 1, true, settings()).await?;
            }
            "quota" => {
                save_quota(&f.h, quota_body(&text(&f.quota, "name")?, 1, 1300)).await?;
            }
            _ => {
                let mut body = policy_body(&text(&f.policy, "name")?, identifier(&f.quota, "id")?, 1);
                body["description"] = json!("a newly reviewed signed revision");
                let response =
                    f.h.request(
                        "PUT",
                        &format!("/api/v1/policies/{}", identifier(&f.policy, "id")?),
                        Some(&f.h.admin),
                        Some(body),
                    )
                    .await;
                assert_eq!(response.status, StatusCode::OK, "policy update: {}", response.text);
                assert_policy(&f.h, &response.json()["policy"])?;
            }
        }
        let before = snapshot(&f.h).await?;
        let request = Id::new();
        let result = f.h.post(&format!("{BASE}/operations"), apply_input(&preview, request)?).await;
        assert_eq!(result.status, StatusCode::CONFLICT, "stale {change} must block: {}", result.text);
        assert_eq!(snapshot(&f.h).await?, before);
        assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 0);
        assert!(workflow_audits(&f.h, request, agf_core::audit::AuditAction::Configure).await?.is_empty());
        assert!(workflow_audits(&f.h, request, agf_core::audit::AuditAction::Execute).await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn capabilities_and_current_tenant_separate_metadata_initialization_and_receipts() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let preview = f.ready().await?;
    let request = Id::new();
    assert_verified(&f.apply(&preview, request).await?);
    for scopes in [&["alicloud:read"][..], &["policies:read"][..], &["alicloud:write", "policies:read"][..]] {
        let token = key(&f.h, scopes).await?;
        let before = snapshot(&f.h).await?;
        assert_eq!(f.h.request("GET", BASE, Some(&token), None).await.status, StatusCode::FORBIDDEN);
        assert_eq!(snapshot(&f.h).await?, before);
    }
    let reader = key(&f.h, &["alicloud:read", "policies:read"]).await?;
    assert_eq!(f.h.request("GET", BASE, Some(&reader), None).await.status, StatusCode::OK);
    assert_eq!(f.h.request("GET", &receipt_path(request), Some(&reader), None).await.status, StatusCode::OK);
    let before = snapshot(&f.h).await?;
    for (path, input) in [
        (format!("{BASE}/observe"), observe_input(Id::new(), 1, true)),
        (
            format!("{BASE}/previews"),
            preview_input(
                &f.state().await?["observation"],
                selection(&f.policy)?,
                number(&f.state().await?, "stateVersion")?,
            )?,
        ),
        (format!("{BASE}/operations"), apply_input(&preview, Id::new())?),
        (format!("{}/recover", receipt_path(request)), json!({})),
        (
            format!("{BASE}/operations/archive"),
            json!({"expected_generation":number(&f.state().await?,"generation")?,"request_ids":[request]}),
        ),
    ] {
        assert_eq!(f.h.request("POST", &path, Some(&reader), Some(input)).await.status, StatusCode::FORBIDDEN);
        assert_eq!(snapshot(&f.h).await?, before);
    }
    assert_eq!(f.h.request("GET", BASE, Some(&f.h.viewer), None).await.status, StatusCode::FORBIDDEN);
    let foreign = for_tenant(f.h.clone(), f.h.other_tenant)?;
    let foreign_before = snapshot(&foreign).await?;
    assert_eq!(read(&foreign, BASE).await?["configured"], false);
    assert_eq!(foreign.get(&receipt_path(request)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        foreign.post(&format!("{BASE}/operations"), apply_input(&preview, request)?).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&foreign).await?, foreign_before);
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 1);
    Ok(())
}
