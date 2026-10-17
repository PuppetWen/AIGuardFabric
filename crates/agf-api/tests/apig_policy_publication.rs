//! Native APIG HTTP workflow against an explicit owned persistent Mock; no cloud or process-global overrides.
mod apig_policy_publication_support;
mod common;

use agf_core::{audit::AuditAction, error::DomainResult, ids::Id};
use apig_policy_publication_support::*;
use common::*;

#[tokio::test]
async fn metadata_get_neither_initializes_business_records_nor_seeds_a_provider() -> DomainResult<()> {
    let h = setup().await;
    let before = snapshot(&h).await?;
    let initial = read(&h, BASE).await?;
    assert_eq!(initial["configured"], false);
    assert!(initial["binding"].is_null());
    assert!(initial["observation"].is_null());
    assert_eq!(initial["stateVersion"], 0);
    assert_eq!(snapshot(&h).await?, before);
    let f = Fixture::with_harness(h).await?;
    let before = snapshot(&f.h).await?;
    for _ in 0..2 {
        let state = f.state().await?;
        assert_eq!(state["configured"], true);
        assert_eq!(state["enabled"], true);
        assert_eq!(state["binding"]["binding"]["policyId"], "policy-agf-demo");
        assert_eq!(state["stateVersion"], 0);
        assert!(state["observation"].is_null());
        assert_eq!(state["operations"], json!([]));
        assert_eq!(state["consumerApplied"], Value::Null);
        assert_private(&state);
        assert_eq!(snapshot(&f.h).await?, before);
    }
    assert!(configurations(&f.h).await?["apig-policy-driver-mock"].is_empty());
    assert!(configurations(&f.h).await?["apig-policy-publication-state"].is_empty());
    Ok(())
}

#[tokio::test]
async fn an_uninitialized_observation_fails_without_fixture_fallback_or_repeating_its_uuid() -> DomainResult<()> {
    let f = Fixture::new().await?;
    let request = Id::new();
    let input = observe_input(request, 1, false);
    let path = format!("{BASE}/observe");
    assert_eq!(f.h.post(&path, input.clone()).await.status, StatusCode::PRECONDITION_FAILED);
    assert!(configurations(&f.h).await?["apig-policy-driver-mock"].is_empty());
    assert!(configurations(&f.h).await?["apig-policy-publication-detail"].is_empty());
    let claimed = snapshot(&f.h).await?;
    assert_eq!(f.h.post(&path, input).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&f.h).await?, claimed);
    assert!(f.state().await?["observation"].is_null());
    let failed =
        f.h.state
            .store
            .audit_chain_durable(f.h.tenant, 0, i64::MAX)
            .await?
            .into_iter()
            .filter(|entry| {
                entry.target.kind == "apig-policy-observation"
                    && entry.target.id.as_deref() == Some(request.to_string().as_str())
                    && entry.outcome == agf_core::audit::AuditOutcome::Failure
            })
            .count();
    assert_eq!(failed, 1);
    Ok(())
}

#[tokio::test]
async fn explicit_observation_and_signed_preview_do_not_write_then_one_put_has_independent_readback() -> DomainResult<()>
{
    let f = Fixture::new().await?;
    let registry = configurations(&f.h).await?["signed-policy-registry"].clone();
    let observed = f.observe(true).await?;
    assert_eq!(observed["usable"], true);
    assert_eq!(observed["target"]["mocked"], true);
    assert_eq!(text(&observed, "fingerprint")?.len(), 64);
    assert_eq!(text(&observed, "configHash")?.len(), 64);
    assert_private(&observed);
    let baseline = provider(&f.h).await?;
    for action in ["GetHttpApi", "GetPolicy", "GetPolicyAttachment"] {
        assert_eq!(baseline.calls(action), 1);
    }
    assert_eq!(baseline.calls("UpdatePolicy"), 0);
    let preview = f.prepare(&observed).await?;
    assert_eq!(preview["previewUsable"], true);
    assert_eq!(preview["managedLimit"], "TokenPerMinute");
    assert_eq!(preview["previousLimit"], 1000);
    assert_eq!(preview["desiredLimit"], 1250);
    assert_eq!(preview["casSemantics"], "none");
    assert_eq!(preview["noCloudCas"], true);
    assert!(preview["sharedPolicyImpact"].is_null());
    assert_private(&preview);
    assert_package(&f.h, &preview, &f.policy).await?;
    assert_eq!(provider(&f.h).await?.row, baseline.row, "preview must not perform provider calls");
    let request = Id::new();
    let result = f.apply(&preview, request).await?;
    assert_verified(&result);
    let after = provider(&f.h).await?;
    assert_eq!(after.calls("UpdatePolicy"), 1);
    for action in ["GetHttpApi", "GetPolicy", "GetPolicyAttachment"] {
        assert_eq!(after.calls(action), 3);
    }
    let mut desired = baseline.config()?;
    desired["globalRules"][0]["limitValue"] = json!(1250);
    assert_eq!(after.config()?, desired, "all nonmanaged rules and unknown fields must survive");
    assert_eq!(after.response("GetPolicyAttachment")?, baseline.response("GetPolicyAttachment")?);
    for field in ["name", "description", "policyId", "classId", "className"] {
        assert_eq!(after.response("GetPolicy")?["data"][field], baseline.response("GetPolicy")?["data"][field]);
    }
    assert_eq!(configurations(&f.h).await?["signed-policy-registry"], registry);
    assert_eq!(workflow_audits(&f.h, request, AuditAction::Configure).await?.len(), 1);
    assert_eq!(workflow_audits(&f.h, request, AuditAction::Execute).await?.len(), 1);
    let before = snapshot(&f.h).await?;
    assert_eq!(read(&f.h, &receipt_path(request)).await?, result);
    assert_eq!(f.state().await?["history"].as_array().map(Vec::len), Some(1));
    assert_eq!(snapshot(&f.h).await?, before);
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn original_uuid_and_local_recovery_are_pure_while_consumed_previews_and_raw_writes_cannot_dispatch()
-> DomainResult<()> {
    let f = Fixture::new().await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let input = apply_input(&preview, request)?;
    let result = post(&f.h, &format!("{BASE}/operations"), input.clone()).await?;
    assert_verified(&result);
    let before = snapshot(&f.h).await?;
    assert_eq!(post(&f.h, &format!("{BASE}/operations"), input.clone()).await?, result);
    assert_eq!(post(&f.h, &format!("{}/recover", receipt_path(request)), json!({})).await?, result);
    assert_eq!(snapshot(&f.h).await?, before);
    let mut changed = input;
    changed["confirm_live"] = json!(true);
    assert_eq!(f.h.post(&format!("{BASE}/operations"), changed).await.status, StatusCode::CONFLICT);
    assert_eq!(
        f.h.post(&format!("{BASE}/operations"), apply_input(&preview, Id::new())?).await.status,
        StatusCode::CONFLICT
    );
    let raw =
        f.h.post(
            &format!("{CONFIG}/operations"),
            json!({"request_id":Id::new(),"configuration_version":1,
        "action":"UpdatePolicy","parameters":{"policyId":"policy-agf-demo","body":{"name":"owned","config":"{}"}}}),
        )
        .await;
    assert_eq!(raw.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 1);
    assert_eq!(workflow_audits(&f.h, request, AuditAction::Execute).await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn two_current_actors_can_consume_a_preview_only_once() -> DomainResult<()> {
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
        f.h.request("POST", &path, Some(&second), Some(input_b))
    );
    assert!(matches!(
        (ra.status, rb.status),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    let (winner, loser) = if ra.status == StatusCode::OK { (a, b) } else { (b, a) };
    assert_verified(&read(&f.h, &receipt_path(winner)).await?);
    assert_eq!(f.h.get(&receipt_path(loser)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 1);
    for action in ["GetHttpApi", "GetPolicy", "GetPolicyAttachment"] {
        assert_eq!(provider(&f.h).await?.calls(action), 3);
    }
    assert_eq!(workflow_audits(&f.h, winner, AuditAction::Configure).await?.len(), 1);
    assert_eq!(workflow_audits(&f.h, winner, AuditAction::Execute).await?.len(), 1);
    assert!(workflow_audits(&f.h, loser, AuditAction::Configure).await?.is_empty());
    assert!(workflow_audits(&f.h, loser, AuditAction::Execute).await?.is_empty());
    Ok(())
}
