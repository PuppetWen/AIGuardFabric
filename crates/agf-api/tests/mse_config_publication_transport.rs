//! Workflow acceptance through a real owned literal-127 HTTP engine; never a live provider.
mod common;
#[path = "mse_config_publication_support/observation_race.rs"]
mod observation_race;
#[path = "mse_config_publication_support/transport.rs"]
mod transport;
use agf_core::{audit::AuditOutcome, error::DomainResult, ids::Id};
use common::*;
use transport::*;

async fn fixture() -> DomainResult<Fixture> {
    Fixture::attach(setup().await).await
}

#[tokio::test]
async fn explicit_loopback_without_live_confirmation_publishes_once_and_gets_are_pure() -> DomainResult<()> {
    let f = fixture().await?;
    let original = snapshot(&f.h).await?;
    read(&f.h, BASE).await?;
    assert_eq!(snapshot(&f.h).await?, original);
    assert_eq!(f.engine.counts().await, (0, 0));
    let preview = f.ready().await?;
    let request = Id::new();
    let input = apply_input(&preview, request)?;
    let result = f.apply(&preview, request).await?;
    verified(&result);
    assert_eq!(f.engine.counts().await, (3, 1));
    let seen = f.engine.seen().await;
    assert!(seen.iter().all(|r| r.authenticated));
    let writes: Vec<_> = seen.iter().filter(|r| r.method == "POST").collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].cas.as_deref(), Some(agf_alicloud::mse::config_cas::content_md5(INITIAL).as_str()));
    assert_eq!(writes[0].fields["namespaceId"], "");
    assert_eq!(writes[0].fields["content"], f.engine.content().await);
    assert!(serde_json::from_str::<Value>(&writes[0].fields["content"]).is_ok());
    let committed = snapshot(&f.h).await?;
    assert_eq!(read(&f.h, &receipt(request)).await?, result);
    assert_eq!(post(&f.h, &format!("{BASE}/operations"), input.clone()).await?, result);
    let mut changed = input;
    changed["preview_id"] = json!(Id::new());
    assert_eq!(f.h.post(&format!("{BASE}/operations"), changed).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&f.h).await?, committed);
    assert_eq!(f.engine.counts().await, (3, 1));
    assert_eq!(audits(&f.h, request, "mse-config-publication-claim").await?.len(), 1);
    let terminal = audits(&f.h, request, "mse-config-publication").await?;
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].outcome, AuditOutcome::Success);
    Ok(())
}

#[tokio::test]
async fn missing_or_wrong_server_md5_never_becomes_a_usable_baseline() -> DomainResult<()> {
    for reply in [Reply::MissingMd5, Reply::WrongMd5] {
        let f = fixture().await?;
        f.engine.reply(reply).await;
        let response = f.h.post(&format!("{BASE}/observe"), observe_input()).await;
        assert!(!response.status.is_success(), "untrusted MD5 was accepted");
        assert_eq!(f.engine.counts().await, (1, 0));
        let state = read(&f.h, BASE).await?;
        assert_eq!(state["observation"], Value::Null);
        assert_eq!(state["canPrepare"], false);
        assert!(f.h.state.configurations.list::<Value>(f.h.tenant, DETAIL).await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn exact_provider_cas_conflict_is_terminal_and_not_retried() -> DomainResult<()> {
    let f = fixture().await?;
    let preview = f.ready().await?;
    f.engine.reply(Reply::Conflict).await;
    let request = Id::new();
    let result = f.apply(&preview, request).await?;
    assert_eq!(result["status"], "conflict");
    assert_eq!(result["cloudWrite"]["status"], "conflict");
    assert_eq!(result["readback"]["status"], "not_attempted");
    assert_eq!(result["completionState"], "complete");
    assert_eq!(f.engine.content().await, INITIAL);
    assert_eq!(f.engine.counts().await, (2, 1));
    let committed = snapshot(&f.h).await?;
    assert_eq!(f.apply(&preview, request).await?, result);
    assert_eq!(snapshot(&f.h).await?, committed);
    assert_eq!(f.engine.counts().await, (2, 1));
    assert_eq!(audits(&f.h, request, "mse-config-publication").await?[0].outcome, AuditOutcome::Failure);
    Ok(())
}

#[tokio::test]
async fn lost_accepted_response_stays_unknown_even_when_an_explicit_observation_matches() -> DomainResult<()> {
    let f = fixture().await?;
    let preview = f.ready().await?;
    f.engine.reply(Reply::Lost).await;
    let request = Id::new();
    let result = f.apply(&preview, request).await?;
    assert_eq!(result["status"], "uncertain");
    assert_eq!(result["cloudWrite"]["status"], "unknown");
    assert_ne!(f.engine.content().await, INITIAL);
    assert_eq!(f.engine.counts().await, (2, 1));
    assert_eq!(read(&f.h, BASE).await?["unresolvedOperationId"], json!(request));
    f.engine.reply(Reply::Normal).await;
    let observation = post(&f.h, &format!("{}/observe", receipt(request)), observe_input()).await?;
    assert_eq!(observation["contentHash"], preview["desiredHash"]);
    let unchanged = read(&f.h, &receipt(request)).await?;
    assert_eq!(unchanged["cloudWrite"]["status"], "unknown");
    assert_eq!(unchanged["status"], "uncertain");
    assert_eq!(read(&f.h, BASE).await?["unresolvedOperationId"], json!(request));
    assert_eq!(f.engine.counts().await, (3, 1));
    assert_eq!(f.apply(&preview, request).await?["cloudWrite"]["status"], "unknown");
    assert_eq!(f.engine.counts().await, (3, 1));
    Ok(())
}

#[tokio::test]
async fn accepted_write_and_different_readback_are_distinct_evidence() -> DomainResult<()> {
    let f = fixture().await?;
    let preview = f.ready().await?;
    f.engine.reply(Reply::Different).await;
    let request = Id::new();
    let result = f.apply(&preview, request).await?;
    assert_eq!(result["status"], "uncertain");
    assert_eq!(result["cloudWrite"]["status"], "accepted");
    assert_eq!(result["readback"]["status"], "different");
    assert_eq!(read(&f.h, BASE).await?["unresolvedOperationId"], Value::Null);
    assert_eq!(result["completionState"], "complete");
    assert_eq!(f.engine.counts().await, (3, 1));
    let before = snapshot(&f.h).await?;
    f.apply(&preview, request).await?;
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(f.engine.counts().await, (3, 1));
    Ok(())
}

#[tokio::test]
async fn accepted_write_retains_its_receipt_when_readback_is_unavailable() -> DomainResult<()> {
    let f = fixture().await?;
    let preview = f.ready().await?;
    f.engine.reply(Reply::Unavailable).await;
    let request = Id::new();
    let result = f.apply(&preview, request).await?;
    assert_eq!(result["status"], "uncertain");
    assert_eq!(result["cloudWrite"]["status"], "accepted");
    assert_eq!(result["readback"]["status"], "unavailable");
    assert_eq!(read(&f.h, BASE).await?["unresolvedOperationId"], Value::Null);
    assert_eq!(result["consumerApplied"], Value::Null);
    assert_ne!(f.engine.content().await, INITIAL);
    assert_eq!(f.engine.counts().await, (3, 1));
    Ok(())
}

#[tokio::test]
async fn non_cas_server_errors_and_false_success_are_unknown_without_automatic_readback_or_retry() -> DomainResult<()> {
    for reply in [Reply::Error, Reply::False] {
        let f = fixture().await?;
        let preview = f.ready().await?;
        f.engine.reply(reply).await;
        let request = Id::new();
        let result = f.apply(&preview, request).await?;
        assert_eq!(result["status"], "uncertain");
        assert_eq!(result["cloudWrite"]["status"], "unknown");
        assert_eq!(f.engine.counts().await, (2, 1));
        f.apply(&preview, request).await?;
        read(&f.h, &receipt(request)).await?;
        assert_eq!(f.engine.counts().await, (2, 1));
    }
    Ok(())
}

#[tokio::test]
async fn changing_configuration_or_policy_while_preflight_is_waiting_prevents_the_post() -> DomainResult<()> {
    for change_policy in [false, true] {
        let f = fixture().await?;
        let preview = f.ready().await?;
        let request = Id::new();
        f.engine.hold("GET", 2).await;
        let pending = Pending::start(
            f.h.clone(),
            format!("{BASE}/operations"),
            f.h.admin.clone(),
            apply_input(&preview, request)?,
        );
        f.engine.waiting("GET", 2).await?;
        if change_policy {
            let response =
                f.h.request(
                    "PUT",
                    &format!("/api/v1/policies/{}", id(&f.policy, "id")?),
                    Some(&f.h.admin),
                    Some(json!({
                "expected_version":1,"name":f.policy["name"],"language":"cel","source":"{\"action\":\"deny\"}",
                "action":"deny","enabled":true,"priority":1,"intercept_points":["ai-gateway","mcp-proxy"]})),
                )
                .await;
            assert_eq!(response.status, StatusCode::OK);
        } else {
            configure(&f.h, f.engine.address, 1, false).await?;
        }
        f.engine.release();
        let response = pending.finish().await?;
        assert!(response.status.is_success() || response.status.is_client_error());
        assert_eq!(f.engine.counts().await, (2, 0));
        assert_eq!(f.engine.content().await, INITIAL);
        let result = read(&f.h, &receipt(request)).await?;
        assert_ne!(result["status"], "verified");
        assert_eq!(result["cloudWrite"]["status"], "not_attempted");
    }
    Ok(())
}

#[tokio::test]
async fn parent_cancellation_after_delivery_stages_locally_and_disabled_source_recovery_never_resends()
-> DomainResult<()> {
    let f = fixture().await?;
    let preview = f.ready().await?;
    let request = Id::new();
    f.engine.hold("POST", 1).await;
    let pending =
        Pending::start(f.h.clone(), format!("{BASE}/operations"), f.h.admin.clone(), apply_input(&preview, request)?);
    f.engine.waiting("POST", 1).await?;
    assert_ne!(f.engine.content().await, INITIAL);
    drop(pending);
    wait_pending(&f.h).await?;
    configure(&f.h, f.engine.address, 1, false).await?;
    f.engine.release();
    let before = snapshot(&f.h).await?;
    let result = read(&f.h, &receipt(request)).await?;
    assert_eq!(snapshot(&f.h).await?, before);
    assert_eq!(result["completionState"], "pending_audit");
    let recovered = post(&f.h, &format!("{}/recover", receipt(request)), json!({})).await?;
    assert_eq!(recovered["status"], "uncertain");
    assert_eq!(recovered["cloudWrite"]["status"], "unknown");
    assert_eq!(recovered["completionState"], "complete");
    assert_eq!(f.engine.counts().await, (2, 1));
    let committed = snapshot(&f.h).await?;
    assert_eq!(post(&f.h, &format!("{}/recover", receipt(request)), json!({})).await?, recovered);
    assert_eq!(snapshot(&f.h).await?, committed);
    assert_eq!(f.engine.counts().await, (2, 1));
    Ok(())
}
