//! Actual router contracts, original UUIDs and explicit Mock effects; no external cloud.
mod apig_configuration_publication_support;
mod common;
use agf_core::{error::DomainResult, ids::Id};
use apig_configuration_publication_support::*;
use common::*;

#[tokio::test]
async fn get_is_pure_and_observe_requires_explicit_fixture_initialization() -> DomainResult<()> {
    let h = setup().await;
    let initial = snapshot(&h).await?;
    assert_eq!(get(&h, BASE).await?["configured"], false);
    assert_eq!(snapshot(&h).await?, initial);
    configure(&h, 0, true, settings("content")).await?;
    let before = snapshot(&h).await?;
    for _ in 0..2 {
        let s = get(&h, BASE).await?;
        assert!(s["observation"].is_null());
        safe(&s);
    }
    assert_eq!(snapshot(&h).await?, before);
    let input = json!({"request_id":Id::new(),"configuration_version":1,"initialize_mock_fixture":false});
    assert_eq!(h.post(&format!("{BASE}/observe"), input.clone()).await.status, StatusCode::PRECONDITION_FAILED);
    let claimed = snapshot(&h).await?;
    assert_eq!(h.post(&format!("{BASE}/observe"), input).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&h).await?, claimed);
    assert!(h.state.configurations.list::<Value>(h.tenant, MOCK).await?.is_empty());
    Ok(())
}
#[tokio::test]
async fn both_configurations_preserve_private_fields_and_one_original_uuid_only_writes_once() -> DomainResult<()> {
    for kind in ["content", "models"] {
        let h = setup().await;
        configure(&h, 0, true, settings(kind)).await?;
        let p = ready(&h, kind).await?;
        safe(&p);
        let request = Id::new();
        let r = apply(&h, &p, request).await?;
        verified(&r);
        assert_eq!(r["cloudWrite"]["providerRequestId"], "mock-configuration-update-1");
        let before = snapshot(&h).await?;
        assert_eq!(apply(&h, &p, request).await?, r);
        assert_eq!(get(&h, &receipt(request)).await?, r);
        assert_eq!(post(&h, &format!("{}/recover", receipt(request)), json!({})).await?, r);
        assert_eq!(snapshot(&h).await?, before);
        assert_eq!(terminal_count(&h, request).await?, 1);
        assert_eq!(
            h.post(&format!("{BASE}/operations"), apply_body(&p, Id::new())?).await.status,
            StatusCode::CONFLICT
        );
        let mut different = apply_body(&p, request)?;
        different["confirm_live"] = json!(true);
        assert_eq!(h.post(&format!("{BASE}/operations"), different).await.status, StatusCode::CONFLICT);
        assert_eq!(snapshot(&h).await?, before);
        assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    }
    Ok(())
}
#[tokio::test]
async fn trusted_history_rolls_back_onto_a_new_baseline_then_disabled_source_keeps_tombstones_readable()
-> DomainResult<()> {
    let h = setup().await;
    configure(&h, 0, true, settings("models")).await?;
    let p = ready(&h, "models").await?;
    let first = Id::new();
    verified(&apply(&h, &p, first).await?);
    let o = observe(&h, false).await?;
    let rollback = preview(&h, &o, json!({"action":"rollback","publication_id":first})).await?;
    assert_eq!(rollback["sourcePublicationId"], json!(first));
    let second = Id::new();
    verified(&apply(&h, &rollback, second).await?);
    assert_ne!(first, second);
    configure(&h, 1, false, settings("models")).await?;
    let s = get(&h, BASE).await?;
    assert_eq!(s["canObserve"], false);
    let before = snapshot(&h).await?;
    assert_eq!(get(&h, &receipt(first)).await?["sourceCurrent"], false);
    assert_eq!(snapshot(&h).await?, before);
    archive(&h, first).await?;
    let tomb = get(&h, &receipt(first)).await?;
    assert_eq!(tomb["status"], "archived");
    assert_eq!(tomb["originalStatus"], "verified");
    assert_eq!(tomb["cloudWrite"]["providerRequestId"], "mock-configuration-update-1");
    let before = snapshot(&h).await?;
    assert_eq!(get(&h, &receipt(first)).await?, tomb);
    assert_eq!(snapshot(&h).await?, before);
    assert!(
        get(&h, BASE).await?["history"]
            .as_array()
            .is_some_and(|a| a.iter().all(|r| r["publicationId"] != json!(first)))
    );
    Ok(())
}
#[tokio::test]
async fn raw_apig_writes_fail_before_claim_audit_or_dispatch_and_safe_reads_still_work() -> DomainResult<()> {
    let h = setup().await;
    configure(&h, 0, true, settings("content")).await?;
    let before = snapshot(&h).await?;
    let rows: Value = serde_json::from_str(include_str!("../../agf-alicloud/src/openapi/contracts/apig.json"))?;
    for row in rows.as_array().into_iter().flatten().filter(|row| row["read_only"] == false) {
        let request = Id::new();
        let r = h
            .post(
                &format!("{CONFIG}/operations"),
                json!({"request_id":request,
            "configuration_version":1,"action":row["action"],"parameters":{},"confirm_live":true}),
            )
            .await;
        assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);
        assert!(r.text.contains("APIG"));
        assert_eq!(h.get(&format!("{CONFIG}/operations/{request}")).await.status, StatusCode::NOT_FOUND);
        assert_eq!(snapshot(&h).await?, before);
    }
    let r = h
        .post(
            &format!("{CONFIG}/operations"),
            json!({"request_id":Id::new(),"configuration_version":1,
        "action":"ListPlugins","parameters":{"pageNumber":1,"pageSize":1}}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json()["status"], "succeeded");
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
#[tokio::test]
async fn stale_source_conflict_and_exact_four_confirmations_never_consume_preview_or_write() -> DomainResult<()> {
    let h = setup().await;
    configure(&h, 0, true, settings("content")).await?;
    let p = ready(&h, "content").await?;
    for field in [
        "confirm_apply",
        "confirm_preserved_private_configuration",
        "confirm_streaming_or_shared_impact",
        "confirm_no_cloud_cas",
    ] {
        let before = snapshot(&h).await?;
        let mut b = apply_body(&p, Id::new())?;
        b[field] = json!(false);
        assert_eq!(h.post(&format!("{BASE}/operations"), b).await.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(snapshot(&h).await?, before);
    }
    let mut changed = settings("content");
    changed["account_id"] = json!("retarget-account");
    configure(&h, 1, true, changed).await?;
    let before = snapshot(&h).await?;
    assert_eq!(h.post(&format!("{BASE}/operations"), apply_body(&p, Id::new())?).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}
