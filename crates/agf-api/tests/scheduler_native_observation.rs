//! Native Scheduler routes: explicit observation, safe evidence and local-only bindings.
mod common;
mod scheduler_native_observation_support;

use agf_core::{audit::AuditOutcome, error::DomainResult, ids::Id};
use common::*;
use scheduler_native_observation_support::*;

#[tokio::test]
async fn authenticated_metadata_is_pure_and_unknown_is_not_an_observed_zero() -> DomainResult<()> {
    let h = setup().await;
    let before = snapshot(&h).await?;
    assert_eq!(h.request("GET", BASE, None, None).await.status, StatusCode::UNAUTHORIZED);
    let view = read(&h, BASE).await?;
    assert_eq!(view["configured"], false);
    assert_eq!(view["enabled"], false);
    assert!(view["sourceTarget"].is_null());
    assert!(view["latestObservation"].is_null());
    assert_eq!(view["stateVersion"], 0);
    assert_eq!(view["detailedObservationCount"], 0);
    assert_eq!(view["canObserve"], false);
    assert_eq!(view["deploymentVerified"], Value::Null);
    assert_eq!(view["callbackConfigured"], Value::Null);
    assert_eq!(h.get(&receipt(Id::new())).await.status, StatusCode::NOT_FOUND);
    assert_eq!(snapshot(&h).await?, before);
    configure(&h, 0, true, settings()).await?;
    let configured = snapshot(&h).await?;
    for _ in 0..2 {
        let view = read(&h, BASE).await?;
        assert_eq!(view["canObserve"], true);
        assert_eq!(view["canInitMock"], true);
        assert_eq!(view["sourceTarget"]["mocked"], true);
        assert!(view["latestObservation"].is_null());
        assert_eq!(view["recentObservations"], json!([]));
        assert_safe(&view);
        assert_eq!(snapshot(&h).await?, configured);
    }
    Ok(())
}

#[tokio::test]
async fn uninitialized_mock_read_claims_once_without_seeding_or_inventing_a_result() -> DomainResult<()> {
    let h = mock_harness().await?;
    let request = Id::new();
    let input = observe_input(request, 1, false);
    let reply = h.post(&format!("{BASE}/observe"), input.clone()).await;
    assert_eq!(reply.status, StatusCode::PRECONDITION_FAILED);
    assert_safe(&reply.json());
    assert!(records(&h, "scheduler-native-driver-mock").await?.is_empty());
    assert!(records(&h, "scheduler-native-observation").await?.is_empty());
    let failed = read(&h, &receipt(request)).await?;
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["total"], Value::Null);
    assert_eq!(failed["observation"], Value::Null);
    assert_eq!(failed["listingComplete"], false);
    assert_read_audit(&h, request, AuditOutcome::Failure).await?;
    let before = snapshot(&h).await?;
    assert_eq!(post(&h, &format!("{BASE}/observe"), input).await?, failed);
    assert_eq!(snapshot(&h).await?, before);
    assert!(read(&h, BASE).await?["latestObservation"].is_null());
    Ok(())
}

#[tokio::test]
async fn explicit_mock_observation_has_six_safe_jobs_and_stable_receipt_pages() -> DomainResult<()> {
    let h = mock_harness().await?;
    let observed = observed(&h).await?;
    let request = identifier(&observed, "requestId")?;
    assert_eq!(observed["status"], "observed");
    assert_eq!(observed["total"], 6);
    assert_eq!(observed["listingComplete"], true);
    assert_eq!(observed["strongSnapshot"], false);
    assert_eq!(observed["authorizationAllowed"], Value::Null);
    assert_eq!(observed["callbackReachability"], Value::Null);
    assert_eq!(observed["callbackBindingEnforced"], false);
    assert_eq!(observed["appId"], "9007199254740993");
    assert_eq!(observed["observation"]["jobs"].as_array().map(Vec::len), Some(6));
    assert_eq!(observed["observation"]["jobs"][5]["enabled"], Value::Null);
    assert_eq!(observed["observation"]["jobs"][5]["schedule"]["utc"], Value::Null);
    assert_eq!(observed["observation"]["jobs"][0]["http"]["verified"], false);
    assert_safe(&observed);
    assert_read_audit(&h, request, AuditOutcome::Success).await?;
    let before = snapshot(&h).await?;
    let mut jobs = Vec::new();
    for page in 1..=3 {
        let value = read(&h, &format!("{}?page={page}&page_size=2", receipt(request))).await?;
        assert_eq!(value["observation"]["totalPages"], 3);
        assert_eq!(value["observation"]["page"], page);
        jobs.extend(
            value["observation"]["jobs"]
                .as_array()
                .ok_or_else(|| agf_core::error::DomainError::Internal("safe page jobs absent".into()))?
                .clone(),
        );
        assert_safe(&value);
    }
    assert_eq!(json!(jobs), observed["observation"]["jobs"]);
    for query in ["page=0", "page_size=0", "page_size=101", "page=4&page_size=2", "unexpected=1"] {
        assert_eq!(h.get(&format!("{}?{query}", receipt(request))).await.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(post(&h, &format!("{BASE}/observe"), observe_input(request, 1, true)).await?, observed);
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}

#[tokio::test]
async fn partial_association_is_canonical_versioned_local_only_and_explicitly_disabled() -> DomainResult<()> {
    let h = mock_harness().await?;
    let observation = identifier(&observed(&h).await?, "requestId")?;
    let report = replace(Id::new(), 0, observation, &[("report", "9007199254741002")]);
    let saved = put(&h, report.clone()).await?;
    assert_eq!(saved["version"], 1);
    assert_eq!(saved["status"], "partial");
    assert_eq!(saved["locallyEnabled"], true);
    assert_eq!(saved["items"].as_array().map(Vec::len), Some(1));
    let item = &saved["items"][0];
    assert_eq!(item["kind"], "report");
    assert_eq!(item["runtimeName"], "report-generate");
    assert_eq!(item["jobId"], "9007199254741002");
    assert_eq!(item["eligibility"], "eligible");
    assert_eq!(item["adoptedProof"]["observationId"], json!(observation));
    assert_eq!(item["adoptedProof"]["jobId"], item["jobId"]);
    assert_eq!(item["adoptedProof"]["httpJob"], true);
    assert_eq!(item["currentEvidence"]["enabled"], true);
    assert_eq!(saved["callbackBindingEnforced"], false);
    assert_eq!(saved["deploymentVerified"], Value::Null);
    let before = snapshot(&h).await?;
    assert_eq!(put(&h, report).await?, saved);
    assert_eq!(snapshot(&h).await?, before);
    let stale = replace(Id::new(), 0, observation, &[("archive", "9007199254741002")]);
    assert_eq!(
        h.request("PUT", &format!("{BASE}/bindings"), Some(&h.admin), Some(stale)).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&h).await?, before);
    let archive = put(&h, replace(Id::new(), 1, observation, &[("archive", "9007199254741002")])).await?;
    assert_eq!(archive["version"], 2);
    assert_eq!(archive["items"][0]["runtimeName"], "cold-archive");
    let disabled = put(&h, disable(Id::new(), 2)).await?;
    assert_eq!(disabled["version"], 3);
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(disabled["locallyEnabled"], false);
    assert_eq!(disabled["items"], archive["items"]);
    assert_eq!(read(&h, BASE).await?["bindings"]["status"], "disabled");
    assert!(records(&h, "integration-operation").await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn binding_rejects_unknown_disabled_non_http_jobs_duplicates_and_noncanonical_kinds() -> DomainResult<()> {
    let h = mock_harness().await?;
    let observation = identifier(&observed(&h).await?, "requestId")?;
    let before = snapshot(&h).await?;
    for (kind, job, status) in [
        ("asset-inventory", "9007199254741001", StatusCode::PRECONDITION_FAILED),
        ("archive", "9007199254741005", StatusCode::PRECONDITION_FAILED),
        ("report", "9007199254741006", StatusCode::PRECONDITION_FAILED),
        ("report-generate", "9007199254741002", StatusCode::BAD_REQUEST),
        ("report", "9007199254741999", StatusCode::CONFLICT),
    ] {
        let reply = h
            .request(
                "PUT",
                &format!("{BASE}/bindings"),
                Some(&h.admin),
                Some(replace(Id::new(), 0, observation, &[(kind, job)])),
            )
            .await;
        assert_eq!(reply.status, status, "kind {kind}, owned job {job}");
        assert_eq!(snapshot(&h).await?, before);
    }
    let duplicate =
        replace(Id::new(), 0, observation, &[("report", "9007199254741002"), ("archive", "9007199254741002")]);
    assert_eq!(
        h.request("PUT", &format!("{BASE}/bindings"), Some(&h.admin), Some(duplicate)).await.status,
        StatusCode::BAD_REQUEST
    );
    let mut unconfirmed = replace(Id::new(), 0, observation, &[]);
    unconfirmed["confirm_local_only"] = json!(false);
    assert_eq!(
        h.request("PUT", &format!("{BASE}/bindings"), Some(&h.admin), Some(unconfirmed)).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}

#[tokio::test]
async fn archive_releases_content_but_keeps_permanent_fact_and_original_uuid_no_dispatch() -> DomainResult<()> {
    let h = mock_harness().await?;
    let observed = observed(&h).await?;
    let id = identifier(&observed, "requestId")?;
    let facts = records(&h, "scheduler-native-fact").await?;
    let version = number(&read(&h, BASE).await?, "generation")?;
    configure(&h, 1, false, settings()).await?;
    let archive = json!({"expected_generation":version,"request_ids":[id]});
    let result = post(&h, &format!("{BASE}/observations/archive"), archive).await?;
    assert_eq!(result["archivedCount"], 1);
    assert_eq!(result["storedContentBytes"], 0);
    assert_eq!(records(&h, "scheduler-native-fact").await?, facts);
    let body = records(&h, "scheduler-native-observation").await?;
    assert_eq!(body.len(), 1);
    assert_eq!(body[0]["class"], "archived");
    assert!(body[0].get("secret").is_none());
    let archived = read(&h, &receipt(id)).await?;
    assert_eq!(archived["status"], "archived");
    assert_eq!(archived["originalStatus"], "observed");
    assert_eq!(archived["current"], false);
    assert_eq!(archived["observation"], Value::Null);
    let before = snapshot(&h).await?;
    assert_eq!(post(&h, &format!("{BASE}/observe"), observe_input(id, 1, true)).await?, archived);
    assert_eq!(snapshot(&h).await?, before);
    let generation = number(&result, "generation")?;
    post(&h, &format!("{BASE}/observations/archive"), json!({"expected_generation":generation,"request_ids":[id]}))
        .await?;
    assert_eq!(snapshot(&h).await?, before);
    assert_eq!(
        h.post(&format!("{BASE}/observations/archive"), json!({"expected_generation":version,"request_ids":[id]}))
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}

#[tokio::test]
async fn permanent_uuid_body_and_purpose_are_tenant_scoped_and_read_capability_cannot_seed() -> DomainResult<()> {
    let h = mock_harness().await?;
    assert_eq!(h.request("GET", BASE, Some(&h.viewer), None).await.status, StatusCode::FORBIDDEN);
    let (readonly, _) = key(&h, &["alicloud:read"]).await?;
    assert_eq!(h.request("GET", BASE, Some(&readonly), None).await.status, StatusCode::OK);
    let before = snapshot(&h).await?;
    assert_eq!(
        h.request("POST", &format!("{BASE}/observe"), Some(&readonly), Some(observe_input(Id::new(), 1, true)))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.request("PUT", &format!("{BASE}/bindings"), Some(&readonly), Some(disable(Id::new(), 0))).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(snapshot(&h).await?, before);
    let observed = observed(&h).await?;
    let id = identifier(&observed, "requestId")?;
    let before = snapshot(&h).await?;
    assert_eq!(h.post(&format!("{BASE}/observe"), observe_input(id, 1, false)).await.status, StatusCode::CONFLICT);
    assert_eq!(
        h.request("PUT", &format!("{BASE}/bindings"), Some(&h.admin), Some(disable(id, 0))).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(snapshot(&h).await?, before);
    let other = for_tenant(h.clone(), h.other_tenant)?;
    let foreign_before = snapshot(&other).await?;
    assert_eq!(other.get(&receipt(id)).await.status, StatusCode::NOT_FOUND);
    assert!(read(&other, BASE).await?["latestObservation"].is_null());
    assert_eq!(snapshot(&other).await?, foreign_before);
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}
