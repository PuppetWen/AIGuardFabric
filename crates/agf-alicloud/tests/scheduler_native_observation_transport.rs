//! Real HTTP/1.1 loopback evidence for the read-only native Scheduler driver.
//! No cloud credentials, environment switches, callback registration or provider writes.
mod scheduler_native_observation_transport_support;

use agf_alicloud::schedulerx3::native_observation::{CarrierPresence, observe_current};
use agf_core::error::{DomainError, DomainResult};
use scheduler_native_observation_transport_support::{
    Authority, Gate, PRIVATE_VALUES, Server, client, fixture_error, query, respond, scope, verify_signature,
};
use std::{collections::BTreeSet, sync::Arc};
use tokio::time::{Duration, Instant, sleep_until, timeout, timeout_at};

#[tokio::test]
async fn real_acs3_rpc_reads_all_101_jobs_across_two_pages_without_exposing_secrets() -> DomainResult<()> {
    let server = Server::start(respond).await?;
    let client = client(&server)?;
    let current =
        observe_current(&client, &scope(), &Authority::default(), Instant::now() + Duration::from_secs(5)).await?;
    assert_eq!(current.app().id, "9007199254740993");
    assert_eq!(current.pagination().total, 101);
    assert_eq!(current.pagination().pages.len(), 2);
    assert!(current.pagination().listing_complete);
    assert!(!current.pagination().strong_snapshot);
    assert_eq!(current.jobs().len(), 101);
    assert_eq!(current.jobs().first().map(|job| job.id.as_str()), Some("9007199254740994"));
    assert_eq!(current.jobs().last().map(|job| job.id.as_str()), Some("9007199254741094"));
    assert!(current.jobs().iter().all(|job| job.http_job
        && !job.http.verified
        && job.http.handler == CarrierPresence::Present
        && job.http.parameters == CarrierPresence::Present
        && job.schedule.utc == Some(true)
        && job.shard_count.is_none()));
    for secret in PRIVATE_VALUES.into_iter().chain(["SYNTHETIC-CALLBACK-TOKEN"]) {
        assert!(!serde_json::to_string(&current)?.contains(secret), "serialized observation exposed a private carrier");
        assert!(!format!("{current:?}").contains(secret), "debug observation exposed a private carrier");
    }
    server.settled(3).await?;
    let requests = server.requests()?;
    let mut nonces = BTreeSet::new();
    let mut observed = Vec::new();
    for request in &requests {
        verify_signature(request, &server.origin)?;
        let values = query(request)?;
        assert!(nonces.insert(
            request.headers.get("x-acs-signature-nonce").cloned().ok_or_else(|| fixture_error("nonce absent"))?
        ));
        observed.push((
            request.headers.get("x-acs-action").cloned(),
            values.get("PageNum").cloned(),
            values.get("PageSize").cloned(),
        ));
    }
    assert_eq!(
        observed,
        vec![
            (Some("GetApp".into()), None, None),
            (Some("ListJobs".into()), Some("1".into()), Some("100".into())),
            (Some("ListJobs".into()), Some("2".into()), Some("100".into())),
        ]
    );
    let original = requests.get(1).ok_or_else(|| fixture_error("first page absent"))?;
    let mut foreign_scope = original.clone();
    foreign_scope.target = foreign_scope.target.replace("cluster-agf-demo", "cluster-foreign");
    let mut altered_page = original.clone();
    altered_page.target = altered_page.target.replace("PageNum=1", "PageNum=2");
    assert!(verify_signature(&foreign_scope, &server.origin).is_err(), "scope is not protected by MAC");
    assert!(verify_signature(&altered_page, &server.origin).is_err(), "page is not protected by MAC");
    Ok(())
}

#[tokio::test]
async fn revocation_while_the_first_page_is_in_flight_prevents_page_two() -> DomainResult<()> {
    let gate = Arc::new(Gate::default());
    let _release = gate.release_on_drop();
    let held = gate.clone();
    let server = Server::start(move |request| {
        let reply = respond(request)?;
        Ok(if request.headers.get("x-acs-action").map(String::as_str) == Some("ListJobs") {
            reply.held(&held)
        } else {
            reply
        })
    })
    .await?;
    let client = Arc::new(client(&server)?);
    let authority = Arc::new(Authority::default());
    let (request_client, request_authority) = (client.clone(), authority.clone());
    let deadline = Instant::now() + Duration::from_secs(5);
    let task =
        tokio::spawn(
            async move { observe_current(&request_client, &scope(), request_authority.as_ref(), deadline).await },
        );
    gate.wait_entered().await?;
    authority.revoke();
    gate.release();
    let result = timeout(Duration::from_secs(3), task)
        .await
        .map_err(|_| fixture_error("revoked read did not finish"))?
        .map_err(|_| fixture_error("read task failed"))?;
    assert!(matches!(result, Err(DomainError::Forbidden(_))));
    server.settled(2).await?;
    let requests = server.requests()?;
    for request in &requests {
        verify_signature(request, &server.origin)?;
    }
    assert!(
        requests
            .iter()
            .all(|request| query(request).is_ok_and(|values| values.get("PageNum").map(String::as_str) != Some("2")))
    );
    Ok(())
}

#[tokio::test]
async fn the_original_deadline_spans_app_and_page_reads_without_restarting() -> DomainResult<()> {
    let app_gate = Arc::new(Gate::default());
    let page_gate = Arc::new(Gate::default());
    let (_app_release, _page_release) = (app_gate.release_on_drop(), page_gate.release_on_drop());
    let (held_app, held_page) = (app_gate.clone(), page_gate.clone());
    let server = Server::start(move |request| {
        let action = request.headers.get("x-acs-action").cloned();
        let reply = respond(request)?;
        Ok(if action.as_deref() == Some("GetApp") { reply.held(&held_app) } else { reply.held(&held_page) })
    })
    .await?;
    let client = Arc::new(client(&server)?);
    let original_deadline = Instant::now() + Duration::from_millis(1600);
    let request_client = client.clone();
    let task = tokio::spawn(async move {
        observe_current(&request_client, &scope(), &Authority::default(), original_deadline).await
    });
    app_gate.wait_entered().await?;
    sleep_until(original_deadline - Duration::from_millis(700)).await;
    app_gate.release();
    page_gate.wait_entered().await?;
    let result = timeout_at(original_deadline + Duration::from_millis(250), task)
        .await
        .map_err(|_| fixture_error("original deadline was restarted after GetApp"))?
        .map_err(|_| fixture_error("deadline task failed"))?;
    assert!(matches!(result, Err(DomainError::DependencyUnavailable { .. })));
    page_gate.release();
    server.settled(2).await?;
    for request in server.requests()? {
        verify_signature(&request, &server.origin)?;
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_a_real_in_flight_app_read_never_dispatches_list_jobs() -> DomainResult<()> {
    let gate = Arc::new(Gate::default());
    let _release = gate.release_on_drop();
    let held = gate.clone();
    let server = Server::start(move |request| Ok(respond(request)?.held(&held))).await?;
    let client = Arc::new(client(&server)?);
    let deadline = Instant::now() + Duration::from_secs(5);
    let request_client = client.clone();
    let task =
        tokio::spawn(async move { observe_current(&request_client, &scope(), &Authority::default(), deadline).await });
    gate.wait_entered().await?;
    task.abort();
    let joined =
        timeout(Duration::from_secs(2), task).await.map_err(|_| fixture_error("cancelled parent did not finish"))?;
    assert!(joined.is_err_and(|error| error.is_cancelled()));
    gate.release();
    server.settled(1).await?;
    let requests = server.requests()?;
    let request = requests.first().ok_or_else(|| fixture_error("actual GetApp request absent"))?;
    verify_signature(request, &server.origin)?;
    assert_eq!(request.headers.get("x-acs-action").map(String::as_str), Some("GetApp"));
    Ok(())
}
