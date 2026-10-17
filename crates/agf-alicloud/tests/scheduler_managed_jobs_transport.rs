//! Actual signed loopback HTTP for single Scheduler control-plane writes.
//! No vendor calls, callback activation, persistent workflow or six-job completion claim.
mod scheduler_managed_jobs_transport_support;

use agf_alicloud::schedulerx3::{
    managed_jobs::{Change, Readback, SchedulePatch, WriteStatus, compare_readback, dispatch_once, prepare},
    native_observation::observe_current,
};
use agf_core::error::{DomainError, DomainResult};
use scheduler_managed_jobs_transport_support::{
    Authority, Fixture, Gate, PRIVATE_VALUES, Reply, Server, assert_requests, client, fixture_error, form, scope,
    selection, verify_signature,
};
use serde_json::json;
use std::sync::Arc;
use tokio::time::{Duration, Instant, timeout, timeout_at};

fn update() -> Change {
    Change::UpdateSchedule {
        patch: SchedulePatch {
            max_attempt: Some(0),
            calendar: Some("owned & calendar/+".into()),
            ..SchedulePatch::default()
        },
    }
}

#[tokio::test]
async fn real_signed_update_preserves_carrier_and_is_exactly_one_form_write() -> DomainResult<()> {
    let fixture = Fixture::new();
    let provider = fixture.clone();
    let server = Server::start(move |request| provider.respond(request)).await?;
    let client = client(&server)?;
    let guard = Authority::default();
    let deadline = Instant::now() + Duration::from_secs(5);
    let original = observe_current(&client, &scope(), &guard, deadline).await?;
    let plan = prepare(&original, &selection(&original), &update())?;
    let receipt = dispatch_once(&client, &plan, &guard, deadline).await?;
    assert_eq!(receipt.status, WriteStatus::Accepted);
    assert!(receipt.attempted && receipt.authority_current && receipt.original_deadline_current);
    let current = observe_current(&client, &scope(), &guard, deadline).await?;
    assert_eq!(compare_readback(&plan, &current), Readback::Matched);
    assert_eq!(current.jobs()[0].enabled, Some(false));
    assert_eq!(current.jobs()[0].http, original.jobs()[0].http);
    let requests = assert_requests(&server, 7, 1).await?;
    let write =
        requests.iter().find(|request| request.method == "POST").ok_or_else(|| fixture_error("write absent"))?;
    assert_eq!(write.headers.get("x-acs-action").map(String::as_str), Some("UpdateJob"));
    assert_eq!(form(write)?.get("MaxAttempt").map(String::as_str), Some("0"));
    assert_eq!(form(write)?.get("Calendar").map(String::as_str), Some("owned & calendar/+"));
    let mut altered = write.clone();
    altered.body = altered.body.replace("MaxAttempt=0", "MaxAttempt=1");
    assert!(verify_signature(&altered, &server.origin).is_err());
    for secret in PRIVATE_VALUES {
        assert!(!serde_json::to_string(&receipt)?.contains(secret));
        assert!(!format!("{receipt:?}").contains(secret));
    }
    Ok(())
}

#[tokio::test]
async fn disabling_and_enabling_are_two_independent_reviewed_actions() -> DomainResult<()> {
    let fixture = Fixture::new();
    fixture.set("Status", json!(1))?;
    let provider = fixture.clone();
    let server = Server::start(move |request| provider.respond(request)).await?;
    let client = client(&server)?;
    let guard = Authority::default();
    let deadline = Instant::now() + Duration::from_secs(5);
    let original = observe_current(&client, &scope(), &guard, deadline).await?;
    assert!(prepare(&original, &selection(&original), &update()).is_err());
    let disabling = prepare(&original, &selection(&original), &Change::Disable)?;
    assert_eq!(dispatch_once(&client, &disabling, &guard, deadline).await?.status, WriteStatus::Accepted);
    let disabled = observe_current(&client, &scope(), &guard, deadline).await?;
    assert_eq!(compare_readback(&disabling, &disabled), Readback::Matched);
    let enabling = prepare(&disabled, &selection(&disabled), &Change::Enable)?;
    assert_eq!(dispatch_once(&client, &enabling, &guard, deadline).await?.status, WriteStatus::Accepted);
    let enabled = observe_current(&client, &scope(), &guard, deadline).await?;
    assert_eq!(compare_readback(&enabling, &enabled), Readback::Matched);
    let requests = assert_requests(&server, 12, 2).await?;
    let actions: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "POST")
        .filter_map(|request| request.headers.get("x-acs-action").map(String::as_str))
        .collect();
    assert_eq!(actions, vec!["OperateDisableJobs", "OperateEnableJobs"]);
    Ok(())
}

#[tokio::test]
async fn fresh_carrier_drift_prevents_dispatch_of_the_original_plan() -> DomainResult<()> {
    let fixture = Fixture::new();
    let provider = fixture.clone();
    let server = Server::start(move |request| provider.respond(request)).await?;
    let client = client(&server)?;
    let guard = Authority::default();
    let deadline = Instant::now() + Duration::from_secs(5);
    let original = observe_current(&client, &scope(), &guard, deadline).await?;
    let plan = prepare(&original, &selection(&original), &update())?;
    fixture.set("Parameters", json!("changed-private-carrier"))?;
    assert!(matches!(dispatch_once(&client, &plan, &guard, deadline).await, Err(DomainError::PreconditionFailed(_))));
    assert_requests(&server, 4, 0).await?;
    Ok(())
}

#[tokio::test]
async fn revocation_before_preflight_is_not_a_provider_write() -> DomainResult<()> {
    let fixture = Fixture::new();
    let server = Server::start(move |request| fixture.respond(request)).await?;
    let client = client(&server)?;
    let guard = Authority::default();
    let deadline = Instant::now() + Duration::from_secs(5);
    let original = observe_current(&client, &scope(), &guard, deadline).await?;
    let plan = prepare(&original, &selection(&original), &update())?;
    guard.revoke();
    assert!(matches!(dispatch_once(&client, &plan, &guard, deadline).await, Err(DomainError::Forbidden(_))));
    assert_requests(&server, 2, 0).await?;
    Ok(())
}

#[tokio::test]
async fn revocation_after_a_real_write_keeps_its_known_ack_for_local_staging() -> DomainResult<()> {
    let guard = Arc::new(Authority::default());
    let current = guard.clone();
    let fixture = Fixture::new();
    let server = Server::start(move |request| {
        let reply = fixture.respond(request)?;
        if request.method == "POST" {
            current.revoke();
        }
        Ok(reply)
    })
    .await?;
    let client = client(&server)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let original = observe_current(&client, &scope(), guard.as_ref(), deadline).await?;
    let plan = prepare(&original, &selection(&original), &update())?;
    let receipt = dispatch_once(&client, &plan, guard.as_ref(), deadline).await?;
    assert_eq!(receipt.status, WriteStatus::Accepted);
    assert!(!receipt.authority_current);
    assert!(receipt.attempted);
    assert_requests(&server, 5, 1).await?;
    Ok(())
}

#[tokio::test]
async fn response_lost_after_mutation_is_unknown_and_manual_readback_never_upgrades_it() -> DomainResult<()> {
    let fixture = Fixture::new();
    let provider = fixture.clone();
    let server = Server::start(move |request| {
        let reply = provider.respond(request)?;
        Ok(if request.method == "POST" { Reply::disconnected() } else { reply })
    })
    .await?;
    let client = client(&server)?;
    let guard = Authority::default();
    let deadline = Instant::now() + Duration::from_secs(5);
    let original = observe_current(&client, &scope(), &guard, deadline).await?;
    let plan = prepare(&original, &selection(&original), &update())?;
    let receipt = dispatch_once(&client, &plan, &guard, deadline).await?;
    assert_eq!(receipt.status, WriteStatus::Unknown);
    assert!(receipt.attempted);
    assert_requests(&server, 5, 1).await?;
    let fresh = observe_current(&client, &scope(), &guard, deadline).await?;
    assert_eq!(compare_readback(&plan, &fresh), Readback::Matched);
    assert_eq!(receipt.status, WriteStatus::Unknown);
    assert_requests(&server, 7, 1).await?;
    Ok(())
}

#[tokio::test]
async fn the_original_deadline_expiring_after_write_is_unknown_without_an_automatic_retry() -> DomainResult<()> {
    let gate = Arc::new(Gate::default());
    let _release = gate.release_on_drop();
    let held = gate.clone();
    let fixture = Fixture::new();
    let server = Server::start(move |request| {
        let reply = fixture.respond(request)?;
        Ok(if request.method == "POST" { reply.held(&held) } else { reply })
    })
    .await?;
    let client = Arc::new(client(&server)?);
    let guard = Arc::new(Authority::default());
    let original = observe_current(&client, &scope(), guard.as_ref(), Instant::now() + Duration::from_secs(5)).await?;
    let plan = prepare(&original, &selection(&original), &update())?;
    let deadline = Instant::now() + Duration::from_millis(1200);
    let task = tokio::spawn(async move { dispatch_once(&client, &plan, guard.as_ref(), deadline).await });
    gate.wait_entered().await?;
    let receipt = timeout_at(deadline + Duration::from_millis(300), task)
        .await
        .map_err(|_| fixture_error("write deadline was restarted"))?
        .map_err(|_| fixture_error("write task failed"))??;
    assert_eq!(receipt.status, WriteStatus::Unknown);
    assert!(receipt.attempted);
    assert!(!receipt.original_deadline_current);
    gate.release();
    assert_requests(&server, 5, 1).await?;
    Ok(())
}

#[tokio::test]
async fn caller_cancellation_after_write_entry_does_not_dispatch_an_enable_or_retry() -> DomainResult<()> {
    let gate = Arc::new(Gate::default());
    let _release = gate.release_on_drop();
    let held = gate.clone();
    let fixture = Fixture::new();
    let server = Server::start(move |request| {
        let reply = fixture.respond(request)?;
        Ok(if request.method == "POST" { reply.held(&held) } else { reply })
    })
    .await?;
    let client = Arc::new(client(&server)?);
    let guard = Arc::new(Authority::default());
    let original = observe_current(&client, &scope(), guard.as_ref(), Instant::now() + Duration::from_secs(5)).await?;
    let plan = prepare(&original, &selection(&original), &update())?;
    let task = tokio::spawn(async move {
        dispatch_once(&client, &plan, guard.as_ref(), Instant::now() + Duration::from_secs(5)).await
    });
    gate.wait_entered().await?;
    task.abort();
    let joined =
        timeout(Duration::from_secs(2), task).await.map_err(|_| fixture_error("cancelled parent did not finish"))?;
    assert!(joined.is_err_and(|error| error.is_cancelled()));
    gate.release();
    assert_requests(&server, 5, 1).await?;
    Ok(())
}
