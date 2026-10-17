use super::{Authority, Gate, Reply, Server, Service, WaitingAuthority, client, deadline, fixture_error};
use agf_alicloud::apig::policy_driver::{
    ManagedLimit, ReadbackState, WriteOutcome, observe_current, prepare_limit, publish_once,
};
use agf_core::error::DomainResult;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::time::{Duration, Instant, timeout};

fn ambiguous_responses() -> [(&'static str, Reply); 14] {
    [
        ("http-500", Reply::json(500, &json!({"code":"Ok","requestId":"owned-ack"}))),
        ("http-429", Reply::json(429, &json!({"code":"Throttling","requestId":"owned-ack"}))),
        ("ram-denial", Reply::json(200, &json!({"code":"Forbidden.RAM","requestId":"owned-ack"}))),
        ("nacos-code-is-not-apig-cas", Reply::json(200, &json!({"code":"20005","requestId":"owned-ack"}))),
        ("numeric-code", Reply::json(200, &json!({"code":200,"requestId":"owned-ack"}))),
        ("missing-code", Reply::json(200, &json!({"requestId":"owned-ack"}))),
        ("missing-request-id", Reply::json(200, &json!({"code":"Ok"}))),
        ("wrong-request-id-type", Reply::json(200, &json!({"code":"Ok","requestId":12}))),
        ("control-in-request-id", Reply::json(200, &json!({"code":"Ok","requestId":"bad\nack"}))),
        ("empty-204", Reply::body(204, Vec::new(), &[])),
        ("html", Reply::body(200, b"<html>not an APIG acknowledgement</html>".to_vec(), &[])),
        ("array", Reply::json(200, &json!([{"code":"Ok","requestId":"owned-ack"}]))),
        ("invalid-utf8", Reply::body(200, vec![0xff, 0xfe], &[])),
        ("response-budget", Reply::body(200, vec![b' '; 2 * 1024 * 1024 + 1], &[])),
    ]
}

#[tokio::test]
async fn ambiguous_http_and_business_responses_remain_unknown_without_retry() -> DomainResult<()> {
    for (name, reply) in ambiguous_responses() {
        let service = Service::new()?;
        let handler = service.clone();
        let server = Server::start(move |request| {
            let ordinary = handler.respond(request)?;
            Ok(if request.method == "PUT" { reply.clone() } else { ordinary })
        })
        .await?;
        let client = client(&server)?;
        let authority = Authority::default();
        let baseline = observe_current(&client, &service.binding, &authority, deadline()).await?;
        let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
        let outcome = publish_once(&client, &update, &authority, deadline()).await?;
        assert_eq!(outcome, WriteOutcome::Unknown, "{name}");
        assert_eq!(server.count("PUT")?, 1, "{name}");
        let current = observe_current(&client, &service.binding, &authority, deadline()).await?;
        assert_eq!(update.compare_readback(&current), ReadbackState::Matched, "{name}");
        assert_eq!(outcome, WriteOutcome::Unknown, "later matching content cannot prove acceptance: {name}");
        assert_eq!(server.count("PUT")?, 1, "{name}");
        server.healthy()?;
    }
    Ok(())
}

#[tokio::test]
async fn a_received_put_with_truncated_acknowledgement_is_not_retried() -> DomainResult<()> {
    let service = Service::new()?;
    let handler = service.clone();
    let server = Server::start(move |request| {
        let ordinary = handler.respond(request)?;
        Ok(if request.method == "PUT" { Reply::truncated() } else { ordinary })
    })
    .await?;
    let client = client(&server)?;
    let authority = Authority::default();
    let baseline = observe_current(&client, &service.binding, &authority, deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    let outcome = publish_once(&client, &update, &authority, deadline()).await?;
    assert_eq!(outcome, WriteOutcome::Unknown);
    let current = observe_current(&client, &service.binding, &authority, deadline()).await?;
    assert_eq!(update.compare_readback(&current), ReadbackState::Matched);
    assert_eq!(outcome, WriteOutcome::Unknown);
    assert_eq!(server.count("PUT")?, 1);
    server.healthy()
}

#[tokio::test]
async fn provider_acknowledgement_wait_is_bounded_by_the_original_deadline() -> DomainResult<()> {
    let service = Service::new()?;
    let gate = Arc::new(Gate::default());
    let _release = gate.release_on_drop();
    let handler = service.clone();
    let waiting = gate.clone();
    let server = Server::start(move |request| {
        let ordinary = handler.respond(request)?;
        Ok(if request.method == "PUT" { ordinary.held(&waiting) } else { ordinary })
    })
    .await?;
    let client = Arc::new(client(&server)?);
    let authority = Arc::new(Authority::default());
    let baseline = observe_current(&client, &service.binding, authority.as_ref(), deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    let task_client = client.clone();
    let task_authority = authority.clone();
    let intended = update.clone();
    let until = Instant::now() + Duration::from_millis(1500);
    let task = tokio::spawn(async move { publish_once(&task_client, &intended, task_authority.as_ref(), until).await });
    gate.wait_entered().await?;
    let outcome = timeout(Duration::from_secs(3), task)
        .await
        .map_err(|_| fixture_error("driver ignored its deadline"))?
        .map_err(|_| fixture_error("publication task failed"))??;
    assert_eq!(outcome, WriteOutcome::Unknown);
    gate.release();
    let current = observe_current(&client, &service.binding, authority.as_ref(), deadline()).await?;
    assert_eq!(update.compare_readback(&current), ReadbackState::Matched);
    assert_eq!(server.count("PUT")?, 1);
    server.healthy()
}

#[tokio::test]
async fn provider_preflight_wait_consumes_the_original_deadline_without_a_put() -> DomainResult<()> {
    let service = Service::new()?;
    let held = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(Gate::default());
    let _release = gate.release_on_drop();
    let handler = service.clone();
    let waiting = gate.clone();
    let enabled = held.clone();
    let server = Server::start(move |request| {
        let ordinary = handler.respond(request)?;
        Ok(if enabled.load(Ordering::SeqCst) { ordinary.held(&waiting) } else { ordinary })
    })
    .await?;
    let client = Arc::new(client(&server)?);
    let authority = Arc::new(Authority::default());
    let baseline = observe_current(&client, &service.binding, authority.as_ref(), deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    let before = service.snapshot()?;
    held.store(true, Ordering::SeqCst);
    let task_client = client.clone();
    let task_authority = authority.clone();
    let until = Instant::now() + Duration::from_millis(1500);
    let task = tokio::spawn(async move { publish_once(&task_client, &update, task_authority.as_ref(), until).await });
    gate.wait_entered().await?;
    let result = timeout(Duration::from_secs(3), task)
        .await
        .map_err(|_| fixture_error("preflight ignored its deadline"))?
        .map_err(|_| fixture_error("preflight task failed"))?;
    assert!(result.is_err());
    assert_eq!(server.count("PUT")?, 0);
    assert_eq!(service.snapshot()?, before);
    gate.release();
    server.healthy()
}

#[tokio::test]
async fn a_blocked_authorization_guard_cannot_renew_the_original_deadline() -> DomainResult<()> {
    let service = Service::new()?;
    let server = service.server().await?;
    let client = Arc::new(client(&server)?);
    let gate = Arc::new(Gate::default());
    let _release = gate.release_on_drop();
    let authority = WaitingAuthority(gate.clone());
    let binding = service.binding.clone();
    let until = Instant::now() + Duration::from_millis(1500);
    let task = tokio::spawn(async move { observe_current(&client, &binding, &authority, until).await });
    gate.wait_entered().await?;
    let result = timeout(Duration::from_secs(3), task)
        .await
        .map_err(|_| fixture_error("guard ignored its deadline"))?
        .map_err(|_| fixture_error("guard task failed"))?;
    assert!(result.is_err());
    assert!(server.requests()?.is_empty());
    gate.release();
    server.healthy()
}

#[tokio::test]
async fn redirects_do_not_forward_signed_requests_to_another_origin() -> DomainResult<()> {
    for status in [302, 307] {
        let second =
            Server::start(|_| Ok(Reply::json(200, &json!({"code":"Ok","requestId":"unexpected-hop"})))).await?;
        let service = Service::new()?;
        let handler = service.clone();
        let location = format!("{}/must-not-receive", second.origin);
        let server = Server::start(move |request| {
            let ordinary = handler.respond(request)?;
            Ok(if request.method == "PUT" {
                Reply::body(status, Vec::new(), &[("Location", location.clone())])
            } else {
                ordinary
            })
        })
        .await?;
        let client = client(&server)?;
        let authority = Authority::default();
        let baseline = observe_current(&client, &service.binding, &authority, deadline()).await?;
        let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
        assert_eq!(publish_once(&client, &update, &authority, deadline()).await?, WriteOutcome::Unknown);
        assert_eq!(server.count("PUT")?, 1);
        assert!(second.requests()?.is_empty(), "redirect status {status}");
        server.healthy()?;
        second.healthy()?;
    }
    Ok(())
}
