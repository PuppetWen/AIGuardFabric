//! Real loopback evidence for the independent APIG control-plane driver.
//! These tests do not establish live RAM access, provider CAS or consumer application.
mod apig_policy_transport_support;

use agf_alicloud::apig::policy_driver::{
    ManagedLimit, ReadbackState, WriteOutcome, observe_current, prepare_limit, publish_once,
};
use agf_core::error::{DomainError, DomainResult};
use apig_policy_transport_support::{
    Authority, Gate, Server, Service, client, deadline, fixture_error, verify_signature,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[tokio::test]
async fn real_acs3_requests_use_plain_json_and_change_only_the_selected_rule() -> DomainResult<()> {
    let service = Service::new()?;
    let before = service.snapshot()?;
    let server = service.server().await?;
    let client = client(&server)?;
    let authority = Authority::default();
    let baseline = observe_current(&client, &service.binding, &authority, deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    let outcome = publish_once(&client, &update, &authority, deadline()).await?;
    assert_eq!(outcome, WriteOutcome::Accepted { request_id: "fixture-update-policy".into() });
    let current = observe_current(&client, &service.binding, &authority, deadline()).await?;
    assert_eq!(update.compare_readback(&current), ReadbackState::Matched);
    let after = service.snapshot()?;
    let mut expected: Value = serde_json::from_str(
        before["GetPolicy"]["data"]["config"].as_str().ok_or_else(|| fixture_error("missing baseline config"))?,
    )?;
    expected["globalRules"][0]["limitValue"] = json!(1250);
    let observed: Value = serde_json::from_str(
        after["GetPolicy"]["data"]["config"].as_str().ok_or_else(|| fixture_error("missing current config"))?,
    )?;
    assert_eq!(observed, expected);
    assert_eq!(after["GetPolicyAttachment"], before["GetPolicyAttachment"]);
    assert_eq!(after["GetHttpApi"], before["GetHttpApi"]);
    assert_eq!(server.count("GET")?, 9);
    assert_eq!(server.count("PUT")?, 1);
    let requests = server.requests()?;
    for request in &requests {
        verify_signature(request, &server.origin)?;
    }
    let put =
        requests.iter().find(|request| request.method == "PUT").ok_or_else(|| fixture_error("PUT not captured"))?;
    let body: Value = serde_json::from_str(&put.body)?;
    assert_eq!(body.as_object().map(serde_json::Map::len), Some(3));
    assert_eq!(body["name"], before["GetPolicy"]["data"]["name"]);
    assert_eq!(body["description"], "保留用户说明");
    assert_eq!(
        serde_json::from_str::<Value>(
            body["config"].as_str().ok_or_else(|| fixture_error("plain config string absent"))?
        )?,
        expected
    );
    let mut changed_body = put.clone();
    changed_body.body.push(' ');
    let mut changed_path = put.clone();
    changed_path.target.push_str("-foreign");
    assert!(verify_signature(&changed_body, &server.origin).is_err());
    assert!(verify_signature(&changed_path, &server.origin).is_err());
    server.healthy()
}

#[tokio::test]
async fn exact_resource_identity_and_envelope_conflicts_never_form_a_baseline() -> DomainResult<()> {
    for (path, value) in [
        ("/GetHttpApi/data/gatewayId", json!("gw-foreign")),
        ("/GetHttpApi/data/httpApiId", json!("api-foreign")),
        ("/GetHttpApi/data/deployConfigs/0/environmentId", json!("env-foreign")),
        ("/GetHttpApi/data/deployConfigs/0/policyConfigs/0/policyReference/policyId", json!("policy-foreign")),
        ("/GetPolicy/data/policyId", json!("policy-foreign")),
        ("/GetPolicyAttachment/data/policyAttachmentId", json!("attachment-foreign")),
        ("/GetPolicyAttachment/data/attachResourceId", json!("api-foreign")),
        ("/GetPolicyAttachment/code", json!("Ok")),
        ("/GetPolicy/data/config", json!("{\"enable\":true,\"enable\":false}")),
    ] {
        let service = Service::new()?;
        service.replace(path, value)?;
        let before = service.snapshot()?;
        let server = service.server().await?;
        let result = observe_current(&client(&server)?, &service.binding, &Authority::default(), deadline()).await;
        assert!(result.is_err(), "invalid provider evidence at {path}");
        assert_eq!(server.count("PUT")?, 0, "{path}");
        assert_eq!(service.snapshot()?, before, "{path}");
        server.healthy()?;
    }
    Ok(())
}

#[tokio::test]
async fn rereading_a_changed_fingerprint_blocks_put_and_preserves_the_external_edit() -> DomainResult<()> {
    let service = Service::new()?;
    let server = service.server().await?;
    let client = client(&server)?;
    let authority = Authority::default();
    let baseline = observe_current(&client, &service.binding, &authority, deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::RequestPerMinute, 12)?;
    service.mutate(|responses| responses["GetPolicy"]["data"]["description"] = json!("external metadata edit"))?;
    let changed = service.snapshot()?;
    assert!(matches!(publish_once(&client, &update, &authority, deadline()).await, Err(DomainError::Conflict(_))));
    assert_eq!(server.count("GET")?, 6);
    assert_eq!(server.count("PUT")?, 0);
    assert_eq!(service.snapshot()?, changed);
    server.healthy()
}

#[tokio::test]
async fn revocation_during_the_last_provider_read_prevents_the_write() -> DomainResult<()> {
    let service = Service::new()?;
    let enabled = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(Gate::default());
    let _release = gate.release_on_drop();
    let handler = service.clone();
    let (held, waiting) = (enabled.clone(), gate.clone());
    let server = Server::start(move |request| {
        let reply = handler.respond(request)?;
        Ok(
            if held.load(Ordering::SeqCst)
                && request.headers.get("x-acs-action").map(String::as_str) == Some("GetPolicyAttachment")
            {
                reply.held(&waiting)
            } else {
                reply
            },
        )
    })
    .await?;
    let client = Arc::new(client(&server)?);
    let authority = Arc::new(Authority::default());
    let baseline = observe_current(&client, &service.binding, authority.as_ref(), deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    let before = service.snapshot()?;
    enabled.store(true, Ordering::SeqCst);
    let task_client = client.clone();
    let task_authority = authority.clone();
    let task =
        tokio::spawn(async move { publish_once(&task_client, &update, task_authority.as_ref(), deadline()).await });
    gate.wait_entered().await?;
    authority.revoke();
    gate.release();
    let result = task.await.map_err(|_| fixture_error("publication task failed"))?;
    assert!(matches!(result, Err(DomainError::Forbidden(_))));
    assert_eq!(server.count("GET")?, 6);
    assert_eq!(server.count("PUT")?, 0);
    assert_eq!(service.snapshot()?, before);
    server.healthy()
}

#[tokio::test]
async fn an_initially_revoked_guard_dispatches_no_provider_request() -> DomainResult<()> {
    let service = Service::new()?;
    let server = service.server().await?;
    let authority = Authority::default();
    authority.revoke();
    assert!(matches!(
        observe_current(&client(&server)?, &service.binding, &authority, deadline()).await,
        Err(DomainError::Forbidden(_))
    ));
    assert!(server.requests()?.is_empty());
    server.healthy()
}

#[tokio::test]
async fn attachment_config_is_preserved_and_nonempty_overrides_remain_read_only() -> DomainResult<()> {
    for value in [None, Some(Value::Null), Some(json!(""))] {
        let service = Service::new()?;
        service.mutate(|responses| {
            if let Some(value) = value {
                responses["GetPolicyAttachment"]["data"]["config"] = value;
            } else if let Some(data) = responses["GetPolicyAttachment"]["data"].as_object_mut() {
                data.remove("config");
            }
        })?;
        let before = service.snapshot()?;
        let server = service.server().await?;
        let client = client(&server)?;
        let authority = Authority::default();
        let baseline = observe_current(&client, &service.binding, &authority, deadline()).await?;
        let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
        assert!(matches!(publish_once(&client, &update, &authority, deadline()).await?, WriteOutcome::Accepted { .. }));
        assert_eq!(service.snapshot()?["GetPolicyAttachment"], before["GetPolicyAttachment"]);
        assert_eq!(server.count("PUT")?, 1);
        server.healthy()?;
    }
    let service = Service::new()?;
    service.mutate(|responses| {
        responses["GetPolicyAttachment"]["data"]["config"] = responses["GetPolicy"]["data"]["config"].clone();
    })?;
    let before = service.snapshot()?;
    let server = service.server().await?;
    let baseline = observe_current(&client(&server)?, &service.binding, &Authority::default(), deadline()).await?;
    assert!(matches!(
        prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250),
        Err(DomainError::PreconditionFailed(_))
    ));
    assert_eq!(server.count("PUT")?, 0);
    assert_eq!(service.snapshot()?, before);
    server.healthy()
}

#[tokio::test]
async fn accepted_acknowledgement_and_different_readback_are_separate_facts() -> DomainResult<()> {
    let service = Service::new()?;
    let server = service.server().await?;
    let client = client(&server)?;
    let authority = Authority::default();
    let baseline = observe_current(&client, &service.binding, &authority, deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    let outcome = publish_once(&client, &update, &authority, deadline()).await?;
    service.mutate(|responses| responses["GetPolicy"]["data"]["description"] = json!("later external metadata"))?;
    let current = observe_current(&client, &service.binding, &authority, deadline()).await?;
    assert_eq!(update.compare_readback(&current), ReadbackState::Different);
    assert!(matches!(outcome, WriteOutcome::Accepted { .. }));
    service.mutate(|responses| responses["GetPolicy"]["code"] = json!("Forbidden.RAM"))?;
    assert!(observe_current(&client, &service.binding, &authority, deadline()).await.is_err());
    assert!(matches!(outcome, WriteOutcome::Accepted { .. }));
    assert_eq!(server.count("PUT")?, 1);
    server.healthy()
}

#[tokio::test]
async fn an_external_write_after_the_last_get_is_not_protected_by_cloud_cas() -> DomainResult<()> {
    let service = Service::new()?;
    let handler = service.clone();
    let server = Server::start(move |request| {
        if request.method == "PUT" {
            handler.mutate(|responses| {
                responses["GetPolicy"]["data"]["description"] = json!("external edit after last GET");
            })?;
        }
        handler.respond(request)
    })
    .await?;
    let client = client(&server)?;
    let authority = Authority::default();
    let baseline = observe_current(&client, &service.binding, &authority, deadline()).await?;
    let update = prepare_limit(&baseline, ManagedLimit::TokenPerMinute, 1250)?;
    assert!(matches!(publish_once(&client, &update, &authority, deadline()).await?, WriteOutcome::Accepted { .. }));
    assert_eq!(service.snapshot()?["GetPolicy"]["data"]["description"], "保留用户说明");
    let request = server
        .requests()?
        .into_iter()
        .find(|request| request.method == "PUT")
        .ok_or_else(|| fixture_error("missing PUT"))?;
    assert!(!request.headers.contains_key("if-match"));
    assert!(!request.target.contains("clientToken"));
    assert_eq!(server.count("PUT")?, 1);
    server.healthy()
}
