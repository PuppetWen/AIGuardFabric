//! Actual signed literal-loopback requests for the restricted configuration driver.
//! These definitions establish neither live RAM permissions nor deployment/consumer acceptance.
mod apig_config_transport_support;
use agf_alicloud::apig::config_driver::{
    ContentSettings, ReadbackState, WriteOutcome, observe_content, observe_models, prepare_content, prepare_models,
    publish_once,
};
use agf_core::error::{DomainError, DomainResult};
use apig_config_transport_support::{
    Authority, Gate, Reply, Server, WaitingAuthority, client, deadline, fixture_error,
    service::{Service, patches},
    verify_signature,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::time::{Duration, Instant, timeout};

fn settings() -> ContentSettings {
    ContentSettings { enabled: true, check_request: true, check_response: true, deny_code: 451 }
}

#[tokio::test]
async fn signed_plugin_update_retains_credentials_and_exact_single_attachment_resource() -> DomainResult<()> {
    let service = Service::new()?;
    let before = service.snapshot()?;
    let server = service.server().await?;
    let client = client(&server)?;
    let authority = Authority::default();
    let baseline = observe_content(&client, &service.content()?, &authority, deadline()).await?;
    let update = prepare_content(&baseline, settings())?;
    assert!(matches!(publish_once(&client, &update, &authority, deadline()).await?, WriteOutcome::Accepted { .. }));
    let current = observe_content(&client, &service.content()?, &authority, deadline()).await?;
    assert_eq!(update.compare_readback(&current), ReadbackState::Matched);
    assert_eq!(server.count("GET")?, 3);
    assert_eq!(server.count("PUT")?, 1);
    let requests = server.requests()?;
    for request in &requests {
        verify_signature(request, &server.origin)?;
    }
    let put = requests.iter().find(|r| r.method == "PUT").ok_or_else(|| fixture_error("missing plugin write"))?;
    let body: Value = serde_json::from_str(&put.body)?;
    assert_eq!(body["attachResourceIds"], json!(["api-owned"]));
    let decode = |value: &Value| -> DomainResult<Value> {
        let encoded = value.as_str().ok_or_else(|| fixture_error("missing encoded config"))?;
        let raw = STANDARD.decode(encoded).map_err(|_| fixture_error("invalid Base64"))?;
        Ok(serde_json::from_slice(&raw)?)
    };
    let mut expected = decode(&before["responses"]["GetPluginAttachment"]["data"]["pluginConfig"])?;
    expected["checkResponse"] = json!(true);
    expected["denyCode"] = json!(451);
    assert_eq!(decode(&body["pluginConfig"])?, expected);
    assert_eq!(service.snapshot()?["responses"]["GetHttpApi"], before["responses"]["GetHttpApi"]);
    assert!(!update.safe_diff().to_string().contains("synthetic-content-secret"));
    server.healthy()
}
#[tokio::test]
async fn signed_model_update_is_configuration_only_and_preserves_other_environment_and_auth() -> DomainResult<()> {
    let service = Service::new()?;
    let before = service.snapshot()?;
    let server = service.server().await?;
    let client = client(&server)?;
    let authority = Authority::default();
    let baseline = observe_models(&client, &service.models()?, &authority, deadline()).await?;
    let update = prepare_models(&baseline, &patches())?;
    assert!(matches!(publish_once(&client, &update, &authority, deadline()).await?, WriteOutcome::Accepted { .. }));
    let current = observe_models(&client, &service.models()?, &authority, deadline()).await?;
    assert_eq!(update.compare_readback(&current), ReadbackState::Matched);
    let requests = server.requests()?;
    for request in &requests {
        verify_signature(request, &server.origin)?;
    }
    let body: Value = serde_json::from_str(
        &requests.iter().find(|r| r.method == "PUT").ok_or_else(|| fixture_error("missing model write"))?.body,
    )?;
    assert_eq!(body["onlyChangeConfig"], json!(true));
    assert_eq!(body["authConfig"], before["responses"]["GetHttpApi"]["data"]["authConfig"]);
    assert_eq!(body["deployConfigs"][1], before["responses"]["GetHttpApi"]["data"]["deployConfigs"][1]);
    assert!(!requests.iter().any(|r| r.target.ends_with("/deploy")));
    assert_eq!(server.count("GET")?, 3);
    assert_eq!(server.count("PUT")?, 1);
    server.healthy()
}
#[tokio::test]
async fn changed_private_configuration_or_unmanaged_field_blocks_the_unique_write() -> DomainResult<()> {
    for plugin in [true, false] {
        let service = Service::new()?;
        let server = service.server().await?;
        let client = client(&server)?;
        let authority = Authority::default();
        let update = if plugin {
            prepare_content(&observe_content(&client, &service.content()?, &authority, deadline()).await?, settings())?
        } else {
            prepare_models(&observe_models(&client, &service.models()?, &authority, deadline()).await?, &patches())?
        };
        service.mutate(|v| {
            if plugin {
                v["responses"]["GetPluginAttachment"]["data"]["resourceInfos"][0]["resourceVersion"] =
                    json!("external-change");
            } else {
                v["responses"]["GetHttpApi"]["data"]["deployConfigs"][1]["futureVendorField"] =
                    json!({"secret":"changed"});
            }
        })?;
        let before = service.snapshot()?;
        assert!(matches!(publish_once(&client, &update, &authority, deadline()).await, Err(DomainError::Conflict(_))));
        assert_eq!(server.count("PUT")?, 0);
        assert_eq!(service.snapshot()?, before);
        server.healthy()?;
    }
    Ok(())
}
#[tokio::test]
async fn permission_revocation_during_final_read_prevents_dispatch() -> DomainResult<()> {
    let service = Service::new()?;
    let enabled = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(Gate::default());
    let _release = gate.release_on_drop();
    let handler = service.clone();
    let (hold, waiting) = (enabled.clone(), gate.clone());
    let server = Server::start(move |r| {
        let reply = handler.respond(r)?;
        Ok(if hold.load(Ordering::SeqCst) { reply.held(&waiting) } else { reply })
    })
    .await?;
    let client = Arc::new(client(&server)?);
    let authority = Arc::new(Authority::default());
    let baseline = observe_content(&client, &service.content()?, authority.as_ref(), deadline()).await?;
    let update = prepare_content(&baseline, settings())?;
    enabled.store(true, Ordering::SeqCst);
    let (task_client, task_authority) = (client.clone(), authority.clone());
    let task =
        tokio::spawn(async move { publish_once(&task_client, &update, task_authority.as_ref(), deadline()).await });
    gate.wait_entered().await?;
    authority.revoke();
    gate.release();
    assert!(matches!(task.await.map_err(|_| fixture_error("join failed"))?, Err(DomainError::Forbidden(_))));
    assert_eq!(server.count("PUT")?, 0);
    server.healthy()
}
#[tokio::test]
async fn received_write_with_lost_ack_stays_unknown_after_matching_independent_readback() -> DomainResult<()> {
    let service = Service::new()?;
    let handler = service.clone();
    let server = Server::start(move |r| {
        let normal = handler.respond(r)?;
        Ok(if r.method == "PUT" { Reply::truncated() } else { normal })
    })
    .await?;
    let client = client(&server)?;
    let authority = Authority::default();
    let baseline = observe_models(&client, &service.models()?, &authority, deadline()).await?;
    let update = prepare_models(&baseline, &patches())?;
    let ack = publish_once(&client, &update, &authority, deadline()).await?;
    assert_eq!(ack, WriteOutcome::Unknown);
    let current = observe_models(&client, &service.models()?, &authority, deadline()).await?;
    assert_eq!(update.compare_readback(&current), ReadbackState::Matched);
    assert_eq!(ack, WriteOutcome::Unknown);
    assert_eq!(server.count("PUT")?, 1);
    server.healthy()
}
#[tokio::test]
async fn redirect_never_forwards_signed_headers_or_content_credentials() -> DomainResult<()> {
    let other = Server::start(|_| Ok(Reply::json(200, &json!({"code":"Ok","requestId":"unexpected"})))).await?;
    let service = Service::new()?;
    let handler = service.clone();
    let location = format!("{}/not-owned", other.origin);
    let server = Server::start(move |r| {
        let normal = handler.respond(r)?;
        Ok(if r.method == "PUT" { Reply::body(307, Vec::new(), &[("Location", location.clone())]) } else { normal })
    })
    .await?;
    let client = client(&server)?;
    let authority = Authority::default();
    let baseline = observe_content(&client, &service.content()?, &authority, deadline()).await?;
    assert_eq!(
        publish_once(&client, &prepare_content(&baseline, settings())?, &authority, deadline()).await?,
        WriteOutcome::Unknown
    );
    assert_eq!(server.count("PUT")?, 1);
    assert!(other.requests()?.is_empty());
    server.healthy()?;
    other.healthy()
}
#[tokio::test]
async fn guard_wait_cannot_renew_the_original_deadline_or_dispatch() -> DomainResult<()> {
    let service = Service::new()?;
    let server = service.server().await?;
    let client = Arc::new(client(&server)?);
    let gate = Arc::new(Gate::default());
    let _release = gate.release_on_drop();
    let waiting = WaitingAuthority(gate.clone());
    let binding = service.models()?;
    let until = Instant::now() + Duration::from_millis(1500);
    let task = tokio::spawn(async move { observe_models(&client, &binding, &waiting, until).await });
    gate.wait_entered().await?;
    let outcome = timeout(Duration::from_secs(3), task)
        .await
        .map_err(|_| fixture_error("deadline ignored"))?
        .map_err(|_| fixture_error("join failed"))?;
    assert!(outcome.is_err());
    assert!(server.requests()?.is_empty());
    gate.release();
    server.healthy()
}
#[tokio::test]
async fn initially_revoked_authority_sends_no_read_or_write() -> DomainResult<()> {
    let service = Service::new()?;
    let server = service.server().await?;
    let authority = Authority::default();
    authority.revoke();
    assert!(matches!(
        observe_content(&client(&server)?, &service.content()?, &authority, deadline()).await,
        Err(DomainError::Forbidden(_))
    ));
    assert!(server.requests()?.is_empty());
    server.healthy()
}
#[tokio::test]
async fn unsuccessful_or_ambiguous_ack_is_never_success_and_is_not_retried() -> DomainResult<()> {
    for (status, body) in [
        (403, json!({"code":"Forbidden","message":"synthetic-secret-response"})),
        (200, json!({"code":"Ok"})),
        (200, json!({"code":200,"requestId":"wrong-protocol"})),
        (200, json!({"code":"Ok","requestId":"bad\nrequest"})),
        (200, json!({"code":"Ok","requestId":"oversized-ack","untrustedExtra":"x".repeat(128 * 1024)})),
    ] {
        let service = Service::new()?;
        let handler = service.clone();
        let server = Server::start(move |r| {
            let normal = handler.respond(r)?;
            Ok(if r.method == "PUT" { Reply::json(status, &body) } else { normal })
        })
        .await?;
        let client = client(&server)?;
        let authority = Authority::default();
        let baseline = observe_content(&client, &service.content()?, &authority, deadline()).await?;
        assert_eq!(
            publish_once(&client, &prepare_content(&baseline, settings())?, &authority, deadline()).await?,
            WriteOutcome::Unknown
        );
        assert_eq!(server.count("PUT")?, 1);
        server.healthy()?;
    }
    Ok(())
}

#[tokio::test]
async fn actual_signed_yaml_baseline_put_base64_yaml_and_reobserve_preserves_private_values() -> DomainResult<()> {
    let service = Service::new()?;
    let before = service.snapshot()?;
    let encoded = before["responses"]["GetPluginAttachment"]["data"]["pluginConfig"]
        .as_str()
        .ok_or_else(|| fixture_error("missing config"))?;
    let bytes = STANDARD.decode(encoded).map_err(|_| fixture_error("invalid Base64"))?;
    let config: Value = serde_json::from_slice(&bytes)?;
    let yaml = serde_yaml::to_string(&config).map_err(|_| fixture_error("synthetic YAML serialization failed"))?;
    service.mutate(|value| {
        value["responses"]["GetPluginAttachment"]["data"]["pluginConfig"] = json!(STANDARD.encode(&yaml));
    })?;
    let server = service.server().await?;
    let client = client(&server)?;
    let authority = Authority::default();
    let baseline = observe_content(&client, &service.content()?, &authority, deadline()).await?;
    let update = prepare_content(&baseline, settings())?;
    assert!(matches!(publish_once(&client, &update, &authority, deadline()).await?, WriteOutcome::Accepted { .. }));
    let current = observe_content(&client, &service.content()?, &authority, deadline()).await?;
    assert_eq!(update.compare_readback(&current), ReadbackState::Matched);
    let requests = server.requests()?;
    for request in &requests {
        verify_signature(request, &server.origin)?;
    }
    let put = requests.iter().find(|request| request.method == "PUT").ok_or_else(|| fixture_error("missing write"))?;
    let body: Value = serde_json::from_str(&put.body)?;
    let encoded = body["pluginConfig"].as_str().ok_or_else(|| fixture_error("missing config"))?;
    let written = STANDARD.decode(encoded).map_err(|_| fixture_error("invalid Base64"))?;
    let written = std::str::from_utf8(&written).map_err(|_| fixture_error("invalid UTF-8"))?;
    assert!(!written.trim_start().starts_with('{'));
    let actual: Value = serde_yaml::from_str(written).map_err(|_| fixture_error("invalid YAML"))?;
    let mut expected = config;
    expected["checkResponse"] = json!(true);
    expected["denyCode"] = json!(451);
    assert_eq!(actual, expected);
    assert_eq!(body["attachResourceIds"], json!(["api-owned"]));
    assert_eq!(server.count("GET")?, 3);
    assert_eq!(server.count("PUT")?, 1);
    assert!(!update.safe_diff().to_string().contains("synthetic-content-secret"));
    server.healthy()
}

#[tokio::test]
async fn unsafe_yaml_actual_signed_read_rejects_before_any_put_and_keeps_provider_fixture() -> DomainResult<()> {
    for raw in [
        "private: &anchor {x: 1}\ncopy: *anchor\n",
        "checkRequest: true\ncheckRequest: false\n",
        "private: !!str secret\n",
        "first: true\n---\nsecond: true\n",
    ] {
        let service = Service::new()?;
        service.mutate(|value| {
            value["responses"]["GetPluginAttachment"]["data"]["pluginConfig"] = json!(STANDARD.encode(raw));
        })?;
        let before = service.snapshot()?;
        let server = service.server().await?;
        assert!(
            observe_content(&client(&server)?, &service.content()?, &Authority::default(), deadline()).await.is_err()
        );
        for request in server.requests()? {
            verify_signature(&request, &server.origin)?;
        }
        assert_eq!(server.count("GET")?, 1);
        assert_eq!(server.count("PUT")?, 0);
        assert_eq!(service.snapshot()?, before);
        server.healthy()?;
    }
    Ok(())
}
