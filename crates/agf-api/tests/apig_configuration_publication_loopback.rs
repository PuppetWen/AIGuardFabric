//! Typed server capability reaches only an owned local HTTP provider. No real cloud/consumer.
mod apig_configuration_publication_support;
mod common;
use common::*;
#[path = "apig_configuration_publication_support/wire.rs"]
mod wire;
use agf_core::{error::DomainResult, ids::Id};
use apig_configuration_publication_support::*;
use wire::*;

#[tokio::test]
async fn typed_content_and_model_put_preserve_private_baseline_and_other_environments() -> DomainResult<()> {
    for kind in ["content", "models"] {
        let engine = Engine::new(kind).await?;
        let harness = live(kind, &engine).await?;
        let original = engine.raw()?;
        let observation = observe(&harness, false).await?;
        assert_eq!(engine.counts()?, (1, 0));
        assert_eq!(observation["target"]["transportMode"], "loopback-test");
        let prepared_preview = preview(&harness, &observation, change(kind)).await?;
        assert_eq!(engine.counts()?, (1, 0));
        let request = Id::new();
        let result = apply(&harness, &prepared_preview, request).await?;
        verified(&result);
        assert_eq!(engine.counts()?, (3, 1));
        let updated = engine.raw()?;
        if kind == "models" {
            assert_eq!(updated["deployConfigs"][1], original["deployConfigs"][1]);
            assert_eq!(updated["authConfig"], original["authConfig"]);
            for service_index in 0..2 {
                for key in ["match", "customBackend", "protocol", "serviceId", "version"] {
                    assert_eq!(
                        updated["deployConfigs"][0]["serviceConfigs"][service_index][key],
                        original["deployConfigs"][0]["serviceConfigs"][service_index][key]
                    );
                }
            }
        } else {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let decode = |attachment: &Value| -> DomainResult<Value> {
                Ok(serde_json::from_slice(
                    &STANDARD
                        .decode(attachment["pluginConfig"].as_str().unwrap_or_default())
                        .map_err(|_| agf_core::error::DomainError::Internal("owned base64".into()))?,
                )?)
            };
            let original_config = decode(&original)?;
            let updated_config = decode(&updated)?;
            for key in ["accessKey", "secretKey", "unmanaged", "denyMessage"] {
                assert_eq!(original_config[key], updated_config[key]);
            }
        }
        let before = snapshot(&harness).await?;
        get(&harness, &receipt(request)).await?;
        get(&harness, BASE).await?;
        assert_eq!(snapshot(&harness).await?, before);
        assert_eq!(engine.counts()?, (3, 1));
        assert_eq!(terminal_count(&harness, request).await?, 1);
    }
    Ok(())
}
#[tokio::test]
async fn unknown_ack_remains_unknown_after_a_new_observation_and_account_text_cannot_reset_resource_risk()
-> DomainResult<()> {
    let engine = Engine::new("content").await?;
    let harness = live("content", &engine).await?;
    let observation = observe(&harness, false).await?;
    let prepared_preview = preview(&harness, &observation, change("content")).await?;
    engine.bad_ack()?;
    let request = Id::new();
    let original = apply(&harness, &prepared_preview, request).await?;
    assert_eq!(original["status"], "uncertain");
    assert_eq!(original["cloudWrite"]["status"], "unknown");
    assert_eq!(engine.counts()?, (2, 1));
    save(&harness, 1, "content", &engine, "changed-unverified-account-text").await?;
    let fresh = observe(&harness, false).await?;
    assert_eq!(fresh["target"]["writeResourceId"], original["target"]["writeResourceId"]);
    assert_ne!(fresh["target"]["targetScopeId"], original["target"]["targetScopeId"]);
    let state = get(&harness, BASE).await?;
    let mut desired = change("content");
    desired["settings"]["denyCode"] = json!(403);
    let before = snapshot(&harness).await?;
    let rejected_preview = harness
        .post(
            &format!("{BASE}/previews"),
            json!({"request_id":Id::new(),"configuration_version":2,
        "observation_id":id(&fresh,"id")?,"expected_state_version":num(&state,"stateVersion")?,"change":desired}),
        )
        .await;
    assert_eq!(rejected_preview.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(snapshot(&harness).await?, before);
    let read = get(&harness, &receipt(request)).await?;
    assert_eq!(read["cloudWrite"], original["cloudWrite"]);
    assert_eq!(read["readback"], original["readback"]);
    assert_eq!(engine.counts()?, (3, 1));
    safe(&read);
    Ok(())
}
