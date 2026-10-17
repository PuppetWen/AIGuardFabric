//! Credential checks prepare inert clients only; no embedding request or paid component is sent.
use super::{configuration::Mode, endpoint, plan, tests::settings};
use crate::{AppState, model_gateway::StoredEndpoint};
use agf_core::{
    enums::{DataClass, LlmProvider},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    model::{Modality, ModelEndpoint, ModelPricing},
    time::Timestamp,
};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

const OWNED_KEY: &str = "owned-embedding-credential-not-a-provider-key";

fn fixture() -> DomainResult<(AppState, super::configuration::Settings, StoredEndpoint)> {
    let mut environment: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_JWT_SECRET", "semantic-profile-crypto-unit-secret-at-least-32-bytes"),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
        ("AGF_PROJECT_ROOT", "."),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    let data = std::env::var_os("AGF_TEST_DATA_DIR").map_or_else(
        || std::path::PathBuf::from("./target/test-data/semantic-profile-crypto-unit"),
        |root| std::path::PathBuf::from(root).join("semantic-profile-crypto-unit"),
    );
    environment.insert("AGF_DATA_DIR".into(), data.to_string_lossy().into_owned());
    let state = AppState::offline(agf_core::config::from_env_map(&environment)?)?;
    let tenant = TenantId::default_tenant();
    let settings = settings(Mode::Live);
    let reference = Id::new();
    let timestamp = Timestamp::now();
    let row = StoredEndpoint {
        version: 1,
        endpoint: ModelEndpoint {
            id: settings.embedding_endpoint_id,
            tenant_id: tenant,
            asset_id: Id::new(),
            name: "owned embedding fixture".into(),
            provider: LlmProvider::OpenAi,
            base_url: "https://embedding.example.test/v1".into(),
            model: settings.embedding_model.clone(),
            modalities: vec![Modality::Embedding],
            context_window: None,
            max_output_tokens: None,
            supports_streaming: false,
            supports_tools: false,
            credential_ref: Some(reference),
            local_deployment: false,
            max_data_class: DataClass::Public,
            pricing: ModelPricing::default(),
            enabled: true,
            fallback: false,
            priority: 1,
            extra_headers: BTreeMap::new(),
            created_at: timestamp,
            updated_at: timestamp,
        },
        secret: Some(crate::model_gateway::encrypt(&state, tenant, reference, OWNED_KEY.into())?),
    };
    Ok((state, settings, row))
}

async fn no_endpoint_write(state: &AppState) -> DomainResult<()> {
    assert!(
        state
            .configurations
            .list::<Value>(TenantId::default_tenant(), crate::model_gateway::ENDPOINT_KIND)
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn valid_encrypted_endpoint_prepares_inert_client_without_exposing_key() -> DomainResult<()> {
    let (state, settings, row) = fixture()?;
    let preparation = plan::embedding_plan(&state, TenantId::default_tenant(), &settings, &row, "owned request")?;
    let plan::EmbeddingPreparation::Ready(plan::EmbeddingPlan::Live(client)) = preparation else {
        return Err(DomainError::Internal("Expected live preparation".into()));
    };
    assert_eq!(client.configuration.configuration_version, 1);
    assert_eq!(client.input_tokens_bound, 8192);
    assert_eq!(client.estimated_cost_micro, 8192);
    assert!(!format!("{:?}", client.client).contains(OWNED_KEY));
    no_endpoint_write(&state).await
}

#[tokio::test]
async fn foreign_tenant_or_credential_aad_propagates_crypto_through_plan() -> DomainResult<()> {
    let (state, settings, row) = fixture()?;
    let reference = row.endpoint.credential_ref.ok_or_else(super::util::corrupt)?;
    for (tenant, credential) in [(TenantId::new(), reference), (TenantId::default_tenant(), Id::new())] {
        let mut moved = row.clone();
        moved.secret = Some(crate::model_gateway::encrypt(&state, tenant, credential, OWNED_KEY.into())?);
        assert!(matches!(
            plan::embedding_plan(&state, TenantId::default_tenant(), &settings, &moved, "owned request"),
            Err(DomainError::Crypto(_))
        ));
    }
    no_endpoint_write(&state).await
}

#[tokio::test]
async fn ciphertext_tag_or_key_identity_corruption_never_becomes_profile_unavailable() -> DomainResult<()> {
    let (state, settings, row) = fixture()?;
    for field in ["ciphertext", "tag", "key"] {
        let mut corrupt = row.clone();
        let secret = corrupt.secret.as_mut().ok_or_else(super::util::corrupt)?;
        match field {
            "ciphertext" => secret.ciphertext_b64 = "not-base64".into(),
            "tag" => secret.tag_b64 = Some("AAAAAAAAAAAAAAAAAAAAAA==".into()),
            _ => secret.key_id = "different-key-id".into(),
        }
        assert!(matches!(
            plan::embedding_plan(&state, TenantId::default_tenant(), &settings, &corrupt, "owned request"),
            Err(DomainError::Crypto(_))
        ));
    }
    no_endpoint_write(&state).await
}

#[tokio::test]
async fn actual_cipher_setup_failure_remains_crypto_instead_of_legacy_bypass() -> DomainResult<()> {
    let (mut state, settings, row) = fixture()?;
    let mut configuration = (*state.config).clone();
    configuration.security.master_key_b64 = "invalid-master-key".into();
    state.config = Arc::new(configuration);
    assert!(matches!(
        plan::embedding_plan(&state, TenantId::default_tenant(), &settings, &row, "owned request"),
        Err(DomainError::Crypto(_))
    ));
    no_endpoint_write(&state).await
}

#[tokio::test]
async fn authenticated_but_invalid_plaintext_key_is_a_fixed_crypto_error() -> DomainResult<()> {
    let (state, settings, mut row) = fixture()?;
    let reference = row.endpoint.credential_ref.ok_or_else(super::util::corrupt)?;
    row.secret = Some(crate::model_gateway::encrypt(
        &state,
        TenantId::default_tenant(),
        reference,
        "invalid credential\n".into(),
    )?);
    let error = match plan::embedding_plan(&state, TenantId::default_tenant(), &settings, &row, "owned request") {
        Err(error) => error,
        Ok(_) => return Err(DomainError::Internal("Expected credential rejection".into())),
    };
    assert!(matches!(error, DomainError::Crypto(_)));
    assert!(!error.to_string().contains("invalid credential"));
    no_endpoint_write(&state).await
}

#[tokio::test]
async fn unavailable_configuration_uses_explicit_verdict_without_swallowing_identity_errors() -> DomainResult<()> {
    let (state, settings, row) = fixture()?;
    let mut missing = row.clone();
    missing.secret = None;
    assert!(matches!(
        endpoint::client(&state, TenantId::default_tenant(), &settings, &missing)?,
        endpoint::ClientPreparation::Unavailable
    ));
    let mut unsupported = row.clone();
    unsupported.endpoint.base_url = "https://embedding.example.test/custom-prefix".into();
    assert!(matches!(
        endpoint::client(&state, TenantId::default_tenant(), &settings, &unsupported)?,
        endpoint::ClientPreparation::Unavailable
    ));
    let mut foreign = row.clone();
    foreign.endpoint.id = Id::new();
    assert!(matches!(
        endpoint::client(&state, TenantId::default_tenant(), &settings, &foreign),
        Err(DomainError::Crypto(_))
    ));
    assert!(matches!(
        plan::embedding_plan(&state, TenantId::default_tenant(), &settings, &row, &"x".repeat(8193))?,
        plan::EmbeddingPreparation::Unavailable
    ));
    no_endpoint_write(&state).await
}
