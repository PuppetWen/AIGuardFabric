use super::{
    configuration::{Mode, Settings},
    util,
};
use crate::{AppState, model_gateway::StoredEndpoint};
use agf_aigw::provider::embedding::{EmbeddingClient, EmbeddingConfiguration, EmbeddingFailure, EmbeddingProfile};
use agf_core::{
    enums::LlmProvider,
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use agf_storage::crypto::FieldCipher;

pub(super) fn validate(
    state: &AppState,
    tenant: TenantId,
    settings: &Settings,
    chat: &StoredEndpoint,
    embedding: &StoredEndpoint,
) -> DomainResult<()> {
    settings.validate()?;
    for (row, id, model) in [
        (chat, settings.chat_endpoint_id, &settings.chat_model),
        (embedding, settings.embedding_endpoint_id, &settings.embedding_model),
    ] {
        if row.version == 0
            || row.endpoint.tenant_id != tenant
            || row.endpoint.id != id
            || !row.endpoint.enabled
            || row.endpoint.model != *model
        {
            return Err(util::stale());
        }
    }
    match settings.mode {
        Mode::MockVector => {
            if chat.endpoint.provider != LlmProvider::Mock || embedding.endpoint.provider != LlmProvider::Mock {
                return Err(util::invalid());
            }
        }
        Mode::Live => {
            if chat.endpoint.provider == LlmProvider::Mock
                || !embedding.endpoint.extra_headers.is_empty()
                || !matches!(embedding.endpoint.provider, LlmProvider::OpenAi | LlmProvider::CustomOpenAiCompat)
                || embedding.secret.is_none()
                || embedding.endpoint.credential_ref.is_none()
            {
                return Err(util::invalid());
            }
            service_origin(state, tenant, embedding)?;
        }
    }
    Ok(())
}

pub(super) fn configuration(
    state: &AppState,
    tenant: TenantId,
    settings: &Settings,
    row: &StoredEndpoint,
) -> DomainResult<EmbeddingConfiguration> {
    Ok(EmbeddingConfiguration {
        tenant_id: tenant,
        endpoint_id: row.endpoint.id,
        configuration_version: row.version,
        provider: row.endpoint.provider.as_str().into(),
        origin: service_origin(state, tenant, row)?,
        model: settings.embedding_model.clone(),
        model_revision: settings.embedding_model_revision.clone(),
        dimensions: settings.dimensions,
        send_dimensions: settings.send_dimensions,
        max_input_tokens: settings.max_input_tokens,
        input_micro_per_1k: settings.embedding_micro_per_1k,
    })
}

/// Configuration unavailability is distinct from authenticated credential failures.
pub(super) enum ClientPreparation {
    Unavailable,
    Ready(Box<(EmbeddingConfiguration, EmbeddingClient)>),
}

pub(super) fn client(
    state: &AppState,
    tenant: TenantId,
    settings: &Settings,
    row: &StoredEndpoint,
) -> DomainResult<ClientPreparation> {
    if (row.endpoint.tenant_id, row.endpoint.id) != (tenant, settings.embedding_endpoint_id) {
        return Err(DomainError::Crypto("Semantic endpoint identity mismatch".into()));
    }
    let (Some(reference), Some(secret)) = (row.endpoint.credential_ref, row.secret.as_ref()) else {
        return Ok(ClientPreparation::Unavailable);
    };
    let aad = FieldCipher::make_aad(&tenant, &reference);
    if reference.is_nil() || secret.aad.as_deref() != Some(aad.as_str()) {
        return Err(DomainError::Crypto("Semantic credential identity mismatch".into()));
    }
    if row.version == 0 || !row.endpoint.enabled || row.endpoint.model != settings.embedding_model {
        return Ok(ClientPreparation::Unavailable);
    }
    let configuration = match configuration(state, tenant, settings, row) {
        Ok(configuration) => configuration,
        Err(DomainError::Validation(_)) => return Ok(ClientPreparation::Unavailable),
        Err(error) => return Err(error),
    };
    let profile = match service_profile(state, configuration.clone()) {
        Ok(profile) => profile,
        Err(EmbeddingFailure::Configuration) => return Ok(ClientPreparation::Unavailable),
        Err(_) => return Err(DomainError::Config("Embedding profile preparation failed".into())),
    };
    let cipher = crate::model_gateway::cipher(state)?;
    let value = cipher.decrypt(secret)?;
    use secrecy::ExposeSecret as _;
    let client =
        EmbeddingClient::from_service_profile(profile, value.expose_secret()).map_err(|failure| match failure {
            EmbeddingFailure::Credentials => DomainError::Crypto("Embedding credential is invalid".into()),
            _ => DomainError::Config("Embedding client preparation failed".into()),
        })?;
    Ok(ClientPreparation::Ready(Box::new((configuration, client))))
}

/// Map only an exact existing OpenAI root or /v1 base to its fixed embedding origin.
/// This does not accept a request URL, path prefix or endpoint supplied by the chat client.
pub(super) fn origin(raw: &str) -> DomainResult<String> {
    if raw.is_empty()
        || raw.len() > 2048
        || raw.trim() != raw
        || raw.contains(['@', '\\', '%', '?', '#'])
        || raw.bytes().any(|byte| byte.is_ascii_control())
        || raw.split('/').any(|segment| matches!(segment, "." | ".."))
    {
        return Err(util::invalid());
    }
    let url = reqwest::Url::parse(raw).map_err(|_| util::invalid())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "/" | "/v1" | "/v1/")
    {
        return Err(util::invalid());
    }
    Ok(url.origin().ascii_serialization())
}

// Normal builds have no capability field or HTTP constructor.
fn service_origin(state: &AppState, tenant: TenantId, row: &StoredEndpoint) -> DomainResult<String> {
    #[cfg(feature = "test-loopback-transport")]
    if let Some(origin) = state
        .gateway_test_transport
        .as_ref()
        .and_then(|capability| capability.origin(tenant, row.endpoint.id, &row.endpoint.base_url))
    {
        return Ok(origin);
    }
    let _ = (state, tenant);
    origin(&row.endpoint.base_url)
}
fn service_profile(
    state: &AppState,
    configuration: EmbeddingConfiguration,
) -> Result<EmbeddingProfile, EmbeddingFailure> {
    #[cfg(feature = "test-loopback-transport")]
    if let Some(capability) = state.gateway_test_transport.as_ref().filter(|capability| {
        capability.origin(configuration.tenant_id, configuration.endpoint_id, &configuration.origin).is_some()
    }) {
        return capability.profile(configuration);
    }
    let _ = state;
    EmbeddingProfile::from_server_configuration(configuration)
}
pub(super) fn transport_mode(state: &AppState, tenant: TenantId, row: &StoredEndpoint) -> &'static str {
    #[cfg(feature = "test-loopback-transport")]
    if state
        .gateway_test_transport
        .as_ref()
        .is_some_and(|capability| capability.origin(tenant, row.endpoint.id, &row.endpoint.base_url).is_some())
    {
        return "test-loopback";
    }
    let _ = (state, tenant, row);
    "live"
}
