//! Encrypted, tenant-scoped model endpoints and reusable gateway instances.
use crate::state::AppState;
use agf_aigw::{AiGateway, provider::StaticCredentialResolver, screen::KeywordScreen};
use agf_core::{
    credential::{KeyBackend, SecretMaterial},
    enums::LlmProvider,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    model::ModelEndpoint,
};
use agf_storage::crypto::FieldCipher;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub const ENDPOINT_KIND: &str = "model-endpoint";

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredEndpoint {
    #[serde(default)]
    pub version: u64,
    pub endpoint: ModelEndpoint,
    pub secret: Option<SecretMaterial>,
}

/// Missing upstream credentials select the existing local Mock adapter; local inference stays live.
pub(crate) fn missing_upstream_key(record: &StoredEndpoint) -> bool {
    record.secret.is_none()
        && !(record.endpoint.local_deployment
            && matches!(record.endpoint.provider, LlmProvider::Ollama | LlmProvider::Vllm))
}

impl std::fmt::Debug for StoredEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredEndpoint")
            .field("id", &self.endpoint.id)
            .field("credential_configured", &self.secret.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub struct GatewayRegistry {
    entries: Mutex<BTreeMap<TenantId, (String, Arc<AiGateway>)>>,
}

pub fn cipher(state: &AppState) -> DomainResult<FieldCipher> {
    FieldCipher::from_base64(&state.config.security.master_key_b64, "agf-master", KeyBackend::LocalFile)
}

pub fn encrypt(state: &AppState, tenant: TenantId, id: Id, value: String) -> DomainResult<SecretMaterial> {
    cipher(state)?.encrypt(&SecretString::from(value), &FieldCipher::make_aad(&tenant, &id))
}

impl GatewayRegistry {
    pub async fn for_tenant(&self, state: &AppState, tenant: TenantId) -> DomainResult<Arc<AiGateway>> {
        self.for_route(state, tenant, None).await
    }

    pub async fn for_route(
        &self,
        state: &AppState,
        tenant: TenantId,
        policy: Option<&crate::store::ModelRoutePolicy>,
    ) -> DomainResult<Arc<AiGateway>> {
        let mut records: Vec<StoredEndpoint> = state.configurations.list(tenant, ENDPOINT_KIND).await?;
        if let Some(policy) = policy {
            crate::model_routes::apply(state, tenant, &mut records, policy).await?;
        }
        if records.is_empty() {
            return Err(DomainError::Config("请先在模型网关中添加至少一个可调用端点".into()));
        }
        let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&records)?));
        {
            let entries = self.entries.lock().map_err(|e| DomainError::Internal(e.to_string()))?;
            if let Some((version, gateway)) = entries.get(&tenant) {
                if version == &fingerprint {
                    return Ok(gateway.clone());
                }
            }
        }
        let mut credentials = StaticCredentialResolver::new();
        let mut endpoints = Vec::new();
        for record in records {
            let mut endpoint = record.endpoint;
            if !endpoint.enabled {
                continue;
            }
            if endpoint.tenant_id != tenant {
                return Err(DomainError::Forbidden("端点租户不匹配".into()));
            }
            if let Some(secret) = record.secret {
                let reference = endpoint.credential_ref.ok_or_else(|| DomainError::Config("缺少凭据引用".into()))?;
                let expected = FieldCipher::make_aad(&tenant, &reference);
                if secret.aad.as_deref() != Some(&expected) {
                    return Err(DomainError::Crypto("凭据绑定不匹配".into()));
                }
                let plaintext = cipher(state)?.decrypt(&secret)?;
                if plaintext.expose_secret().trim().is_empty() {
                    return Err(DomainError::Crypto("模型凭据为空或无效".into()));
                }
                credentials = if endpoint.provider == LlmProvider::Bedrock {
                    credentials
                        .with_aws(reference, crate::routes::gateway::credentials::aws(plaintext.expose_secret())?)
                } else {
                    credentials.with_key(reference, plaintext.expose_secret().to_string())
                };
            } else if endpoint.local_deployment && matches!(endpoint.provider, LlmProvider::Ollama | LlmProvider::Vllm)
            {
                // These local deployments conventionally accept any bearer value when authentication is disabled.
                endpoint.credential_ref = Some(endpoint.id);
                credentials = credentials.with_key(endpoint.id, "local-inference");
            }
            endpoints.push(endpoint);
        }
        let gateway = Arc::new(
            AiGateway::new(endpoints)
                .with_credentials(Arc::new(credentials))
                .with_meter(state.meter.clone())
                .with_screen(Arc::new(KeywordScreen::new()))
                .with_mock_mode(state.config.mock_mode),
        );
        self.entries
            .lock()
            .map_err(|e| DomainError::Internal(e.to_string()))?
            .insert(tenant, (fingerprint, gateway.clone()));
        Ok(gateway)
    }
}
