//! Tenant-scoped Agent red-team targets; credentials and protected canaries never leave the server.
use super::*;
use crate::model_gateway::{cipher, encrypt};
use agf_core::{
    credential::SecretMaterial,
    enums::AssetKind,
    ids::{Id, TenantId},
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use std::collections::BTreeMap;

const KIND: &str = "redteam-agent-targets";

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Profile {
    pub id: Id,
    pub asset_id: Id,
    pub name: String,
    pub url: String,
    pub model: String,
    pub enabled: bool,
    pub version: u64,
    pub secret: Option<SecretMaterial>,
    pub canary: SecretMaterial,
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedteamAgentProfile")
            .field("id", &self.id)
            .field("asset_id", &self.asset_id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Registry {
    entries: BTreeMap<Id, Profile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub id: Option<Id>,
    pub expected_version: u64,
    pub asset_id: Id,
    pub name: String,
    pub url: String,
    pub model: String,
    pub enabled: bool,
    pub bearer_token: Option<String>,
    pub protected_canary: Option<String>,
}

fn public(row: &Profile) -> serde_json::Value {
    serde_json::json!({"id":row.id,"asset_id":row.asset_id,"name":row.name,"url":row.url,
        "model":row.model,"enabled":row.enabled,"version":row.version,
        "credential_configured":row.secret.is_some(),"canary_configured":true,"kind":"agent-http"})
}

async fn registry(state: &AppState, tenant: TenantId) -> Result<Registry, DomainError> {
    Ok(state.configurations.get(tenant, KIND, crate::model_routes::tenant_record_id(tenant)).await?.unwrap_or_default())
}

pub(super) async fn load(state: &AppState, tenant: TenantId, id: Id) -> Result<Profile, DomainError> {
    registry(state, tenant)
        .await?
        .entries
        .remove(&id)
        .ok_or_else(|| DomainError::NotFound { entity: "redteam-agent-target", id: id.to_string() })
}

pub(super) fn unseal(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    material: &SecretMaterial,
) -> Result<String, DomainError> {
    if material.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &id)) {
        return Err(DomainError::Crypto("Red-team target credential binding mismatch".into()));
    }
    Ok(cipher(state)?.decrypt(material)?.expose_secret().to_string())
}

pub(super) async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "read")?;
    principal.require(&state, "agents", "read")?;
    let profiles = registry(&state, principal.tenant).await?;
    Ok(Json(serde_json::json!({"items":profiles.entries.values().map(public).collect::<Vec<_>>()})))
}

pub(super) async fn get(
    State(state): State<AppState>,
    principal: Principal,
    Path(raw): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "read")?;
    principal.require(&state, "agents", "read")?;
    Ok(Json(public(&load(&state, principal.tenant, parse_id(&raw, "redteam-agent-target")?).await?)))
}

pub(super) async fn save(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<Input>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "execute")?;
    principal.require(&state, "agents", "read")?;
    principal.require(&state, "agents", "write")?;
    let asset = state
        .store
        .asset_get_durable(principal.tenant, input.asset_id)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "agent-asset", id: input.asset_id.to_string() })?;
    if asset.kind != AssetKind::Agent || !asset.is_live() {
        return Err(DomainError::Validation("Red-team HTTP target must reference an active Agent asset".into()).into());
    }
    let url = url::Url::parse(&input.url).map_err(|_| DomainError::Validation("Agent target URL is invalid".into()))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || input.url.len() > 2048
        || input.name.trim().is_empty()
        || input.name.len() > 160
        || input.model.trim().is_empty()
        || input.model.len() > 160
    {
        return Err(
            DomainError::Validation("Agent target needs a name, model and credential-free HTTP(S) URL".into()).into()
        );
    }
    if input
        .bearer_token
        .as_ref()
        .is_some_and(|token| token.len() > 8192 || !token.bytes().all(|byte| (33..=126).contains(&byte)))
    {
        return Err(
            DomainError::Validation("Bearer token must be visible ASCII without spaces or newlines".into()).into()
        );
    }
    if input.protected_canary.as_ref().is_some_and(|value| {
        !(16..=128).contains(&value.len())
            || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    }) {
        return Err(
            DomainError::Validation("Protected canary must be 16–128 ASCII letters, digits, _ or -".into()).into()
        );
    }
    let id = input.id.unwrap_or_else(Id::new);
    let new_secret =
        input
            .bearer_token
            .as_ref()
            .map(|token| {
                if token.is_empty() { Ok(None) } else { encrypt(&state, principal.tenant, id, token.clone()).map(Some) }
            })
            .transpose()?;
    let new_canary = input
        .protected_canary
        .as_ref()
        .map(|value| encrypt(&state, principal.tenant, id, value.clone()))
        .transpose()?;
    let normalized_url = url.to_string();
    let apply = |saved: &mut Registry| {
        let old = saved.entries.get(&id);
        if old.map_or(0, |row| row.version) != input.expected_version {
            return Err(DomainError::Conflict("Target changed; refresh and compare before saving".into()));
        }
        if old.is_none() && saved.entries.len() >= 64 {
            return Err(DomainError::Validation("At most 64 Agent red-team targets per tenant".into()));
        }
        let moved = old.is_some_and(|row| row.url != normalized_url || row.asset_id != input.asset_id);
        if moved && old.is_some_and(|row| row.secret.is_some()) && input.bearer_token.is_none() {
            return Err(DomainError::Validation(
                "Re-enter or explicitly clear the token when changing the target".into(),
            ));
        }
        if (old.is_none() || moved) && new_canary.is_none() {
            return Err(DomainError::Validation("Set the protected canary on the selected Agent before saving".into()));
        }
        let canary = new_canary
            .clone()
            .or_else(|| old.map(|row| row.canary.clone()))
            .ok_or_else(|| DomainError::Validation("Protected canary is required".into()))?;
        let secret = new_secret.clone().unwrap_or_else(|| old.and_then(|row| row.secret.clone()));
        saved.entries.insert(
            id,
            Profile {
                id,
                asset_id: input.asset_id,
                name: input.name.trim().into(),
                url: normalized_url.clone(),
                model: input.model.trim().into(),
                enabled: input.enabled,
                version: input
                    .expected_version
                    .checked_add(1)
                    .ok_or_else(|| DomainError::Conflict("Target version limit reached".into()))?,
                secret,
                canary,
            },
        );
        Ok(())
    };
    let entry = AppState::audit_entry(
        principal.tenant,
        if input.expected_version == 0 { AuditAction::Create } else { AuditAction::Configure },
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "redteam-agent-target"),
        AuditTarget::new("redteam-agent-target", Some(id.to_string()), None),
        "Agent red-team target configuration changed",
    );
    let (saved, sealed): (Registry, _) = state
        .configurations
        .mutate_audited(
            principal.tenant,
            KIND,
            crate::model_routes::tenant_record_id(principal.tenant),
            entry.clone(),
            apply,
        )
        .await?;
    let row = saved.entries.get(&id).ok_or_else(|| DomainError::Internal("Saved target missing".into()))?;
    let view = public(row);
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(target_id=%id,%error,"Committed Agent target audit projection failed");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(Json(view))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeleteInput {
    pub expected_version: u64,
}

pub(super) async fn remove(
    State(state): State<AppState>,
    principal: Principal,
    Path(raw): Path<String>,
    ApiJson(input): ApiJson<DeleteInput>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "execute")?;
    principal.require(&state, "agents", "write")?;
    let id = parse_id(&raw, "redteam-agent-target")?;
    let apply = |registry: &mut Registry| {
        let row = registry
            .entries
            .get(&id)
            .ok_or_else(|| DomainError::NotFound { entity: "redteam-agent-target", id: id.to_string() })?;
        if row.version != input.expected_version {
            return Err(DomainError::Conflict("Target changed; refresh before removing".into()));
        }
        registry.entries.remove(&id);
        Ok(())
    };
    let entry = AppState::audit_entry(
        principal.tenant,
        AuditAction::Delete,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "redteam-agent-target"),
        AuditTarget::new("redteam-agent-target", Some(id.to_string()), None),
        "Agent red-team target configuration removed",
    );
    let (_, sealed): (Registry, _) = state
        .configurations
        .mutate_audited(
            principal.tenant,
            KIND,
            crate::model_routes::tenant_record_id(principal.tenant),
            entry.clone(),
            apply,
        )
        .await?;
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(target_id=%id,%error,"Committed Agent target deletion audit projection failed");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(Json(serde_json::json!({"deleted":true})))
}
