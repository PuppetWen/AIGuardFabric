//! Tenant-scoped MCP red-team targets; secrets are bound to profile IDs and never listed.
use super::*;
use crate::model_gateway::encrypt;
use agf_core::{
    credential::SecretMaterial,
    enums::AssetKind,
    ids::{Id, TenantId},
};
use agf_scan::redteam::McpHttpTarget;
use std::collections::BTreeMap;

const KIND: &str = "redteam-mcp-targets";

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Profile {
    pub id: Id,
    pub asset_id: Id,
    pub name: String,
    pub url: String,
    pub tool_name: String,
    pub argument_name: String,
    #[serde(default)]
    pub detail_tool_name: Option<String>,
    #[serde(default)]
    pub detail_argument_name: Option<String>,
    pub enabled: bool,
    pub version: u64,
    pub secret: Option<SecretMaterial>,
    pub canary: SecretMaterial,
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
    pub tool_name: String,
    pub argument_name: String,
    pub detail_tool_name: Option<String>,
    pub detail_argument_name: Option<String>,
    pub enabled: bool,
    pub bearer_token: Option<String>,
    pub protected_canary: Option<String>,
}

fn public(row: &Profile) -> serde_json::Value {
    serde_json::json!({"id":row.id,"asset_id":row.asset_id,"name":row.name,"url":row.url,
        "tool_name":row.tool_name,"argument_name":row.argument_name,"enabled":row.enabled,
        "detail_tool_name":row.detail_tool_name,"detail_argument_name":row.detail_argument_name,
        "version":row.version,"credential_configured":row.secret.is_some(),
        "canary_configured":true,"kind":"mcp-http"})
}

async fn registry(state: &AppState, tenant: TenantId) -> Result<Registry, DomainError> {
    Ok(state.configurations.get(tenant, KIND, crate::model_routes::tenant_record_id(tenant)).await?.unwrap_or_default())
}

pub(super) async fn load(state: &AppState, tenant: TenantId, id: Id) -> Result<Profile, DomainError> {
    registry(state, tenant)
        .await?
        .entries
        .remove(&id)
        .ok_or_else(|| DomainError::NotFound { entity: "redteam-mcp-target", id: id.to_string() })
}

pub(super) async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "read")?;
    principal.require(&state, "mcps", "read")?;
    let profiles = registry(&state, principal.tenant).await?;
    Ok(Json(serde_json::json!({"items":profiles.entries.values().map(public).collect::<Vec<_>>()})))
}

pub(super) async fn get(
    State(state): State<AppState>,
    principal: Principal,
    Path(raw): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "read")?;
    principal.require(&state, "mcps", "read")?;
    Ok(Json(public(&load(&state, principal.tenant, parse_id(&raw, "redteam-mcp-target")?).await?)))
}

pub(super) async fn usage(
    State(state): State<AppState>,
    principal: Principal,
    Path(raw): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "read")?;
    principal.require(&state, "mcps", "read")?;
    let id = parse_id(&raw, "redteam-mcp-target")?;
    load(&state, principal.tenant, id).await?;
    let mut snapshot = crate::mcp_gateway::usage::redteam_snapshot(&state, principal.tenant, id).await?;
    if let Some(object) = snapshot.as_object_mut() {
        object.remove("endpoint_id");
        object.insert("source".into(), serde_json::json!("redteam-mcp"));
        object.insert("target_profile_id".into(), serde_json::json!(id));
    }
    Ok(Json(snapshot))
}

pub(super) async fn save(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<Input>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "execute")?;
    principal.require(&state, "mcps", "read")?;
    principal.require(&state, "mcps", "write")?;
    let asset = state
        .store
        .asset_get_durable(principal.tenant, input.asset_id)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "mcp-asset", id: input.asset_id.to_string() })?;
    if asset.kind != AssetKind::McpServer || !asset.is_live() {
        return Err(DomainError::Validation("MCP target must reference an active MCP Server asset".into()).into());
    }
    // Use the same validator as the executor, with a disposable valid canary.
    let validated = McpHttpTarget::new(
        input.name.clone(),
        input.asset_id,
        &input.url,
        input.tool_name.clone(),
        input.argument_name.clone(),
        None,
        "MCP_VALIDATION_CANARY_123".into(),
    )?;
    match (&input.detail_tool_name, &input.detail_argument_name) {
        (Some(tool), Some(argument)) => {
            validated.with_detail_tool(tool.clone(), argument.clone())?;
        }
        (None, None) => {}
        _ => return Err(DomainError::Validation("Set both MCP detail tool and argument, or neither".into()).into()),
    }
    if input
        .bearer_token
        .as_ref()
        .is_some_and(|value| value.len() > 8192 || !value.bytes().all(|byte| (33..=126).contains(&byte)))
        || input.protected_canary.as_ref().is_some_and(|value| {
            !(16..=128).contains(&value.len())
                || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
    {
        return Err(DomainError::Validation("MCP target secret or canary format is invalid".into()).into());
    }
    let id = input.id.unwrap_or_else(Id::new);
    let new_secret =
        input
            .bearer_token
            .as_ref()
            .map(|value| {
                if value.is_empty() { Ok(None) } else { encrypt(&state, principal.tenant, id, value.clone()).map(Some) }
            })
            .transpose()?;
    let new_canary = input
        .protected_canary
        .as_ref()
        .map(|value| encrypt(&state, principal.tenant, id, value.clone()))
        .transpose()?;
    let normalized_url = url::Url::parse(&input.url)
        .map_err(|_| DomainError::Validation("MCP target URL is invalid".into()))?
        .to_string();
    let apply = |saved: &mut Registry| {
        let old = saved.entries.get(&id);
        if old.map_or(0, |row| row.version) != input.expected_version {
            return Err(DomainError::Conflict("MCP target changed; refresh before saving".into()));
        }
        if old.is_none() && saved.entries.len() >= 64 {
            return Err(DomainError::Validation("At most 64 MCP red-team targets per tenant".into()));
        }
        let moved = old.is_some_and(|row| {
            row.url != normalized_url
                || row.asset_id != input.asset_id
                || row.tool_name != input.tool_name
                || row.argument_name != input.argument_name
                || row.detail_tool_name != input.detail_tool_name
                || row.detail_argument_name != input.detail_argument_name
        });
        if moved && old.is_some_and(|row| row.secret.is_some()) && input.bearer_token.is_none() {
            return Err(DomainError::Validation(
                "Re-enter or explicitly clear the token when changing the MCP target".into(),
            ));
        }
        if (old.is_none() || moved) && new_canary.is_none() {
            return Err(DomainError::Validation("Set the protected canary on this target before saving".into()));
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
                tool_name: input.tool_name.clone(),
                argument_name: input.argument_name.clone(),
                detail_tool_name: input.detail_tool_name.clone(),
                detail_argument_name: input.detail_argument_name.clone(),
                enabled: input.enabled,
                version: input
                    .expected_version
                    .checked_add(1)
                    .ok_or_else(|| DomainError::Conflict("MCP target version limit reached".into()))?,
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
        AppState::audit_actor(&principal, "redteam-mcp-target"),
        AuditTarget::new("redteam-mcp-target", Some(id.to_string()), None),
        "MCP red-team target configuration changed",
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
    let row = saved.entries.get(&id).ok_or_else(|| DomainError::Internal("Saved MCP target missing".into()))?;
    let view = public(row);
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(target_id=%id,%error,"Committed MCP target audit projection failed");
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
    principal.require(&state, "mcps", "write")?;
    let id = parse_id(&raw, "redteam-mcp-target")?;
    let apply = |saved: &mut Registry| {
        let row = saved
            .entries
            .get(&id)
            .ok_or_else(|| DomainError::NotFound { entity: "redteam-mcp-target", id: id.to_string() })?;
        if row.version != input.expected_version {
            return Err(DomainError::Conflict("MCP target changed; refresh before removing".into()));
        }
        saved.entries.remove(&id);
        Ok(())
    };
    let entry = AppState::audit_entry(
        principal.tenant,
        AuditAction::Delete,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "redteam-mcp-target"),
        AuditTarget::new("redteam-mcp-target", Some(id.to_string()), None),
        "MCP red-team target configuration removed",
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
            tracing::warn!(target_id=%id,%error,"Committed MCP target deletion audit projection failed");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(Json(serde_json::json!({"deleted":true})))
}
