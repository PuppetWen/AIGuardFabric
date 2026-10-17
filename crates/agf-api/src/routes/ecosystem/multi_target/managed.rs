//! Narrow transport/protocol approval, independent of credentials and business execution.
use super::{
    authority::Authority,
    managed_model::*,
    types::{Kind, hash},
};
use crate::{
    AppState, Principal,
    error::ApiResult,
    routes::{ApiJson, parse_id},
    store::asset_transaction::AssetTransaction,
};
use agf_asset::service::AssetBackend;
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde_json::{Value, json};

fn kind(raw: &str) -> DomainResult<Kind> {
    match raw {
        "agent-http" => Ok(Kind::AgentHttp),
        "mcp-http" => Ok(Kind::McpHttp),
        _ => Err(DomainError::Validation("Choose an Agent HTTP or MCP HTTP profile".into())),
    }
}
struct Registered {
    version: u64,
    url: String,
    asset: Id,
    raw_hash: String,
}
async fn registered(state: &AppState, tenant: TenantId, kind: Kind, id: Id) -> DomainResult<Registered> {
    let registry = super::source::registry(state, tenant, kind.registry()).await?;
    let raw = registry["entries"]
        .get(id.to_string())
        .ok_or_else(|| DomainError::NotFound { entity: "registered target profile", id: id.to_string() })?;
    let (saved, version, enabled, url, asset) = match kind {
        Kind::AgentHttp => {
            let row: super::super::agent_targets::Profile =
                serde_json::from_value(raw.clone()).map_err(|_| super::records::corrupt())?;
            (row.id, row.version, row.enabled, row.url, row.asset_id)
        }
        Kind::McpHttp => {
            let row: super::super::mcp_targets::Profile =
                serde_json::from_value(raw.clone()).map_err(|_| super::records::corrupt())?;
            (row.id, row.version, row.enabled, row.url, row.asset_id)
        }
    };
    if saved != id || version == 0 || !enabled {
        return Err(DomainError::Conflict("Registered profile is inactive or corrupt".into()));
    }
    let live = state.store.asset_get_durable(tenant, asset).await?.ok_or_else(super::records::corrupt)?;
    if live.kind != kind.asset() || !live.is_live() {
        return Err(DomainError::Conflict("Registered target asset is inactive".into()));
    }
    Ok(Registered { version, url, asset, raw_hash: hash(raw)? })
}
async fn locked(
    tx: &AssetTransaction<'_>,
    tenant: TenantId,
    kind: Kind,
    id: Id,
    original: &Registered,
) -> DomainResult<()> {
    let key = crate::model_routes::tenant_record_id(tenant);
    tx.configuration_lock(kind.registry(), key).await?;
    let registry = tx.multi_target_registry(kind.registry(), key).await?.ok_or_else(super::records::corrupt)?;
    let raw = registry["entries"].get(id.to_string()).ok_or_else(super::records::corrupt)?;
    let active =
        tx.find(tenant, original.asset).await?.is_some_and(|asset| asset.kind == kind.asset() && asset.is_live());
    if !active || hash(raw)? != original.raw_hash {
        return Err(DomainError::Conflict("Registered target changed before approval publication".into()));
    }
    Ok(())
}
pub(super) async fn get(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path((raw_kind, raw_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let authority = Authority::capture(&state, principal, &headers, false)?;
    let value = Box::pin(authority.within(async {
        authority.admin(&state).await?;
        let kind = kind(&raw_kind)?;
        let id = parse_id(&raw_id, "registered-target-profile").map_err(|error| error.error)?;
        let current = registered(&state, authority.principal.tenant, kind, id).await?;
        let saved = read(&state, authority.principal.tenant, kind, id).await?;
        let control =
            saved.as_ref().map(|row| restore(&state, authority.principal.tenant, kind, id, row)).transpose()?;
        authority.admin(&state).await?;
        Ok(json!({
            "configured": control.is_some(),
            "profileId": id,
            "profileVersion": current.version,
            "url": current.url,
            "version": control.as_ref().map_or(0, |row| row.version),
            "settings": control.as_ref().map(Control::view),
            "defaultPrivateAccess": false,
            "defaultMcpProtocolRevision": "2026-07-28",
            "supportedMcpProtocolRevisions": ["2026-07-28", "2025-11-25"],
            "requiresDurableDatabase": true,
            "businessDispatched": false
        }))
    }))
    .await?;
    Ok(Json(value))
}
pub(super) async fn save(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path((raw_kind, raw_id)): Path<(String, String)>,
    ApiJson(input): ApiJson<Input>,
) -> ApiResult<Json<Value>> {
    let authority = Authority::capture(&state, principal, &headers, false)?;
    let value = Box::pin(authority.within(async {
        authority.admin(&state).await?;
        let kind = kind(&raw_kind)?;
        let profile = parse_id(&raw_id, "registered-target-profile").map_err(|error| error.error)?;

        if kind == Kind::AgentHttp && input.mcp_protocol_revision != super::mcp::Revision::Modern {
            return Err(invalid());
        }
        let tenant = authority.principal.tenant;
        let original = registered(&state, tenant, kind, profile).await?;
        let registered_version = original.version;
        if input.profile_version != registered_version || input.url != original.url {
            return Err(DomainError::Conflict("Review the actual registered profile version and exact URL".into()));
        }

        let private = match input.private_network {
            Some(private) => {
                if !private.confirm_exact_private_network {
                    return Err(invalid());
                }
                Some(PrivateNetwork {
                    addresses: private.addresses,
                    port: private.port,
                    allow_plain_http: private.allow_plain_http,
                })
            }
            None => None,
        };
        let database = state
            .store
            .database()
            .ok_or_else(|| DomainError::PreconditionFailed("Managed transport approval requires durable SQL".into()))?;

        let tx = AssetTransaction::begin(database, tenant).await?;
        tx.tenant_enabled().await?;
        authority.admin(&state).await?;
        locked(&tx, tenant, kind, profile, &original).await?;
        let id = key(tenant, kind, profile);
        tx.configuration_lock(KIND, id).await?;
        let old = tx
            .configuration::<Envelope>(KIND, id)
            .await?
            .map(|row| restore(&state, tenant, kind, profile, &row))
            .transpose()?;

        if old.as_ref().map_or(0, |row| row.version) != input.expected_version {
            return Err(DomainError::Conflict(
                "Managed transport approval changed; review and explicitly adopt its current version".into(),
            ));
        }

        let row = Control {
            tenant,
            id,
            kind,
            profile,
            profile_version: original.version,
            version: input.expected_version.checked_add(1).ok_or_else(super::records::corrupt)?,

            url: original.url.clone(),
            enabled: input.enabled,
            revision: input.mcp_protocol_revision,
            private,
        };
        row.validate(tenant, kind, profile)?;
        if row.private.is_none() {
            super::transport::mode(&state, tenant, profile, &row.url)?;
        }
        let sealed = serde_json::to_value(seal(&state, &row)?)?;
        if serde_json::to_vec(&sealed)?.len() > 16 * 1024 {
            return Err(invalid());
        }
        let mut audit = AppState::audit_entry(
            tenant,
            AuditAction::Configure,
            AuditOutcome::Success,
            AppState::audit_actor(&authority.principal, "redteam-managed-target-profile"),
            AuditTarget::new(KIND, Some(profile.to_string()), None),
            "Explicit current profile protocol/network approval; no target request sent",
        );

        audit.before = old.as_ref().map(|old| json!({"version":old.version,"enabled":old.enabled}));
        audit.after = Some(json!({
            "version": row.version,
            "enabled": row.enabled,
            "profileVersion": row.profile_version,
            "urlSha256": hash(&row.url)?,
            "networkSha256": hash(&row.private)?,
            "mcpProtocolRevision": row.revision,
            "businessDispatched": false
        }));

        tx.configure(KIND, id, Some(sealed)).await?;
        tx.audit(audit).await?;
        authority.admin(&state).await?;
        locked(&tx, tenant, kind, profile, &original).await?;
        tx.commit(&state.store).await?;
        Ok(row.view())
    }))
    .await?;
    Ok(Json(value))
}
