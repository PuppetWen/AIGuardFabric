use super::types::{Kind, Selection, Target, hash, validate};
use crate::{AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use agf_storage::configuration::BoundedConfigurationList;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) struct Loaded {
    pub target: Target,
    pub url: String,
    pub model_or_tool: String,
    pub argument: Option<String>,
    pub secret: Option<String>,
    pub canary: String,
    pub mcp_revision: super::mcp::Revision,
    pub private_network: Option<super::managed_model::PrivateNetwork>,
}
pub(super) async fn registry(state: &AppState, tenant: TenantId, kind: &str) -> DomainResult<Value> {
    match state.configurations.list_bounded::<Value>(tenant, kind, 1, 512 * 1024).await? {
        BoundedConfigurationList::Complete(mut rows) if rows.len() == 1 => Ok(rows.remove(0)),
        BoundedConfigurationList::Complete(_) => {
            Err(DomainError::NotFound { entity: "registered redteam targets", id: kind.into() })
        }
        _ => Err(DomainError::PreconditionFailed("Registered target evidence exceeds its budget".into())),
    }
}
pub(super) async fn capture(state: &AppState, tenant: TenantId, inputs: &[Selection]) -> DomainResult<Vec<Loaded>> {
    validate(inputs)?;
    let mut registries = BTreeMap::new();
    for kind in ["redteam-agent-targets", "redteam-mcp-targets"] {
        registries.insert(kind, registry(state, tenant, kind).await?);
    }
    let mut out = Vec::new();
    for input in inputs {
        let saved = registries.get(input.kind.registry()).ok_or_else(corrupt)?;
        let raw = saved["entries"].get(input.profile_id.to_string()).cloned().ok_or_else(|| DomainError::NotFound {
            entity: "registered redteam target",
            id: input.profile_id.to_string(),
        })?;
        let (id, asset, version, enabled, url, model_or_tool, argument, secret, canary) = match input.kind {
            Kind::AgentHttp => {
                let p: super::super::agent_targets::Profile =
                    serde_json::from_value(raw.clone()).map_err(|_| corrupt())?;
                (p.id, p.asset_id, p.version, p.enabled, p.url, p.model, None, p.secret, p.canary)
            }
            Kind::McpHttp => {
                let p: super::super::mcp_targets::Profile =
                    serde_json::from_value(raw.clone()).map_err(|_| corrupt())?;
                (p.id, p.asset_id, p.version, p.enabled, p.url, p.tool_name, Some(p.argument_name), p.secret, p.canary)
            }
        };
        if id != input.profile_id || !enabled || version != input.expected_version {
            return Err(DomainError::Conflict("Registered target changed or is disabled".into()));
        }
        let live = state.store.asset_get_durable(tenant, asset).await?.ok_or_else(corrupt)?;
        if live.kind != input.kind.asset() || !live.is_live() {
            return Err(DomainError::Conflict("Target asset is inactive or has a different kind".into()));
        }
        let managed = super::managed_model::read(state, tenant, input.kind, id).await?;
        let control = managed
            .as_ref()
            .map(|row| super::managed_model::restore(state, tenant, input.kind, id, row))
            .transpose()?;
        if control
            .as_ref()
            .is_some_and(|control| !control.enabled || control.profile_version != version || control.url != url)
        {
            return Err(DomainError::Conflict(
                "Managed transport approval changed, is disabled or belongs to a different profile version/URL".into(),
            ));
        }
        let private_network = control.as_ref().and_then(|control| control.private.clone());
        let mcp_revision = control.as_ref().map_or(super::mcp::Revision::Modern, |control| control.revision);
        let transport_mode = super::transport::mode_approved(state, tenant, id, &url, private_network.as_ref())?;
        let secret = secret.as_ref().map(|value| unseal(state, tenant, id, value)).transpose()?;
        let canary = unseal(state, tenant, id, &canary)?;
        if !(16..=128).contains(&canary.len())
            || !canary.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
            || model_or_tool.is_empty()
            || model_or_tool.len() > 160
            || argument.as_ref().is_some_and(|arg| arg.is_empty() || arg.len() > 160)
            || secret
                .as_ref()
                .is_some_and(|value| value.len() > 8192 || !value.bytes().all(|c| (33..=126).contains(&c)))
        {
            return Err(corrupt());
        }
        out.push(Loaded {
            target: Target {
                kind: input.kind,
                profile_id: id,
                version,
                asset_id: asset,
                profile_sha256: hash(&raw)?,
                registry_sha256: hash(saved)?,
                transport_mode,
                managed_profile_version: control.as_ref().map(|control| control.version),
                managed_profile_sha256: super::managed_model::fingerprint(managed.as_ref())?,
                mcp_protocol_revision: (input.kind == Kind::McpHttp).then_some(mcp_revision),
            },
            url,
            model_or_tool,
            argument,
            secret,
            canary,
            mcp_revision,
            private_network,
        });
    }
    if out[0].target.asset_id == out[2].target.asset_id {
        return Err(DomainError::Validation("Select two different registered Agent assets".into()));
    }
    Ok(out)
}
fn unseal(state: &AppState, tenant: TenantId, id: agf_core::ids::Id, value: &SecretMaterial) -> DomainResult<String> {
    // The existing target decoder checks exact tenant/profile AAD and never logs the value.
    super::super::agent_targets::unseal(state, tenant, id, value)
}
pub(super) async fn locked(
    tx: &AssetTransaction<'_>,
    tenant: TenantId,
    targets: &[Target],
    strict: bool,
) -> DomainResult<bool> {
    use agf_asset::service::AssetBackend;
    let id = crate::model_routes::tenant_record_id(tenant);
    let mut rows = BTreeMap::new();
    for kind in ["redteam-agent-targets", "redteam-mcp-targets"] {
        tx.configuration_lock(kind, id).await?;
        let row = tx.multi_target_registry(kind, id).await?;
        rows.insert(kind, row);
    }
    let mut current = true;
    for target in targets {
        let active = tx
            .find(tenant, target.asset_id)
            .await?
            .is_some_and(|asset| asset.kind == target.kind.asset() && asset.is_live());
        current &= active;
        let row = rows.get(target.kind.registry()).and_then(Option::as_ref);
        let same = match row {
            Some(row) => hash(row)? == target.registry_sha256,
            None => false,
        };
        current &= same;
        let id = super::managed_model::key(tenant, target.kind, target.profile_id);
        tx.configuration_lock(super::managed_model::KIND, id).await?;
        let managed = tx.configuration::<super::managed_model::Envelope>(super::managed_model::KIND, id).await?;
        current &= super::managed_model::fingerprint(managed.as_ref())? == target.managed_profile_sha256;
    }
    if strict && !current {
        return Err(DomainError::Conflict("Registered targets changed; no new outbound step is permitted".into()));
    }
    Ok(current)
}
fn corrupt() -> DomainError {
    DomainError::Crypto("Registered target identity/evidence is invalid".into())
}
/// Read-only metadata; historical receipts never decrypt present-day credentials.
pub(super) async fn current_metadata(state: &AppState, tenant: TenantId, targets: &[Target]) -> DomainResult<bool> {
    let mut rows = BTreeMap::new();
    for kind in ["redteam-agent-targets", "redteam-mcp-targets"] {
        let row = match registry(state, tenant, kind).await {
            Ok(row) => Some(row),
            Err(DomainError::NotFound { .. }) => None,
            Err(error) => return Err(error),
        };
        rows.insert(kind, row);
    }
    for target in targets {
        let active = state
            .store
            .asset_get_durable(tenant, target.asset_id)
            .await?
            .is_some_and(|asset| asset.kind == target.kind.asset() && asset.is_live());
        let row = rows.get(target.kind.registry()).and_then(Option::as_ref);
        if !active || row.is_none() || hash(row.ok_or_else(corrupt)?)? != target.registry_sha256 {
            return Ok(false);
        }
        let managed = super::managed_model::read(state, tenant, target.kind, target.profile_id).await?;
        if super::managed_model::fingerprint(managed.as_ref())? != target.managed_profile_sha256 {
            return Ok(false);
        }
    }
    Ok(true)
}
