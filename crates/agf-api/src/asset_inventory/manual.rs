//! Explicit applications, distinct from automatically discovered trial assets.
use super::*;
use agf_core::asset::{Asset, AssetChange, ChangeKind};
use agf_core::audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget};
use agf_core::enums::{AssetKind, DataClass, DiscoverySource, LifecycleState};
use agf_core::secret::content_hash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    /// Stable client request ID; retry the identical request after a network failure.
    pub request_id: String,
    /// Inventory key, unique within the organization. Reuse it in discovery to merge.
    pub fingerprint: String,
    pub kind: String,
    pub name: String,
    pub owner: String,
    pub data_class: String,
    pub note: String,
    #[serde(default)]
    pub department: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub version: String,
    /// Optional external EDR host identifier for reviewed isolation actions.
    #[serde(default)]
    pub edr_host_id: String,
    /// Optional external SCIM user ID for reviewed identity deactivation.
    #[serde(default)]
    pub scim_user_id: String,
}

pub async fn register(
    state: &AppState,
    tenant: TenantId,
    actor: &str,
    audit_actor: AuditActor,
    mut input: Registration,
) -> DomainResult<Asset> {
    for (value, limit, required) in [
        (&mut input.fingerprint, 256, true),
        (&mut input.name, 256, true),
        (&mut input.owner, 256, true),
        (&mut input.department, 256, false),
        (&mut input.endpoint, 2048, false),
        (&mut input.vendor, 256, false),
        (&mut input.version, 128, false),
        (&mut input.edr_host_id, 128, false),
        (&mut input.scim_user_id, 128, false),
    ] {
        *value = value.trim().to_string();
        if (required && value.is_empty()) || value.len() > limit || value.chars().any(char::is_control) {
            return Err(DomainError::Validation(
                "Registration fields are empty, too long or contain control characters".into(),
            ));
        }
    }
    if !input.edr_host_id.is_empty() {
        agf_adapters::vendors::require_safe_id("edr-isolation", &input.edr_host_id, "host id")?;
    }
    if !input.scim_user_id.is_empty() {
        if input.kind != "credential" {
            return Err(DomainError::Validation("SCIM user binding requires kind=credential".into()));
        }
        agf_adapters::vendors::require_safe_id("iam-scim", &input.scim_user_id, "SCIM user id")?;
    }
    input.note = input.note.trim().to_string();
    if input.note.is_empty()
        || input.note.len() > 2000
        || input.note.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(DomainError::Validation(
            "Application purpose is empty, too long or contains control characters".into(),
        ));
    }
    let request = Id::parse(&input.request_id).map_err(|_| DomainError::Validation("Invalid request_id".into()))?;
    let kind = AssetKind::parse(&input.kind).map_err(DomainError::Validation)?;
    let data_class = match input.data_class.as_str() {
        "public" => DataClass::Public,
        "internal" => DataClass::Internal,
        "confidential" => DataClass::Confidential,
        "restricted" => DataClass::Restricted,
        _ => return Err(DomainError::Validation("Unknown data classification".into())),
    };
    if !input.endpoint.is_empty() && !input.endpoint.starts_with("stdio:") {
        let endpoint = url::Url::parse(&input.endpoint)
            .map_err(|_| DomainError::Validation("Use an absolute endpoint URL or stdio:name".into()))?;
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(DomainError::Validation(
                "Endpoint metadata must not contain credentials, query parameters or fragments".into(),
            ));
        }
    }
    let digest = content_hash(&serde_json::to_string(&input)?);
    let mut asset = Asset::new(tenant, kind, input.name, input.fingerprint);
    // Use the same tenant-scoped identity as discovery.
    asset.id = agf_core::ids::deterministic_id(agf_core::ids::NS_ASSET, &format!("{tenant}:{}", asset.fingerprint));
    asset.lifecycle = LifecycleState::Requested;
    asset.discovery_source = DiscoverySource::Manual;
    asset.last_seen_at = None; // Registration is not evidence of a running service.
    asset.owner = Some(input.owner);
    asset.data_class = data_class;
    asset.department = optional(input.department);
    asset.endpoint = optional(input.endpoint);
    asset.vendor = optional(input.vendor);
    asset.version = optional(input.version);
    if !input.edr_host_id.is_empty() {
        asset.attributes.insert("edr_host_id".into(), json!(input.edr_host_id));
    }
    if !input.scim_user_id.is_empty() {
        asset.attributes.insert("scim_user_id".into(), json!(input.scim_user_id));
    }
    asset.attributes.insert("registration_request_id".into(), json!(request));
    asset.attributes.insert("registration_digest".into(), json!(digest));
    let id = asset.id;
    let audit = AppState::audit_entry(
        tenant,
        AuditAction::Create,
        AuditOutcome::Success,
        audit_actor,
        AuditTarget::new("asset", Some(id.to_string()), Some(asset.name.clone())),
        "手工登记资产",
    );
    let change = AssetChange {
        id: Id::new(),
        tenant_id: tenant,
        asset_id: id,
        kind,
        change_kind: ChangeKind::Added,
        field: Some("registration".into()),
        old_value: None,
        new_value: Some(json!("requested")),
        risky: false,
        risk_note: Some(format!("{actor}: {}", input.note)),
        domain: None,
        detected_at: Timestamp::now(),
    };
    state
        .store
        .asset_mutate_audited_durable(tenant, id, audit, move |existing| {
            if let Some(existing) = existing {
                if existing.attributes.get("registration_request_id") == Some(&json!(request))
                    && existing.attributes.get("registration_digest") == Some(&json!(digest))
                {
                    return Ok((existing, None));
                }
                return Err(DomainError::Conflict(
                    "This inventory key already exists; open the existing asset instead".into(),
                ));
            }
            Ok((asset, Some(change)))
        })
        .await
}

fn optional(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}
