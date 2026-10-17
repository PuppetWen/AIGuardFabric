use super::*;
use agf_core::credential::SecretMaterial;
use agf_core::enums::{AssetKind, DataClass};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RoleEntry {
    pub(crate) id: Id,
    pub(crate) tenant_id: TenantId,
    pub(crate) name: String,
    pub(crate) display_name: String,
    pub(crate) permissions: Vec<Permission>,
    pub(crate) builtin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct AgentIdentity {
    pub(super) id: Id,
    pub(super) tenant_id: TenantId,
    pub(super) fingerprint: String,
    pub(super) department: Option<String>,
    pub(super) data_class: DataClass,
}
impl AgentIdentity {
    pub(super) fn capture(tenant: TenantId, asset: &Asset) -> DomainResult<Self> {
        if asset.id.is_nil() || asset.tenant_id != tenant || asset.kind != AssetKind::Agent || !asset.is_live() {
            return Err(denied());
        }
        Ok(Self {
            id: asset.id,
            tenant_id: tenant,
            fingerprint: asset.fingerprint.clone(),
            department: asset.department.clone(),
            data_class: asset.data_class,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Proof {
    pub(super) agent: AgentIdentity,
    pub(super) configuration_version: u64,
    pub(super) source_digest: String,
    pub(super) mocked: bool,
    pub(super) region: String,
    pub(super) instance_id: String,
    pub(super) worker_name: String,
    pub(super) team_name: String,
    pub(super) cloud_role: String,
    pub(super) observed_at: Timestamp,
    pub(super) role_id: Id,
    pub(super) role_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Eligibility {
    Eligible,
    Revoked,
    Unverified,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Record {
    pub(super) tenant: TenantId,
    pub(super) asset_id: Id,
    pub(super) version: u64,
    pub(super) governed: bool,
    pub(super) eligibility: Eligibility,
    pub(super) reason: Option<String>,
    pub(super) proof: Proof,
    pub(super) updated_at: Timestamp,
}
impl Record {
    pub(super) fn retire(&mut self, eligibility: Eligibility, reason: &str) -> DomainResult<bool> {
        // Positive evidence cannot revive a revoked, unknown or disabled mapping.
        if self.eligibility != Eligibility::Eligible {
            return Ok(false);
        }
        self.version = self.version.checked_add(1).ok_or_else(|| DomainError::Validation("映射版本已耗尽".into()))?;
        self.eligibility = eligibility;
        self.reason = Some(reason.into());
        self.updated_at = Timestamp::now();
        Ok(true)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Sealed {
    pub(super) secret: SecretMaterial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Change {
    Adopt {
        configuration_version: u64,
        observed_at: Timestamp,
        worker_name: String,
        team_name: String,
        cloud_role: String,
        role_id: Id,
    },
    Disable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub(super) request_id: Id,
    pub(super) expected_version: u64,
    pub(super) confirm_local_constraint: bool,
    pub(super) change: Change,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Intent {
    pub(super) tenant: TenantId,
    pub(super) actor_id: Id,
    pub(super) request_id: Id,
    pub(super) asset_id: Id,
    pub(super) body_hash: String,
    pub(super) result: Record,
}
