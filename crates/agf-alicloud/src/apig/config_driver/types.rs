use agf_core::error::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;

/// Exact existing ModelAPI deployment; workflow additionally fences tenant, source and configuration version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModelBinding {
    /// Existing ModelAPI identifier.
    pub http_api_id: String,
    /// Selected dedicated gateway.
    pub gateway_id: String,
    /// Selected environment.
    pub environment_id: String,
}
impl ModelBinding {
    /// Validate literal resource identifiers without implicit normalization.
    ///
    /// # Errors
    /// Missing or unsafe resource identity.
    pub fn validate(&self) -> DomainResult<()> {
        for value in [&self.http_api_id, &self.gateway_id, &self.environment_id] {
            identifier(value)?;
        }
        Ok(())
    }
}

/// One actual installed plugin and its exact one-resource attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContentBinding {
    /// Exact gateway/environment/API identities.
    pub model: ModelBinding,
    /// Existing attachment ID.
    pub attachment_id: String,
    /// Existing installed plugin ID.
    pub plugin_id: String,
    /// Actual plugin class ID.
    pub class_id: String,
    /// Actual observed class revision; not assumed to be a default version.
    pub class_version: String,
}
impl ContentBinding {
    /// Validate the exact selected plugin identities.
    ///
    /// # Errors
    /// Missing or unsafe identity.
    pub fn validate(&self) -> DomainResult<()> {
        self.model.validate()?;
        for value in [&self.attachment_id, &self.plugin_id, &self.class_id, &self.class_version] {
            identifier(value)?;
        }
        Ok(())
    }
}

/// Only public switches editable in this first plugin profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContentSettings {
    /// Attachment enabled state, independent of each inspection switch.
    pub enabled: bool,
    /// Check the request body.
    pub check_request: bool,
    /// Check the response; operators must review its effect on streaming.
    pub check_response: bool,
    /// HTTP denial status (100..599), independent of inspection verdict evidence.
    pub deny_code: u16,
}

/// Safe identity of an already observed service/model; no credential or backend configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelService {
    /// Existing service identity.
    pub service_id: String,
    /// Exact service revision, absent values remain absent.
    pub version: Option<String>,
    /// Actual model name in this deployment.
    pub model_name: String,
    /// Observed route weight.
    pub weight: u32,
}

/// Change a known slot; requested model must already have been observed for the same service revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServicePatch {
    /// Existing service identifier.
    pub service_id: String,
    /// Exact current service revision.
    pub version: Option<String>,
    /// Exact baseline model name of the selected slot.
    pub expected_model_name: String,
    /// Already observed model name, never a synthetic model default.
    pub model_name: String,
    /// Explicit route weight in 1..100.
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "binding", rename_all = "snake_case")]
pub(super) enum Target {
    Content(ContentBinding),
    Models(ModelBinding),
}

/// Complete bounded evidence; raw provider configuration is excluded from Debug and public views.
#[derive(Clone)]
pub struct Observation {
    pub(super) target: Target,
    pub(super) raw: Value,
    pub(super) config: Value,
    pub(super) fingerprint: String,
    pub(super) view: Value,
}
impl Observation {
    /// Full control-plane comparison fingerprint; never a provider CAS token.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    /// Explicit safe view; does not serialize arbitrary provider strings or secrets.
    pub fn safe_view(&self) -> Value {
        self.view.clone()
    }
    /// Complete provider evidence for AEAD-only persistence by a trusted workflow.
    pub fn exported_evidence(&self) -> Value {
        json!({"schema":1,"target":self.target,"response":self.raw})
    }
}
impl fmt::Debug for Observation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observation")
            .field("target", &self.target)
            .field("fingerprint", &self.fingerprint)
            .field("configuration", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Server-prepared full body with bounded, public-field-only changes.
#[derive(Clone)]
pub struct Prepared {
    pub(super) baseline: Observation,
    pub(super) body: Value,
    pub(super) desired: Observation,
}
impl Prepared {
    /// Original evidence for AEAD-only workflow persistence; never a public response or audit field.
    pub fn baseline_evidence(&self) -> Value {
        self.baseline.exported_evidence()
    }
    /// Prepared evidence for the tenant's transactional Mock record, not proof of a cloud write.
    /// The caller must hold the admitted original intent and current authority before storing it.
    pub fn desired_evidence(&self) -> Value {
        self.desired.exported_evidence()
    }
    /// Safe before/after differences; raw configuration remains private.
    pub fn safe_diff(&self) -> Value {
        json!({"before":self.baseline.safe_view(),"after":self.desired.safe_view(),
            "baselineHash":self.baseline.fingerprint(),"desiredHash":self.desired.fingerprint(),
            "cloudCas":false,"deploymentVerified":null,"consumerApplied":null})
    }
    /// Separate current comparison does not upgrade an earlier Unknown acknowledgement.
    pub fn compare_readback(&self, current: &Observation) -> super::ReadbackState {
        if self.desired.target == current.target && self.desired.fingerprint == current.fingerprint {
            super::ReadbackState::Matched
        } else {
            super::ReadbackState::Different
        }
    }
}
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("baseline", &self.baseline.fingerprint())
            .field("body", &"[redacted]")
            .finish_non_exhaustive()
    }
}
pub(super) fn identifier(value: &str) -> DomainResult<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.contains(['/', '\\'])
        || matches!(value, "." | "..")
    {
        return Err(DomainError::Validation("APIG exact resource identity is invalid".into()));
    }
    Ok(())
}
