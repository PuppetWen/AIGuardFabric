use agf_core::{
    enums::DataClass,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;

/// Current full configuration content and version, observed by service code.
/// No request DTO deserializer is implemented for this type.
#[derive(Clone, Serialize)]
pub struct ConfigurationFence {
    pub(super) kind: String,
    pub(super) id: Id,
    pub(super) version: u64,
    pub(super) content_hash: String,
}

impl std::fmt::Debug for ConfigurationFence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfigurationFence(<private-content-witness>)")
    }
}

impl ConfigurationFence {
    /// Stored configuration kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }
    /// Stored record identity.
    pub const fn id(&self) -> Id {
        self.id
    }
    /// Actually observed version, including authenticated legacy version zero.
    pub const fn version(&self) -> u64 {
        self.version
    }
    /// Compare a freshly loaded full stored payload; same-version content changes also invalidate.
    pub fn matches(&self, payload: &Value) -> DomainResult<bool> {
        Ok(content_hash(payload)? == self.content_hash)
    }
    /// Capture the actual stored payload, rather than a caller-supplied digest.
    pub fn from_server_record(kind: &str, id: Id, version: u64, payload: &Value) -> DomainResult<Self> {
        if kind.is_empty()
            || kind.len() > 64
            || id.is_nil()
            || !kind.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(invalid());
        }
        Ok(Self { kind: kind.into(), id, version, content_hash: content_hash(payload)? })
    }
}

/// Complete service-owned evidence after authentication, current policy and route resolution.
/// This is deliberately not Deserialize. Holding an issuer does not itself establish authority.
#[derive(Clone, Serialize)]
pub struct ServerSemanticEvidence {
    /// Actual effective tenant.
    pub tenant: TenantId,
    /// Authenticated subject id, never a display string.
    pub subject_id: Id,
    /// Actual server subject category (user or API key).
    pub subject_kind: String,
    /// Identity tenant retained when a superadmin changes the effective organization.
    pub identity_tenant: TenantId,
    /// Authenticated session, Agent and department isolation.
    pub session: Option<String>,
    /// Server-resolved Agent, including key binding.
    pub agent_id: Option<Id>,
    /// Authoritative department.
    pub department: Option<String>,
    /// Authoritative data class.
    pub data_class: DataClass,
    /// Internal data requires a verified permitted embedding placement.
    pub internal_placement_verified: bool,
    /// Selected chat endpoint.
    pub chat_endpoint: Id,
    /// Exact chat model and pinned revision.
    pub chat_model: String,
    /// Server-pinned model revision, independent of provider wire model string.
    pub chat_model_revision: String,
    /// Independently authorized embedding endpoint.
    pub embedding_endpoint: Id,
    /// Exact embedding model.
    pub embedding_model: String,
    /// Pinned embedding revision.
    pub embedding_model_revision: String,
    /// Validated embedding dimensions.
    pub dimensions: u16,
    /// Effective transport mode, explicitly separating mock/live/local placement.
    pub transport_mode: String,
    /// Cache configuration version, not implicitly enabled by endpoint presence.
    pub cache_configuration_version: u64,
    /// Full source/policy/rule/containment/route/credential/configuration records.
    pub fences: Vec<ConfigurationFence>,
    /// Fixed system messages and every accepted non-user-text parameter.
    pub fixed_request: Value,
    /// Original request authority deadline in UTC milliseconds; not a reusable domain field.
    #[serde(skip)]
    pub authority_deadline_ms: i64,
}

impl std::fmt::Debug for ServerSemanticEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerSemanticEvidence(<redacted>)")
    }
}

/// Non-deserializable authenticated cache domain; fields cannot be supplied by an HTTP client.
#[derive(Clone)]
pub struct TrustedSemanticDomain {
    pub(super) tenant: TenantId,
    pub(super) hash: String,
    pub(super) dimensions: u16,
    pub(super) model: String,
    pub(super) fences: Vec<ConfigurationFence>,
    deadline_ms: i64,
    tag: Vec<u8>,
}

impl std::fmt::Debug for TrustedSemanticDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedSemanticDomain").field("dimensions", &self.dimensions).finish_non_exhaustive()
    }
}

impl TrustedSemanticDomain {
    /// Effective tenant.
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// Keyed digest safe for an internal index; no raw system text or identity is stored.
    pub fn digest(&self) -> &str {
        &self.hash
    }
    /// Validated dimensions.
    pub const fn dimensions(&self) -> u16 {
        self.dimensions
    }
    /// Full source witnesses for trusted authority revalidation, without private payloads.
    pub fn configuration_fences(&self) -> &[ConfigurationFence] {
        &self.fences
    }
}

/// Server-held HMAC capability. Never load this key or evidence from a request body.
#[derive(Clone)]
pub struct DomainIssuer {
    key: [u8; 32],
}

impl std::fmt::Debug for DomainIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DomainIssuer(<redacted>)")
    }
}

impl DomainIssuer {
    /// Construct from an independently managed service key, never a provider API key.
    pub fn from_server_key(key: [u8; 32]) -> DomainResult<Self> {
        if key.iter().all(|byte| *byte == 0) {
            return Err(invalid());
        }
        Ok(Self { key })
    }
    /// Issue only after current authenticated authority and complete source evidence were resolved.
    /// The gateway must recheck original authorization/deadline before network, admission and delivery.
    pub fn issue(&self, mut evidence: ServerSemanticEvidence) -> DomainResult<TrustedSemanticDomain> {
        if evidence.tenant.as_uuid().is_nil()
            || evidence.identity_tenant.as_uuid().is_nil()
            || evidence.subject_id.is_nil()
            || !matches!(evidence.subject_kind.as_str(), "user" | "api_key")
            || evidence.chat_endpoint.is_nil()
            || evidence.embedding_endpoint.is_nil()
            || !(1..=4096).contains(&evidence.dimensions)
            || evidence.cache_configuration_version == 0
            || evidence.fences.is_empty()
            || evidence.fences.len() > 32
            || !transport_mode_allowed(&evidence.transport_mode)
            || !matches!(evidence.data_class, DataClass::Public | DataClass::Internal)
            || evidence.data_class == DataClass::Internal && !evidence.internal_placement_verified
            || [
                &evidence.chat_model,
                &evidence.chat_model_revision,
                &evidence.embedding_model,
                &evidence.embedding_model_revision,
            ]
            .iter()
            .any(|value| value.is_empty() || value.len() > 256 || value.chars().any(char::is_control))
            || !evidence.fixed_request.is_object()
            || serde_json::to_vec(&evidence.fixed_request)?.len() > 16 * 1024
            || evidence.authority_deadline_ms <= chrono::Utc::now().timestamp_millis()
        {
            return Err(invalid());
        }
        evidence.fences.sort_by(|a, b| (&a.kind, a.id).cmp(&(&b.kind, b.id)));
        if evidence.fences.windows(2).any(|pair| pair[0].kind == pair[1].kind && pair[0].id == pair[1].id) {
            return Err(invalid());
        }
        let mut mac = self.mac()?;
        mac.update(b"agf-semantic-domain-v2\0");
        mac.update(&canonical_bytes(&serde_json::to_value(&evidence)?)?);
        let hash = hex::encode(mac.finalize().into_bytes());
        let mut domain = TrustedSemanticDomain {
            tenant: evidence.tenant,
            hash,
            dimensions: evidence.dimensions,
            model: evidence.chat_model,
            fences: evidence.fences,
            deadline_ms: evidence.authority_deadline_ms,
            tag: Vec::new(),
        };
        let mut mac = self.mac()?;
        mac.update(&domain.capability_bytes()?);
        domain.tag = mac.finalize().into_bytes().to_vec();
        Ok(domain)
    }
    pub(super) fn validate(&self, domain: &TrustedSemanticDomain) -> DomainResult<()> {
        let mut mac = self.mac()?;
        mac.update(&domain.capability_bytes()?);
        mac.verify_slice(&domain.tag).map_err(|_| invalid())?;
        if domain.deadline_ms <= chrono::Utc::now().timestamp_millis() {
            return Err(invalid());
        }
        Ok(())
    }
    fn mac(&self) -> DomainResult<Hmac<Sha256>> {
        Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| invalid())
    }
}

impl TrustedSemanticDomain {
    fn capability_bytes(&self) -> DomainResult<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "agf-semantic-lease-v2",
            self.tenant,
            &self.hash,
            self.dimensions,
            &self.model,
            &self.fences,
            self.deadline_ms,
        ))?)
    }
}

pub(super) fn content_hash(value: &Value) -> DomainResult<String> {
    use sha2::Digest;
    Ok(hex::encode(Sha256::digest(canonical_bytes(value)?)))
}

fn canonical_bytes(value: &Value) -> DomainResult<Vec<u8>> {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(fields) => {
                let sorted: std::collections::BTreeMap<_, _> =
                    fields.iter().map(|(key, value)| (key.clone(), canonical(value))).collect();
                Value::Object(sorted.into_iter().collect())
            }
            Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
            other => other.clone(),
        }
    }
    Ok(serde_json::to_vec(&canonical(value))?)
}

fn invalid() -> DomainError {
    DomainError::PreconditionFailed("Semantic cache trusted domain is unavailable or stale".into())
}

fn transport_mode_allowed(mode: &str) -> bool {
    matches!(mode, "live" | "mock" | "local") || cfg!(feature = "test-loopback-transport") && mode == "test-loopback"
}
