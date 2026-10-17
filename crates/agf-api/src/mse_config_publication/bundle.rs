//! Content comes only from validated platform revisions, never from an API body.
use super::{
    MAX_AGENT_IDS, MAX_CONTENT_BYTES, MAX_POLICIES,
    contract::{BundleTarget, DependencyEvidence, Scope},
    input::PolicyRevision,
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    policy::Policy,
};
use agf_runtime::{
    engine::{EngineConfig, RuntimeEngine},
    signature::PolicySigner,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const SCHEMA: &str = "agf.policy-bundle.v1";
const SIGNING_DOMAIN: &str = "agf.mse-nacos-bundle.v1:";

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Payload {
    schema: String,
    tenant_id: TenantId,
    target_scope_id: Id,
    target: BundleTarget,
    policies: Vec<Policy>,
    dependencies: Vec<DependencyEvidence>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    payload: Payload,
    payload_hash: String,
    key_id: String,
    signature: String,
}

pub(super) struct BundleContent {
    pub plaintext: String,
    pub content_hash: String,
    pub source_policy_versions: Vec<PolicyRevision>,
    pub source_policies: Vec<Policy>,
}

impl std::fmt::Debug for BundleContent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NacosBundleContent")
            .field("content_hash", &self.content_hash)
            .field("content_bytes", &self.plaintext.len())
            .finish_non_exhaustive()
    }
}

pub(super) fn generate(
    scope: &Scope,
    mut policies: Vec<Policy>,
    mut dependencies: Vec<DependencyEvidence>,
    signer: &PolicySigner,
) -> DomainResult<BundleContent> {
    validate_policies(scope.tenant, &policies, signer)?;
    policies.sort_by_key(|policy| policy.id);
    dependencies.sort_by(|left, right| (&left.kind, left.id).cmp(&(&right.kind, right.id)));
    validate_dependencies(&dependencies)?;
    validate_dependency_references(&policies, &dependencies)?;
    let payload = Payload {
        schema: SCHEMA.into(),
        tenant_id: scope.tenant,
        target_scope_id: scope.target.target_scope_id,
        target: BundleTarget::from(&scope.target),
        policies,
        dependencies,
    };
    let payload_hash = hash(canonical(&payload)?.as_bytes());
    let signature = signer.sign_hash(&format!("{SIGNING_DOMAIN}{payload_hash}"));
    let envelope = Envelope { payload, payload_hash, key_id: signer.key_id().into(), signature };
    let plaintext = canonical(&envelope)?;
    ensure_content_bound(plaintext.len())?;
    Ok(content(plaintext, &envelope))
}

/// The caller must first authenticate encrypted history and match its stored content hash.
pub(super) fn verify_history(
    scope: &Scope,
    plaintext: &str,
    expected_hash: &str,
    signer: &PolicySigner,
) -> DomainResult<BundleContent> {
    ensure_content_bound(plaintext.len())?;
    if hash(plaintext.as_bytes()) != expected_hash {
        return Err(corrupt());
    }
    let envelope: Envelope = serde_json::from_str(plaintext).map_err(|_| corrupt())?;
    let same_target = envelope.payload.target == BundleTarget::from(&scope.target);
    let same_identity =
        (envelope.payload.tenant_id, envelope.payload.target_scope_id) == (scope.tenant, scope.target.target_scope_id);
    if envelope.payload.schema != SCHEMA || !same_identity || !same_target || envelope.key_id != signer.key_id() {
        return Err(corrupt());
    }
    let payload_hash = hash(canonical(&envelope.payload)?.as_bytes());
    let signature = signer.sign_hash(&format!("{SIGNING_DOMAIN}{payload_hash}"));
    if envelope.payload_hash != payload_hash || !equal_signature(&envelope.signature, &signature) {
        return Err(corrupt());
    }
    validate_policies(scope.tenant, &envelope.payload.policies, signer)?;
    validate_dependencies(&envelope.payload.dependencies)?;
    validate_dependency_references(&envelope.payload.policies, &envelope.payload.dependencies)?;
    if !strictly_sorted_policies(&envelope.payload.policies) || canonical(&envelope)? != plaintext {
        return Err(corrupt());
    }
    Ok(content(plaintext.into(), &envelope))
}

fn content(plaintext: String, envelope: &Envelope) -> BundleContent {
    BundleContent {
        content_hash: hash(plaintext.as_bytes()),
        plaintext,
        source_policy_versions: envelope
            .payload
            .policies
            .iter()
            .map(|policy| PolicyRevision { policy_id: policy.id, version: policy.version })
            .collect(),
        source_policies: envelope.payload.policies.clone(),
    }
}

fn validate_policies(tenant: TenantId, policies: &[Policy], signer: &PolicySigner) -> DomainResult<()> {
    if policies.is_empty() || policies.len() > MAX_POLICIES {
        return Err(DomainError::Validation("可信策略包须包含1到20条政策".into()));
    }
    let mut selected = BTreeSet::new();
    let mut agents = BTreeSet::new();
    for policy in policies {
        if policy.tenant_id != tenant
            || policy.id.is_nil()
            || policy.version == 0
            || policy.deleted_at.is_some()
            || !policy.enabled
            || policy.content_hash != policy.compute_hash()
            || !selected.insert(policy.id)
        {
            return Err(corrupt());
        }
        signer.verify(policy)?;
        agents.extend(policy.scope_agent_ids.iter().copied());
    }
    if agents.len() > MAX_AGENT_IDS || agents.iter().any(Id::is_nil) {
        return Err(DomainError::PreconditionFailed("所选政策关联Agent聚合范围超过500个或含空ID；请缩小范围".into()));
    }
    RuntimeEngine::in_memory(policies.to_vec(), Vec::new(), EngineConfig::default())?;
    Ok(())
}

fn validate_dependencies(dependencies: &[DependencyEvidence]) -> DomainResult<()> {
    let mut selected = BTreeSet::new();
    if dependencies.len() > 540 {
        return Err(DomainError::PreconditionFailed("策略包依赖证据超过有界上限".into()));
    }
    for row in dependencies {
        if !matches!(row.kind.as_str(), "quota" | "model-endpoint" | "agent")
            || row.id.is_nil()
            || row.version == Some(0)
            || row.fingerprint.len() != 64
            || !row.fingerprint.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !selected.insert((&row.kind, row.id))
        {
            return Err(corrupt());
        }
    }
    if !dependencies.windows(2).all(|pair| (&pair[0].kind, pair[0].id) < (&pair[1].kind, pair[1].id)) {
        return Err(corrupt());
    }
    Ok(())
}

fn validate_dependency_references(policies: &[Policy], dependencies: &[DependencyEvidence]) -> DomainResult<()> {
    let mut expected = BTreeSet::new();
    for policy in policies {
        if let Some(id) = policy.quota_id {
            expected.insert(("quota", id));
        }
        if let Some(id) = policy.degrade_endpoint_id {
            expected.insert(("model-endpoint", id));
        }
        expected.extend(policy.scope_agent_ids.iter().map(|id| ("agent", *id)));
    }
    let actual = dependencies.iter().map(|row| (row.kind.as_str(), row.id)).collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(corrupt());
    }
    Ok(())
}

fn strictly_sorted_policies(policies: &[Policy]) -> bool {
    policies.windows(2).all(|pair| pair[0].id < pair[1].id)
}
fn ensure_content_bound(bytes: usize) -> DomainResult<()> {
    if bytes > MAX_CONTENT_BYTES {
        return Err(DomainError::PreconditionFailed("完整签名策略包超过256KiB，请缩小政策选择".into()));
    }
    Ok(())
}
fn canonical<T: Serialize>(value: &T) -> DomainResult<String> {
    Ok(serde_json::to_string(&ordered(serde_json::to_value(value)?))?)
}
fn ordered(value: Value) -> Value {
    match value {
        Value::Object(values) => {
            let mut sorted = values.into_iter().collect::<Vec<_>>();
            sorted.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(sorted.into_iter().map(|(key, value)| (key, ordered(value))).collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(ordered).collect()),
        other => other,
    }
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn equal_signature(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes().zip(right.bytes()).fold(0, |difference, (left, right)| difference | (left ^ right)) == 0
}
fn corrupt() -> DomainError {
    DomainError::Crypto("可信Nacos策略包的身份、顺序、hash或签名不匹配".into())
}
