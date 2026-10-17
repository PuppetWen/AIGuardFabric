//! One authenticated intent retains the full baseline privately and edits public fields only.
use super::{
    contract::{Binding, Scope},
    input::PreviewChange,
    records::{Action, Prepared},
    util,
};
use crate::state::AppState;
use agf_alicloud::apig::config_driver::{
    self as driver, ContentSettings, ModelService, Observation, Prepared as Update, ServicePatch,
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    schema: u8,
    proof: Proof,
    baseline: Value,
    intent: Intent,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    pub scope: Scope,
    pub state_version: u64,
    pub observation_id: Id,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub baseline_observed_at: Timestamp,
    pub acknowledge_unknown_operation_id: Option<Id>,
}
impl Proof {
    fn from_prepared(row: &Prepared) -> Self {
        Self {
            scope: row.scope.clone(),
            state_version: row.state_version,
            observation_id: row.observation_id,
            created_at: row.created_at,
            expires_at: row.expires_at,
            baseline_observed_at: row.baseline_observed_at,
            acknowledge_unknown_operation_id: row.acknowledge_unknown_operation_id,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub action: Action,
    pub source_publication_id: Option<Id>,
    pub change: PreviewChange,
}
pub(super) struct Content {
    pub plaintext: String,
    pub package_hash: String,
    pub update: Update,
}

pub(super) fn generate(scope: &Scope, baseline: &Observation, intent: Intent, proof: Proof) -> DomainResult<Content> {
    validated(scope, Package { schema: 1, proof, baseline: baseline.exported_evidence(), intent })
}
pub(super) fn restore(state: &AppState, tenant: TenantId, prepared: &Prepared) -> DomainResult<Content> {
    if (prepared.tenant, prepared.scope.tenant) != (tenant, tenant) || prepared.request_id.is_nil() {
        return Err(util::corrupt());
    }
    let plaintext = util::decrypt_content(
        state,
        tenant,
        body_id(tenant, prepared.request_id),
        &prepared.body,
        &prepared.body_hash,
    )?;
    if plaintext.len() != prepared.body_bytes {
        return Err(util::corrupt());
    }
    let package: Package = serde_json::from_str(&plaintext)?;
    if serde_json::to_value(&package.proof)? != serde_json::to_value(Proof::from_prepared(prepared))?
        || package.intent.action != prepared.action
        || package.intent.source_publication_id != prepared.source_publication_id
    {
        return Err(util::corrupt());
    }
    let baseline = restore_evidence(&prepared.scope, &package.baseline)?;
    let content = validated(&prepared.scope, package)?;
    if baseline.fingerprint() != prepared.baseline_fingerprint
        || baseline.fingerprint() != prepared.baseline_config_hash
        || desired_hash(&content.update)? != prepared.desired_hash
        || desired_bytes(&content.update)? != prepared.desired_bytes
    {
        return Err(util::corrupt());
    }
    Ok(content)
}
fn validated(scope: &Scope, package: Package) -> DomainResult<Content> {
    if package.schema != 1
        || package.proof.scope != *scope
        || (package.intent.action == Action::Rollback) != package.intent.source_publication_id.is_some()
        || package.intent.source_publication_id.is_some_and(|id| id.is_nil())
    {
        return Err(util::corrupt());
    }
    let baseline = restore_evidence(scope, &package.baseline)?;
    let update = prepare(&baseline, &package.intent.change)?;
    let plaintext = serde_json::to_string(&package)?;
    util::bound(&package, super::MAX_CONTENT_BYTES)?;
    Ok(Content { package_hash: util::hash(plaintext.as_bytes()), plaintext, update })
}
pub(super) fn restore_evidence(scope: &Scope, evidence: &Value) -> DomainResult<Observation> {
    match &scope.target.binding {
        Binding::Content(binding) => driver::restore_content(binding, evidence),
        Binding::Models(binding) => driver::restore_models(binding, evidence),
    }
}
pub(super) fn prepare(baseline: &Observation, change: &PreviewChange) -> DomainResult<Update> {
    match change {
        PreviewChange::Content { settings } => driver::prepare_content(baseline, *settings),
        PreviewChange::Models { services } => driver::prepare_models(baseline, services),
        PreviewChange::Rollback { .. } => Err(util::corrupt()),
    }
}
pub(super) fn desired_hash(update: &Update) -> DomainResult<String> {
    update.safe_diff()["desiredHash"].as_str().map(str::to_owned).ok_or_else(util::corrupt)
}
pub(super) fn desired_bytes(update: &Update) -> DomainResult<usize> {
    util::bound(&update.desired_evidence(), super::MAX_CONTENT_BYTES)
}

/// Trusted history restores only public values onto the newly observed private configuration.
/// The old ciphertext is never sent as a replacement for fresh credentials or other environments.
pub(super) fn rollback(scope: &Scope, baseline: &Observation, history: &Content) -> DomainResult<PreviewChange> {
    let previous = restore_evidence(scope, &history.update.baseline_evidence())?.safe_view();
    match &scope.target.binding {
        Binding::Content(_) => Ok(PreviewChange::Content {
            settings: serde_json::from_value::<ContentSettings>(previous["settings"].clone())?,
        }),
        Binding::Models(_) => {
            let old: Vec<ModelService> = serde_json::from_value(previous["services"].clone())?;
            let current: Vec<ModelService> = serde_json::from_value(baseline.safe_view()["services"].clone())?;
            if old.len() != current.len() {
                return Err(DomainError::PreconditionFailed("当前服务槽已改变，不能猜测历史槽映射".into()));
            }
            let mut patches = Vec::new();
            for (prior, now) in old.iter().zip(&current) {
                if (prior.service_id.as_str(), &prior.version) != (now.service_id.as_str(), &now.version) {
                    return Err(util::stale());
                }
                patches.push(ServicePatch {
                    service_id: now.service_id.clone(),
                    version: now.version.clone(),
                    expected_model_name: now.model_name.clone(),
                    model_name: prior.model_name.clone(),
                    weight: prior.weight,
                });
            }
            Ok(PreviewChange::Models { services: patches })
        }
    }
}
pub(super) fn body_id(tenant: TenantId, request: Id) -> Id {
    util::content_id(tenant, request, "intent")
}
