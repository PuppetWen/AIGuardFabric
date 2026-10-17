//! Server-only source guards. Disabled configuration allows local annotations; deletion does not.
use super::{ArchiveSource, FailureEvidence, SourceFingerprint, VerifiedSource, source_proof, util};
use crate::{integration_store::Stored, state::AppState};
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
    source::SourceRecord,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) const NAME: &str = "alicloud-agentteams";
pub(super) fn cloud_id(tenant: TenantId) -> Id {
    crate::integration_store::id(tenant, NAME)
}
pub(super) fn row(value: Option<&Value>, tenant: TenantId, id: Id) -> DomainResult<Option<SourceRecord>> {
    let row: Option<SourceRecord> =
        value.map(|value| serde_json::from_value(value.clone()).map_err(|_| util::corrupt())).transpose()?;
    if row
        .as_ref()
        .and_then(|row| row.source.as_ref())
        .is_some_and(|source| source.tenant_id != tenant || source.id != id)
    {
        return Err(util::corrupt());
    }
    Ok(row)
}
pub(super) fn verify(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    token: &SourceFingerprint,
    cloud: Option<&Value>,
    source: Option<&Value>,
) -> DomainResult<VerifiedSource> {
    let cloud = cloud.ok_or_else(util::stale)?;
    let cloud: Stored = serde_json::from_value(cloud.clone()).map_err(|_| util::corrupt())?;
    let row = row(source, tenant, id)?.ok_or_else(util::stale)?;
    let cipher = crate::model_gateway::cipher(state)?;
    let proof = source_proof::authenticate(&cipher, tenant, id, token)?;
    source_proof::check_current(&proof, &cloud, &row)
}
pub(super) fn archive_sources(
    state: &AppState,
    tenant: TenantId,
    evidence: &BTreeMap<Id, FailureEvidence>,
    expected: &super::ArchiveInput,
    cloud: Option<&Value>,
    sources: &BTreeMap<Id, Option<Value>>,
) -> DomainResult<BTreeMap<Id, ArchiveSource>> {
    let mut output = BTreeMap::new();
    for entry in &expected.sources {
        let source = sources.get(&entry.source_id).ok_or_else(util::corrupt)?.as_ref();
        let original = evidence.values().find(|row| row.source_id == entry.source_id).ok_or_else(util::invalid)?;
        let checked = if let Some(token) = &entry.fingerprint {
            ArchiveSource::current(verify(state, tenant, entry.source_id, token, cloud, source)?)
        } else {
            let row = row(source, tenant, entry.source_id)?;
            ArchiveSource::gone(original, row.as_ref())?
        };
        output.insert(entry.source_id, checked);
    }
    Ok(output)
}
