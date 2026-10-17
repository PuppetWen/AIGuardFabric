use super::{NAME, authority::Submission, util};
use crate::{
    cloud_store,
    integration_store::{Stored, decrypt, id},
    state::AppState,
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    pub tenant: TenantId,
    pub id: Id,
    pub version: u64,
    pub fingerprint: String,
    pub group: String,
    pub region: String,
    pub mode: String,
}

pub(super) async fn current(state: &AppState, submission: &Submission, version: u64) -> DomainResult<Source> {
    submission.authorize(state).await?;
    let row =
        super::authority::bounded(submission.deadline, cloud_store::load(state, submission.principal.tenant, NAME))
            .await?
            .filter(|row| row.enabled)
            .ok_or_else(|| DomainError::PreconditionFailed("CMS source is absent or disabled".into()))?;
    let source = from_row(state, submission.principal.tenant, &row)?;
    if source.version != version {
        return Err(util::conflict());
    }
    Ok(source)
}
pub(super) fn from_row(state: &AppState, tenant: TenantId, row: &Stored) -> DomainResult<Source> {
    if row.id != id(tenant, NAME) || row.name != NAME || row.version == 0 {
        return Err(util::corrupt());
    }
    let private = decrypt(state, tenant, row)?;
    let group = cloud_store::setting(&private, "group_id", "");
    if group.is_empty() || group.len() > 128 || group.chars().any(char::is_control) {
        return Err(util::invalid());
    }
    let endpoint = cloud_store::endpoint(AliCloudService::Cms, &private)?;
    let mode =
        if state.config.mock_mode || row.mock { "mock" } else { state.cms_queue.mode(tenant, &endpoint.url("/"))? };
    if mode != "mock" && !group.parse::<i64>().is_ok_and(|id| id > 0 && id.to_string() == group) {
        return Err(util::invalid());
    }
    Ok(Source {
        tenant,
        id: row.id,
        version: row.version,
        fingerprint: util::fingerprint(row)?,
        group: group.into(),
        region: endpoint.region,
        mode: mode.into(),
    })
}
pub(super) fn validate(source: &Source, tenant: TenantId) -> DomainResult<()> {
    if source.tenant != tenant
        || source.id != id(tenant, NAME)
        || source.version == 0
        || source.fingerprint.len() != 64
        || !source.fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
        || source.group.is_empty()
        || source.group.len() > 128
        || source.group.chars().any(char::is_control)
        || source.region.is_empty()
        || source.region.len() > 128
        || source.region.chars().any(char::is_control)
        || !["mock", "live", "loopback_test"].contains(&source.mode.as_str())
        || (source.mode != "mock"
            && !source.group.parse::<i64>().is_ok_and(|id| id > 0 && id.to_string() == source.group))
    {
        return Err(util::corrupt());
    }
    Ok(())
}
pub(super) fn locked(state: &AppState, source: &Source, value: Option<&Value>) -> DomainResult<()> {
    let row: Stored = value
        .cloned()
        .map(serde_json::from_value::<Stored>)
        .transpose()
        .map_err(|_| util::corrupt())?
        .filter(|row| row.enabled)
        .ok_or_else(util::conflict)?;
    if from_row(state, source.tenant, &row)? != *source {
        return Err(util::conflict());
    }
    Ok(())
}
pub(super) async fn check(state: &AppState, submission: &Submission, source: &Source) -> DomainResult<()> {
    submission.authorize(state).await?;
    if current(state, submission, source.version).await? != *source {
        return Err(util::conflict());
    }
    submission.budget()
}
