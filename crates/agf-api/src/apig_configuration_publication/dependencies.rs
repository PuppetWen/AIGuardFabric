//! Source locks authenticate the original settings, credential envelope and exact target.
use super::{contract::Scope, records::Values, util};
use crate::{cloud_store, state::AppState};
use agf_core::error::DomainResult;
use agf_storage::configuration::ConfigurationGuard;
pub(super) fn guards(scope: Option<&Scope>) -> Vec<ConfigurationGuard<'static>> {
    scope
        .map(|scope| ConfigurationGuard { kind: cloud_store::KIND, id: scope.target.configuration_id })
        .into_iter()
        .collect()
}
pub(super) fn validate_locked(state: &AppState, scope: &Scope, values: &Values) -> DomainResult<()> {
    let cloud: crate::integration_store::Stored = util::read(values, cloud_store::KIND, scope.target.configuration_id)?
        .filter(|row: &crate::integration_store::Stored| row.enabled)
        .ok_or_else(util::stale)?;
    if super::scope::from_row(state, scope.tenant, &cloud)? != *scope {
        return Err(util::stale());
    }
    Ok(())
}
