//! Evidence for one existing endpoint is a cloud observation, never a proof of network reachability.
mod archive;
mod archive_sql;
mod archive_store;
mod assets;
mod collect;
pub mod contract;
mod graph;
mod guard;
pub(crate) mod mock;
mod parse;
#[cfg(test)]
mod parse_tests;
mod publication;
mod routes;
mod scope;
mod store;
mod store_sql;
mod views;
pub(crate) use routes::router;

const NAME: &str = "alicloud-privatelink";
const KIND: &str = "privatelink-inventory";
const MAX_RUNS: usize = 512;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const LEASE_SECS: i64 = 120;
const EXECUTION_SECS: u64 = 110;

pub(crate) mod provisioning_selection;
pub(crate) fn provisioning_scope(
    state: &crate::state::AppState,
    tenant: agf_core::ids::TenantId,
    row: &crate::integration_store::Stored,
) -> agf_core::error::DomainResult<contract::Scope> {
    scope::from_row(state, tenant, row)
}
