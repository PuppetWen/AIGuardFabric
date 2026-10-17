//! Complete public MSE service listings become governed source observations, never invented AI metadata.
mod archive;
mod archive_sql;
mod archive_store;
mod collect;
pub mod contract;
mod guard;
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

const NAME: &str = "alicloud-mse";
const KIND: &str = "mse-inventory";
const MAX_RUNS: usize = 512;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const LEASE_SECS: i64 = 120;
const EXECUTION_SECS: u64 = 110;
