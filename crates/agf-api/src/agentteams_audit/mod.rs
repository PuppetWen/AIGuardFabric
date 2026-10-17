//! Authenticated AgentTeams telemetry bound to a reviewed cloud inventory.
pub mod binding;
mod binding_write;
pub mod contract;
pub mod ingest;
pub(crate) mod inventory_refresh;
pub mod routes;
pub mod trace;
mod trace_cursor;
mod trace_graph;
pub mod views;

use agf_core::error::DomainError;

fn stale() -> DomainError {
    DomainError::Conflict("审计绑定已失效，请重新盘点并绑定日志源".into())
}
