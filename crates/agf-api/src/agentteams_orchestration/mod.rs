//! Explicit application-owned declarations and a separate persisted Mock receiver, never execution.
use crate::{Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

mod codec;
mod model;
mod offline;
mod reducer;
mod routes;
mod source;
mod sql;
mod views;
mod write;
pub(crate) use routes::router;

const KIND: &str = "agentteams-application-orchestration";
const MAX_RECORDS: usize = 64;
const MAX_INTENTS: usize = 512;
const MAX_BYTES: usize = 3 * 1024 * 1024;
fn record_id(tenant: TenantId) -> Id {
    crate::model_routes::tenant_record_id(tenant)
}
fn denied() -> DomainError {
    DomainError::PreconditionFailed("需要启用连接、当前完整 Mock 库存及明确应用编排声明；真实云定义写入未实现".into())
}
fn invalid() -> DomainError {
    DomainError::Validation("编排声明、请求编号或容量无效；不会执行任务或修改云端".into())
}
fn hash<T: Serialize>(value: &T) -> DomainResult<String> {
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
#[cfg(test)]
mod tests;
