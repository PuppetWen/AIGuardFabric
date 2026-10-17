//! Explicit local permission constraints for inventoried AgentTeams Workers.
//! Cloud role strings are observations, never credentials or permission grants.
use crate::{Principal, state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    asset::Asset,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    rbac::{ApiKey, Permission},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

mod authority;
mod catalog;
mod codec;
mod model;
mod proof;
mod refresh;
mod routes;
#[cfg(test)]
mod tests;
mod views;
mod write;
pub(crate) use authority::constrain_key;
pub(crate) use authority::constrain_key_transaction;
pub(crate) use model::RoleEntry;
pub(crate) use refresh::in_transaction as refresh_in_transaction;
pub(crate) use routes::router;

const KIND: &str = "agentteams-role-governance";
const INTENTS: &str = "agentteams-role-governance-intent";
const MARKER: &str = "agf.agentteams.role_governed";
const MAX_WORKERS: usize = 512;
const MAX_INTENTS: usize = 2048;
const MAX_BYTES: usize = 128 * 1024;

fn denied() -> DomainError {
    DomainError::Forbidden("AgentTeams 角色约束已停用、失去资格或缺少可信证明；请管理员重新盘点并明确采用".into())
}
fn hash<T: Serialize>(value: &T) -> DomainResult<String> {
    use sha2::{Digest, Sha256};
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
