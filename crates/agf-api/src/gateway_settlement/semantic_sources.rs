//! Full source-set check includes absent kinds and additions, not just the selected fences.
use super::{source, store};
use crate::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use agf_storage::configuration::BoundedConfigurationList;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use tokio::time::Instant;

pub(super) async fn current(
    state: &AppState,
    tenant: TenantId,
    original: &Value,
    deadline: Instant,
) -> DomainResult<bool> {
    tokio::time::timeout_at(deadline, compare(state, tenant, original))
        .await
        .map_err(|_| DomainError::Timeout("Original semantic source check exhausted publication budget".into()))?
}
async fn compare(state: &AppState, tenant: TenantId, original: &Value) -> DomainResult<bool> {
    let mut hashes = BTreeMap::new();
    let mut keys = BTreeSet::new();
    let mut count = 0usize;
    let mut bytes = 0usize;
    for kind in source::KINDS {
        let values =
            state.configurations.list_bounded::<Value>(tenant, kind, 32 - count, 8 * 1024 * 1024 - bytes).await?;
        let BoundedConfigurationList::Complete(values) = values else {
            return Ok(false);
        };
        count = count.checked_add(values.len()).ok_or_else(store::missing)?;
        let ids = source::record_ids(kind, tenant, &values)?;
        if !values.is_empty() {
            keys.extend(ids.into_iter().map(|id| (kind.to_string(), id)));
        }
        let mut sorted = Vec::new();
        for value in values {
            bytes = bytes.checked_add(serde_json::to_vec(&value)?.len()).ok_or_else(store::missing)?;
            if bytes > 8 * 1024 * 1024 {
                return Ok(false);
            }
            sorted.push(digest(&value)?);
        }
        sorted.sort();
        hashes.insert(kind.to_string(), digest(&json!(sorted))?);
    }
    let actual = json!({"schema":"full-semantic-source-set-v1","tenant":tenant,"mocked":state.config.mock_mode,
        "rules":state.rules.report.pack_fingerprint,"collections":hashes,"keys":keys.into_iter().map(|(kind,id)| json!([kind,id])).collect::<Vec<_>>()});
    Ok(actual == *original)
}
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let sorted: BTreeMap<_, _> = fields.iter().map(|(key, value)| (key.clone(), canonical(value))).collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}
fn digest(value: &Value) -> DomainResult<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&canonical(value))?)))
}
