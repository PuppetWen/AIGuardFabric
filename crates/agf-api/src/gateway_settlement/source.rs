//! Private source evidence binds the complete evaluated configuration set, including ciphertext and versions.
use super::{codec, store};
use crate::{state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use agf_storage::configuration::{BoundedConfigurationList, ConfigStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) const KINDS: [&str; 9] = [
    "case-containment",
    "detection-rules",
    "gateway-quotas",
    "model-endpoint",
    "model-route-policy",
    "quota-definitions",
    "runtime-blacklists",
    "signed-policy-registry",
    "semantic-cache-profile",
];

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Source {
    tenant: TenantId,
    mocked: bool,
    rules: String,
    hashes: BTreeMap<String, String>,
    keys: BTreeMap<String, Vec<Id>>,
}

/// Explicit capacity verdicts never authorize a protected durable call to use legacy accounting.
/// Authentication, tenant, malformed source and database errors remain errors.
pub(super) enum Capture {
    Ready(Source),
    Bypass(Bypass),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Bypass {
    Cardinality,
    EncodedBytes,
}
struct Bounds {
    records: usize,
    bytes: usize,
}

impl Source {
    pub(super) async fn capture(state: &AppState, tenant: TenantId) -> DomainResult<Capture> {
        Self::capture_records(
            &state.configurations,
            tenant,
            state.config.mock_mode,
            state.rules.report.pack_fingerprint.clone(),
            Bounds { records: 512, bytes: 8 * 1024 * 1024 },
        )
        .await
    }

    async fn capture_records(
        configurations: &ConfigStore,
        tenant: TenantId,
        mocked: bool,
        rules: String,
        mut remaining: Bounds,
    ) -> DomainResult<Capture> {
        let mut hashes = BTreeMap::new();
        let mut keys = BTreeMap::new();
        for kind in KINDS {
            // A singleton overflow is a typed capacity verdict. The protected HTTP owner
            // publishes a NotSent failure instead of granting a weaker execution lane.
            let max = if collection(kind) { remaining.records } else { remaining.records.min(1) };
            let values = match configurations.list_bounded::<Value>(tenant, kind, max, remaining.bytes).await? {
                BoundedConfigurationList::Complete(values) => values,
                BoundedConfigurationList::TooMany => return Ok(Capture::Bypass(Bypass::Cardinality)),
                BoundedConfigurationList::TooLarge => return Ok(Capture::Bypass(Bypass::EncodedBytes)),
            };
            let ids = record_ids(kind, tenant, &values)?;
            remaining.records = remaining.records.checked_sub(values.len()).ok_or_else(store::missing)?;
            for value in &values {
                remaining.bytes =
                    remaining.bytes.checked_sub(serde_json::to_vec(value)?.len()).ok_or_else(store::missing)?;
            }
            keys.insert(kind.into(), ids);
            hashes.insert(kind.into(), digest(values)?);
        }
        Ok(Capture::Ready(Self { tenant, mocked, rules, hashes, keys }))
    }

    pub(super) async fn current(&self, state: &AppState) -> DomainResult<()> {
        let Capture::Ready(current) = Self::capture(state, self.tenant).await? else {
            // A previously admitted source cannot gain a new permit through the legacy bypass.
            return Err(changed());
        };
        if current.rules != self.rules
            || current.mocked != self.mocked
            || current.hashes != self.hashes
            || current.keys != self.keys
        {
            return Err(changed());
        }
        Ok(())
    }

    pub(super) async fn locked(
        &self,
        state: &AppState,
        tx: &AssetTransaction<'_>,
        semantic: Option<&super::semantic_plan::CachePlan>,
    ) -> DomainResult<()> {
        if state.rules.report.pack_fingerprint != self.rules
            || state.config.mock_mode != self.mocked
            || self.hashes.len() != KINDS.len()
        {
            return Err(changed());
        }
        // Acquire the actual ordinary-writer key BEFORE its FOR UPDATE row lock. Reversing
        // those locks can deadlock against ConfigStore's advisory-key → row-update order.
        for (kind, id) in lock_order(&self.keys, semantic) {
            tx.configuration_lock(&kind, id).await?;
        }
        let mut remaining = Bounds { records: 512, bytes: 8 * 1024 * 1024 };
        for kind in KINDS {
            let max = if collection(kind) { remaining.records } else { remaining.records.min(1) };
            let BoundedConfigurationList::Complete(rows) =
                tx.configurations_bounded(kind, max, remaining.bytes).await?
            else {
                return Err(changed());
            };
            remaining.records = remaining.records.checked_sub(rows.len()).ok_or_else(changed)?;
            for (_, value) in &rows {
                remaining.bytes = remaining.bytes.checked_sub(serde_json::to_vec(value)?.len()).ok_or_else(changed)?;
            }
            let actual_ids = rows.iter().map(|(id, _)| *id).collect::<Vec<_>>();
            let expected = self.keys.get(kind).ok_or_else(changed)?;
            if !locked_ids_match(kind, &actual_ids, expected) {
                return Err(changed());
            }
            if self.hashes.get(kind) != Some(&digest(rows.into_iter().map(|(_, value)| value).collect())?) {
                return Err(changed());
            }
        }
        Ok(())
    }
}

fn digest(values: Vec<Value>) -> DomainResult<String> {
    if values.len() > 512 {
        return Err(store::missing());
    }
    let mut rows = values.into_iter().map(|value| codec::hash(&value)).collect::<DomainResult<Vec<_>>>()?;
    rows.sort();
    codec::hash(&rows)
}
fn changed() -> DomainError {
    DomainError::Conflict("Gateway authority, model pricing or evaluated policy source changed".into())
}

pub(super) fn record_ids(kind: &str, tenant: TenantId, values: &[Value]) -> DomainResult<Vec<Id>> {
    for value in values {
        if let Some(owner) =
            value.get("tenant_id").or_else(|| value.get("tenant")).or_else(|| value.pointer("/endpoint/tenant_id"))
        {
            if serde_json::from_value::<TenantId>(owner.clone()).map_err(|_| store::missing())? != tenant {
                return Err(store::missing());
            }
        }
    }
    if !collection(kind) {
        if values.len() > 1 {
            return Err(store::missing());
        }
        let id = if kind == "semantic-cache-profile" {
            agf_core::ids::deterministic_id("agf.semantic-cache.profile.v1", &tenant.to_string())
        } else if kind == "detection-rules" {
            agf_core::ids::deterministic_id("detection-rules", &tenant.to_string())
        } else {
            crate::model_routes::tenant_record_id(tenant)
        };
        return Ok(vec![id]);
    }
    if values.len() > 512 {
        return Err(store::missing());
    }
    let mut ids = values
        .iter()
        .map(|value| {
            let path = if kind == "model-endpoint" { "/endpoint/id" } else { "/id" };
            serde_json::from_value::<Id>(value.pointer(path).cloned().ok_or_else(store::missing)?)
                .map_err(|_| store::missing())
        })
        .collect::<DomainResult<Vec<_>>>()?;
    ids.sort();
    if ids.iter().any(Id::is_nil) || ids.windows(2).any(|row| row[0] == row[1]) {
        return Err(store::missing());
    }
    Ok(ids)
}

pub(super) fn lock_order(
    keys: &BTreeMap<String, Vec<Id>>,
    semantic: Option<&super::semantic_plan::CachePlan>,
) -> Vec<(String, Id)> {
    let mut all = keys
        .iter()
        .flat_map(|(kind, ids)| ids.iter().map(|id| (kind.clone(), *id)))
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(plan) = semantic {
        all.extend(plan.profile.fences.iter().map(|row| (row.kind.clone(), row.id)));
    }
    all.into_iter().collect()
}

fn collection(kind: &str) -> bool {
    matches!(kind, "case-containment" | "model-endpoint" | "model-route-policy")
}

#[cfg(test)]
mod tests;

fn locked_ids_match(kind: &str, actual: &[Id], expected: &[Id]) -> bool {
    if collection(kind) { actual == expected } else { actual.is_empty() || actual == expected }
}
