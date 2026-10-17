use super::{KIND, util};
use crate::AppState;
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
};
use agf_storage::configuration::BoundedConfigurationList;
use agf_storage::semantic_response_cache::ConfigurationFence;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio::time::Instant;

const KINDS: [&str; 9] = [
    "case-containment",
    "detection-rules",
    "gateway-quotas",
    "model-endpoint",
    "model-route-policy",
    "quota-definitions",
    "runtime-blacklists",
    "signed-policy-registry",
    KIND,
];

/// Private full set includes absent kinds and every present record, not just selected endpoints.
/// No Deserialize or public DTO exposes its unkeyed private fingerprints.
pub(super) struct Source {
    tenant: TenantId,
    mocked: bool,
    rules: String,
    hashes: BTreeMap<String, String>,
    rows: BTreeMap<(String, Id), Value>,
}
pub(super) enum Capture {
    Complete(Box<Source>),
    TooMany,
    TooLarge,
}
impl Source {
    pub(super) async fn capture(state: &AppState, tenant: TenantId, deadline: Instant) -> DomainResult<Capture> {
        let mut hashes = BTreeMap::new();
        let mut rows = BTreeMap::new();
        let mut bytes = 0usize;
        let mut count = 0usize;
        for kind in KINDS {
            check_deadline(deadline)?;
            let values = tokio::time::timeout_at(
                deadline,
                state.configurations.list_bounded::<Value>(tenant, kind, 32 - count, 8 * 1024 * 1024 - bytes),
            )
            .await
            .map_err(|_| util::stale())??;
            let values = match values {
                BoundedConfigurationList::Complete(values) => values,
                BoundedConfigurationList::TooMany => return Ok(Capture::TooMany),
                BoundedConfigurationList::TooLarge => return Ok(Capture::TooLarge),
            };
            count = count.checked_add(values.len()).ok_or_else(util::stale)?;
            let mut sorted = Vec::new();
            for value in values {
                bytes = bytes.checked_add(serde_json::to_vec(&value)?.len()).ok_or_else(util::stale)?;
                if bytes > 8 * 1024 * 1024 {
                    return Err(util::stale());
                }
                let id = identity(kind, tenant, &value)?;
                sorted.push(util::digest(&value)?);
                if rows.insert((kind.into(), id), value).is_some() {
                    return Err(util::stale());
                }
            }
            sorted.sort();
            hashes.insert(kind.into(), util::digest(&json!(sorted))?);
        }
        let policy_key = ("signed-policy-registry".into(), crate::model_routes::tenant_record_id(tenant));
        // Validate every stored policy identity, history ordering and signature, without initialization.
        crate::policy_store::publication_candidates(state, tenant, rows.get(&policy_key).cloned())?;
        let source = Self {
            tenant,
            mocked: state.config.mock_mode,
            rules: state.rules.report.pack_fingerprint.clone(),
            hashes,
            rows,
        };
        check_deadline(deadline)?;
        Ok(Capture::Complete(Box::new(source)))
    }
    pub(super) fn get(&self, kind: &str, id: Id) -> Option<&Value> {
        self.rows.get(&(kind.into(), id))
    }
    pub(super) fn fences(&self) -> DomainResult<Vec<ConfigurationFence>> {
        if self.rows.is_empty() || self.rows.len() > 32 {
            return Err(util::stale());
        }
        self.rows
            .iter()
            .map(|((kind, id), value)| {
                let version = match value.get("version") {
                    None => 0,
                    Some(version) => version.as_u64().ok_or_else(util::stale)?,
                };
                ConfigurationFence::from_server_record(kind, *id, version, value)
            })
            .collect()
    }
    pub(super) fn metadata(&self) -> Value {
        json!({"schema":"full-semantic-source-set-v1","tenant":self.tenant,
            "mocked":self.mocked,"rules":self.rules,"collections":self.hashes,
            "keys":self.rows.keys().map(|(kind,id)| json!([kind,id])).collect::<Vec<_>>()})
    }
    pub(super) async fn current(&self, state: &AppState, deadline: Instant) -> DomainResult<()> {
        let Capture::Complete(actual) = Self::capture(state, self.tenant, deadline).await? else {
            return Err(util::stale());
        };
        if self.metadata() != actual.metadata() {
            return Err(util::stale());
        }
        check_deadline(deadline)
    }
}

pub(super) fn identity(kind: &str, tenant: TenantId, value: &Value) -> DomainResult<Id> {
    let explicit = match kind {
        "case-containment" | "model-route-policy" | KIND => value.get("id"),
        "model-endpoint" => value.pointer("/endpoint/id"),
        _ => None,
    };
    let id = if matches!(kind, "case-containment" | "model-route-policy" | "model-endpoint" | KIND) {
        serde_json::from_value::<Id>(explicit.cloned().ok_or_else(util::stale)?).map_err(|_| util::stale())?
    } else if kind == "detection-rules" {
        deterministic_id("detection-rules", &tenant.to_string())
    } else {
        crate::model_routes::tenant_record_id(tenant)
    };
    if id.is_nil() {
        return Err(util::stale());
    }
    if let Some(owner) =
        value.get("tenant_id").or_else(|| value.get("tenant")).or_else(|| value.pointer("/endpoint/tenant_id"))
    {
        if serde_json::from_value::<TenantId>(owner.clone()).map_err(|_| util::stale())? != tenant {
            return Err(util::stale());
        }
    }
    if kind == KIND && id != util::record_id(tenant) {
        return Err(util::stale());
    }
    Ok(id)
}
pub(super) fn check_deadline(deadline: Instant) -> DomainResult<()> {
    if Instant::now() >= deadline {
        return Err(util::stale());
    }
    Ok(())
}
