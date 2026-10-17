//! Durable, bounded counts for tool calls forwarded through one MCP endpoint.
use crate::{config_store::ConfigStore, model_routes::tenant_record_id, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

const KIND: &str = "mcp-tool-usage";
const REDTEAM_KIND: &str = "redteam-mcp-tool-usage";
const OTHER: &str = "<other tools>";
const MAX_NAMED_TOOLS: usize = 127;
const MAX_PENDING: usize = 4096;
const LEASE_MS: i64 = 15 * 60 * 1000;

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct ToolCounts {
    pub attempts: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub unknown: u64,
    pub latency_ms_total: u64,
    pub last_seen_at: Option<Timestamp>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    tool: String,
    started_ms: i64,
    expires_ms: i64,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    request_id: Option<Value>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Ledger {
    tools: BTreeMap<String, ToolCounts>,
    pending: BTreeMap<Id, Pending>,
}

#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Succeeded,
    Failed,
    Unknown,
    NotDelivered,
}

/// MCP tool execution errors can be returned inside a valid JSON-RPC result.
pub(crate) fn response_outcome(frame: &Value) -> Outcome {
    if frame.get("error").is_some() || frame.pointer("/result/isError") == Some(&Value::Bool(true)) {
        Outcome::Failed
    } else {
        Outcome::Succeeded
    }
}

impl Ledger {
    fn finish(&mut self, id: Id, outcome: Outcome, now: Timestamp) {
        let Some(pending) = self.pending.remove(&id) else { return };
        let Some(row) = self.tools.get_mut(&pending.tool) else { return };
        match outcome {
            Outcome::Succeeded => row.succeeded = row.succeeded.saturating_add(1),
            Outcome::Failed => row.failed = row.failed.saturating_add(1),
            Outcome::Unknown => row.unknown = row.unknown.saturating_add(1),
            Outcome::NotDelivered => row.attempts = row.attempts.saturating_sub(1),
        }
        if matches!(outcome, Outcome::Succeeded | Outcome::Failed) {
            row.latency_ms_total =
                row.latency_ms_total.saturating_add(now.unix_millis().saturating_sub(pending.started_ms).max(0) as u64);
        }
        row.last_seen_at = Some(now);
    }

    fn roll(&mut self, now: Timestamp) {
        let expired: Vec<_> =
            self.pending.iter().filter(|(_, row)| row.expires_ms <= now.unix_millis()).map(|(id, _)| *id).collect();
        for id in expired {
            self.finish(id, Outcome::Unknown, now);
        }
    }
}

fn safe_name(name: Option<&str>) -> String {
    let value = name.unwrap_or_default().trim();
    if value.is_empty() || value.chars().count() > 160 || value.chars().any(char::is_control) {
        "<unnamed or invalid>".into()
    } else {
        value.into()
    }
}

pub(crate) struct Attempt {
    store: Arc<ConfigStore>,
    tenant: TenantId,
    endpoint: Id,
    kind: &'static str,
    id: Id,
    completed: bool,
}

impl Attempt {
    pub(crate) async fn begin(
        state: &AppState,
        tenant: TenantId,
        endpoint: Id,
        tool: Option<&str>,
    ) -> DomainResult<Self> {
        let id = Id::new();
        Self::begin_with_id(state, tenant, (KIND, endpoint), tool, id, None, None).await
    }

    pub(crate) async fn begin_redteam(
        state: &AppState,
        tenant: TenantId,
        profile: Id,
        tool: Option<&str>,
    ) -> DomainResult<Self> {
        Self::begin_with_id(state, tenant, (REDTEAM_KIND, profile), tool, Id::new(), None, None).await
    }

    async fn begin_with_id(
        state: &AppState,
        tenant: TenantId,
        key: (&'static str, Id),
        tool: Option<&str>,
        id: Id,
        owner: Option<&str>,
        request_id: Option<&Value>,
    ) -> DomainResult<Self> {
        let (kind, endpoint) = key;
        let now = Timestamp::now();
        let name = safe_name(tool);
        state
            .configurations
            .mutate::<Ledger, _>(tenant, kind, endpoint, |ledger| {
                ledger.roll(now);
                if ledger.pending.len() >= MAX_PENDING || ledger.pending.contains_key(&id) {
                    return Err(DomainError::PreconditionFailed("MCP tool usage capacity reached".into()));
                }
                let key = if ledger.tools.contains_key(&name) || ledger.tools.len() < MAX_NAMED_TOOLS {
                    name.clone()
                } else {
                    OTHER.into()
                };
                let row = ledger.tools.entry(key.clone()).or_default();
                row.attempts = row.attempts.saturating_add(1);
                row.last_seen_at = Some(now);
                ledger.pending.insert(
                    id,
                    Pending {
                        tool: key,
                        started_ms: now.unix_millis(),
                        expires_ms: now.unix_millis() + LEASE_MS,
                        owner: owner.map(str::to_owned),
                        request_id: request_id.cloned(),
                    },
                );
                Ok(())
            })
            .await?;
        Ok(Self { store: state.configurations.clone(), tenant, endpoint, kind, id, completed: false })
    }

    pub(super) async fn renew(&self) -> DomainResult<()> {
        renew(&self.store, self.tenant, self.endpoint, self.id).await
    }

    pub(crate) async fn finish(mut self, outcome: Outcome) -> DomainResult<()> {
        finish_owned(&self.store, self.tenant, (self.kind, self.endpoint), self.id, outcome, None).await?;
        self.completed = true;
        Ok(())
    }

    pub(super) fn detach(mut self) -> Id {
        self.completed = true;
        self.id
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let (store, tenant, key, id) = (self.store.clone(), self.tenant, (self.kind, self.endpoint), self.id);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = finish_owned(&store, tenant, key, id, Outcome::Unknown, None).await {
                    tracing::warn!(%error, "MCP tool outcome remains pending until expiry");
                }
            });
        }
    }
}

async fn finish(store: &ConfigStore, tenant: TenantId, endpoint: Id, id: Id, outcome: Outcome) -> DomainResult<()> {
    finish_owned(store, tenant, (KIND, endpoint), id, outcome, None).await
}

async fn finish_owned(
    store: &ConfigStore,
    tenant: TenantId,
    key: (&str, Id),
    id: Id,
    outcome: Outcome,
    owner: Option<&str>,
) -> DomainResult<()> {
    let (kind, endpoint) = key;
    let now = Timestamp::now();
    store
        .mutate::<Ledger, _>(tenant, kind, endpoint, |ledger| {
            if let Some(pending) = ledger.pending.get(&id) {
                if owner.is_some_and(|owner| pending.owner.as_deref() != Some(owner)) {
                    return Err(DomainError::Forbidden("MCP tool usage belongs to another caller".into()));
                }
            }
            // Finish this result before expiring other calls; a late final result is still evidence.
            ledger.finish(id, outcome, now);
            ledger.roll(now);
            Ok(())
        })
        .await?;
    Ok(())
}

async fn renew(store: &ConfigStore, tenant: TenantId, endpoint: Id, id: Id) -> DomainResult<()> {
    let now = Timestamp::now();
    store
        .mutate::<Ledger, _>(tenant, KIND, endpoint, |ledger| {
            ledger.roll(now);
            let row = ledger
                .pending
                .get_mut(&id)
                .ok_or_else(|| DomainError::PreconditionFailed("MCP tool usage lease expired".into()))?;
            row.expires_ms = now.unix_millis() + LEASE_MS;
            Ok(())
        })
        .await?;
    Ok(())
}

pub(super) async fn finish_remote(
    state: &AppState,
    tenant: TenantId,
    endpoint: Id,
    id: Id,
    outcome: Outcome,
) -> DomainResult<()> {
    finish(&state.configurations, tenant, endpoint, id, outcome).await
}

/// The remote MCP check uses its authenticated quota lease as the durable attempt ID.
pub(crate) async fn begin_runtime(
    state: &AppState,
    tenant: TenantId,
    lease: Id,
    owner: &str,
    tool: Option<&str>,
    request_id: &Value,
) -> DomainResult<()> {
    Attempt::begin_with_id(state, tenant, (KIND, tenant_record_id(tenant)), tool, lease, Some(owner), Some(request_id))
        .await?
        .detach();
    Ok(())
}

/// A result can only settle the call that created its quota lease. An absent row is a
/// previously settled retry, which remains idempotent without changing any counters.
pub(crate) async fn verify_runtime_result(
    state: &AppState,
    tenant: TenantId,
    lease: Id,
    owner: &str,
    response_id: &Value,
) -> DomainResult<()> {
    let ledger = state.configurations.get::<Ledger>(tenant, KIND, tenant_record_id(tenant)).await?.unwrap_or_default();
    if let Some(pending) = ledger.pending.get(&lease) {
        if pending.owner.as_deref() != Some(owner) {
            return Err(DomainError::Forbidden("MCP tool usage belongs to another caller".into()));
        }
        // Calls admitted before this field existed may still be in flight during a
        // rolling upgrade; keep their former lease/owner checks until they expire.
        if pending.request_id.as_ref().is_some_and(|expected| expected != response_id) {
            return Err(DomainError::Conflict("MCP tool result does not match its request ID".into()));
        }
    }
    Ok(())
}

pub(crate) async fn finish_runtime(
    state: &AppState,
    tenant: TenantId,
    lease: Id,
    owner: &str,
    outcome: Outcome,
) -> DomainResult<()> {
    finish_owned(&state.configurations, tenant, (KIND, tenant_record_id(tenant)), lease, outcome, Some(owner)).await
}

pub(crate) async fn runtime_snapshot(state: &AppState, tenant: TenantId) -> DomainResult<serde_json::Value> {
    let mut result = snapshot(state, tenant, tenant_record_id(tenant)).await?;
    if let Some(object) = result.as_object_mut() {
        object.remove("endpoint_id");
        object.insert("source".into(), serde_json::json!("runtime-check"));
    }
    Ok(result)
}

pub(super) async fn renew_remote(state: &AppState, tenant: TenantId, endpoint: Id, id: Id) -> DomainResult<()> {
    renew(&state.configurations, tenant, endpoint, id).await
}

pub(crate) async fn snapshot(state: &AppState, tenant: TenantId, endpoint: Id) -> DomainResult<serde_json::Value> {
    snapshot_with_kind(state, tenant, endpoint, KIND).await
}

pub(crate) async fn redteam_snapshot(
    state: &AppState,
    tenant: TenantId,
    profile: Id,
) -> DomainResult<serde_json::Value> {
    snapshot_with_kind(state, tenant, profile, REDTEAM_KIND).await
}

async fn snapshot_with_kind(
    state: &AppState,
    tenant: TenantId,
    endpoint: Id,
    kind: &str,
) -> DomainResult<serde_json::Value> {
    let now = Timestamp::now();
    let mut ledger = state.configurations.get::<Ledger>(tenant, kind, endpoint).await?.unwrap_or_default();
    ledger.roll(now);
    let items: Vec<_> = ledger
        .tools
        .iter()
        .map(|(name, row)| {
            serde_json::json!({"name":name,"attempts":row.attempts,"succeeded":row.succeeded,
            "failed":row.failed,"unknown":row.unknown,"inflight":row.attempts.saturating_sub(
                row.succeeded.saturating_add(row.failed).saturating_add(row.unknown)),
            "latency_ms_total":row.latency_ms_total,"last_seen_at":row.last_seen_at})
        })
        .collect();
    Ok(serde_json::json!({"endpoint_id":endpoint,"items":items}))
}
