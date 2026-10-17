//! Explicit metadata projections. Raw payloads, credentials, PoCs and free-form timelines are never sent.
use super::{Purpose, authorize};
use crate::{middleware::Principal, state::AppState};
use agf_core::{
    alert::Alert,
    enums::DataClass,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    report::ReportKind,
    time::{TimeRange, Timestamp},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const MAX_FACTS: usize = 48;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFact {
    pub reference: String,
    pub kind: String,
    pub observed_at: Option<Timestamp>,
    pub content_hash: Option<String>,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub tenant_id: TenantId,
    pub purpose: Purpose,
    pub object_id: Id,
    pub data_class: DataClass,
    pub facts: Vec<EvidenceFact>,
    pub truncated: bool,
    pub relationship_semantics: String,
    pub omitted_facts: usize,
    pub omitted_records: usize,
}

impl Snapshot {
    fn new(tenant_id: TenantId, purpose: Purpose, object_id: Id) -> Self {
        Self {
            tenant_id,
            purpose,
            object_id,
            data_class: DataClass::Internal,
            facts: Vec::new(),
            truncated: false,
            relationship_semantics: "Co-occurrence; causality unproven".into(),
            omitted_facts: 0,
            omitted_records: 0,
        }
    }
    fn add(&mut self, fact: EvidenceFact) -> DomainResult<()> {
        if self.facts.iter().any(|old| old.reference == fact.reference) {
            return Ok(());
        }
        if self.facts.len() >= MAX_FACTS {
            return Err(DomainError::Validation(
                "Analysis object exceeds 48 evidence facts; narrow the associated object".into(),
            ));
        }
        if serde_json::to_vec(&fact)?.len() > 8192 {
            return Err(DomainError::Validation(
                "Analysis evidence metadata exceeds 8 KiB per fact; narrow the associated object".into(),
            ));
        }
        self.facts.push(fact);
        Ok(())
    }
}

fn same_tenant(own: TenantId, actual: TenantId) -> DomainResult<()> {
    if own != actual {
        return Err(DomainError::Forbidden("Evidence belongs to another tenant".into()));
    }
    Ok(())
}

fn missing(kind: &'static str, id: Id) -> DomainError {
    DomainError::NotFound { entity: kind, id: id.to_string() }
}

fn sha256(value: &str) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then(|| value.to_ascii_lowercase())
}

/// Arbitrary ingested rule strings never enter the model context; only current published keys do.
async fn rule_versions(state: &AppState, principal: &Principal, keys: &[String]) -> DomainResult<Vec<Value>> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    principal.require(state, "rules", "read").map_err(|error| error.error)?;
    let pack = crate::rule_store::pack(state, principal.tenant).await?;
    Ok(keys
        .iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|key| {
            pack.rules.iter().find(|rule| rule.key == *key).map(|rule| {
                json!({
                    "key":rule.key,"current_published_version":rule.version,
                    "version_scope":"current published rule; not an inferred detection-time version",
                })
            })
        })
        .collect())
}

fn unique_ids(ids: &[Id]) -> BTreeSet<Id> {
    ids.iter().copied().collect()
}

async fn assets(state: &AppState, principal: &Principal, snapshot: &mut Snapshot, ids: &[Id]) -> DomainResult<()> {
    if ids.is_empty() {
        return Ok(());
    }
    principal.require(state, "assets", "read").map_err(|error| error.error)?;
    for id in unique_ids(ids) {
        let asset =
            state.store.asset_get_durable(principal.tenant, id).await?.ok_or_else(|| missing("analysis-asset", id))?;
        same_tenant(principal.tenant, asset.tenant_id)?;
        snapshot.data_class = snapshot.data_class.max(asset.data_class);
        snapshot.add(EvidenceFact {
            reference: format!("asset:{id}"),
            kind: "asset".into(),
            observed_at: Some(asset.updated_at),
            content_hash: None,
            metadata: json!({"kind":asset.kind,"data_class":asset.data_class}),
        })?;
    }
    Ok(())
}

async fn events(state: &AppState, principal: &Principal, snapshot: &mut Snapshot, ids: &[Id]) -> DomainResult<()> {
    if ids.is_empty() {
        return Ok(());
    }
    principal.require(state, "sources", "read").map_err(|error| error.error)?;
    for id in unique_ids(ids) {
        let event =
            state.ingest_sink.get_event(principal.tenant, id).await?.ok_or_else(|| missing("analysis-event", id))?;
        same_tenant(principal.tenant, event.tenant_id)?;
        let mut linked: Vec<_> = [event.ai.agent_id, event.ai.mcp_server_id].into_iter().flatten().collect();
        if let Some(endpoint_id) = event.ai.model_endpoint_id {
            principal.require(state, "models", "read").map_err(|error| error.error)?;
            // Gateway endpoint IDs differ from asset IDs; use the actual endpoint asset linkage.
            if let Some(endpoint) = state
                .configurations
                .get::<crate::model_gateway::StoredEndpoint>(
                    principal.tenant,
                    crate::model_gateway::ENDPOINT_KIND,
                    endpoint_id,
                )
                .await?
            {
                same_tenant(principal.tenant, endpoint.endpoint.tenant_id)?;
                linked.push(endpoint.endpoint.asset_id);
            } else {
                // Discovered model-endpoint events may already carry the model asset ID.
                linked.push(endpoint_id);
            }
        }
        assets(state, principal, snapshot, &linked).await?;
        let versions = rule_versions(state, principal, &event.ai.rule_keys).await?;
        snapshot.add(EvidenceFact { reference: format!("event:{id}"), kind: "event".into(),
            observed_at: Some(event.time), content_hash: sha256(&event.raw_hash),
            metadata: json!({"source_id":event.source_id,"protocol":event.protocol,
                "category":event.category,"severity":event.severity,"parser_id":event.parser_id,
                "rule_versions":versions,"unpublished_rule_keys_omitted":event.ai.rule_keys.len().saturating_sub(versions.len())}) })?;
    }
    Ok(())
}

async fn findings(state: &AppState, principal: &Principal, snapshot: &mut Snapshot, ids: &[Id]) -> DomainResult<()> {
    if ids.is_empty() {
        return Ok(());
    }
    principal.require(state, "findings", "read").map_err(|error| error.error)?;
    for id in unique_ids(ids) {
        let finding = state
            .store
            .finding_get_durable(principal.tenant, id)
            .await?
            .ok_or_else(|| missing("analysis-finding", id))?;
        same_tenant(principal.tenant, finding.tenant_id)?;
        assets(state, principal, snapshot, &finding.asset_id.into_iter().collect::<Vec<_>>()).await?;
        let versions = rule_versions(state, principal, &finding.rule_keys).await?;
        let referenced: Vec<Id> = finding
            .evidence
            .iter()
            .filter_map(|evidence| evidence.artifact_ref.as_deref())
            .filter_map(|reference| reference.strip_prefix(&format!("event:{}:", principal.tenant)))
            .filter_map(|id| id.parse().ok())
            .collect();
        events(state, principal, snapshot, &referenced).await?;
        snapshot.add(EvidenceFact { reference: format!("finding:{id}"), kind: "finding".into(),
            observed_at: Some(finding.first_seen_at), content_hash: Some(agf_core::secret::content_hash(&serde_json::to_string(&finding.evidence)?)),
            metadata: json!({"domain":finding.domain,
                "severity":finding.severity,"state":finding.state,"rule_versions":versions,
                "unpublished_rule_keys_omitted":finding.rule_keys.len().saturating_sub(versions.len()),
                "evidence_hashes":finding.evidence.iter().enumerate().map(|(index,e)|json!({"ordinal":index,"hash":sha256(&e.content_hash)})).collect::<Vec<_>>(),
                "event_ids":referenced}) })?;
    }
    Ok(())
}

async fn alert(state: &AppState, principal: &Principal, snapshot: &mut Snapshot, row: Alert) -> DomainResult<()> {
    same_tenant(principal.tenant, row.tenant_id)?;
    assets(state, principal, snapshot, &row.asset_ids).await?;
    findings(state, principal, snapshot, &row.finding_ids).await?;
    events(state, principal, snapshot, &row.event_ids).await?;
    snapshot.add(EvidenceFact { reference: format!("alert:{}", row.id), kind: "alert".into(),
        observed_at: Some(row.first_seen_at), content_hash: None,
        metadata: json!({"severity":row.severity,"state":row.state,
            "last_seen_at":row.last_seen_at,"asset_ids":row.asset_ids,"event_ids":row.event_ids,"finding_ids":row.finding_ids}) })
}

pub async fn load_alert(state: &AppState, principal: &Principal, id: Id) -> DomainResult<Snapshot> {
    authorize(state, principal, Purpose::Alert, false)?;
    let row = state.store.alert_get_durable(principal.tenant, id).await?.ok_or_else(|| missing("alert", id))?;
    let mut snapshot = Snapshot::new(principal.tenant, Purpose::Alert, id);
    alert(state, principal, &mut snapshot, row).await?;
    Ok(snapshot)
}

pub async fn load_case(state: &AppState, principal: &Principal, id: Id) -> DomainResult<Snapshot> {
    authorize(state, principal, Purpose::Case, false)?;
    let case = state.store.case_get_durable(principal.tenant, id).await?.ok_or_else(|| missing("case", id))?;
    same_tenant(principal.tenant, case.tenant_id)?;
    let mut snapshot = Snapshot::new(principal.tenant, Purpose::Case, id);
    assets(state, principal, &mut snapshot, &case.asset_ids).await?;
    findings(state, principal, &mut snapshot, &case.finding_ids).await?;
    if !case.alert_ids.is_empty() {
        principal.require(state, "alerts", "read").map_err(|error| error.error)?;
    }
    for alert_id in &case.alert_ids {
        let row = state
            .store
            .alert_get_durable(principal.tenant, *alert_id)
            .await?
            .ok_or_else(|| missing("analysis-alert", *alert_id))?;
        alert(state, principal, &mut snapshot, row).await?;
    }
    let timeline = state.store.case_events_durable(principal.tenant, id).await?;
    for event in timeline {
        same_tenant(principal.tenant, event.tenant_id)?;
        if event.case_id != id {
            return Err(DomainError::Forbidden("Case timeline belongs to another case".into()));
        }
        snapshot.add(EvidenceFact {
            reference: format!("case-event:{}", event.id),
            kind: "case-event".into(),
            observed_at: Some(event.at),
            content_hash: None,
            metadata: json!({"case_id":event.case_id,"kind":event.kind,"automated":event.automated}),
        })?;
    }
    snapshot.add(EvidenceFact { reference: format!("case:{id}"), kind: "case".into(),
        observed_at: Some(case.created_at), content_hash: None,
        metadata: json!({"state":case.state,
            "severity":case.severity,"asset_ids":case.asset_ids,"alert_ids":case.alert_ids,"finding_ids":case.finding_ids}) })?;
    snapshot.facts.sort_by_key(|fact| (fact.observed_at, fact.reference.clone()));
    Ok(snapshot)
}

pub async fn load_report(
    state: &AppState,
    principal: &Principal,
    id: Id,
    kind: ReportKind,
    range: &TimeRange,
) -> DomainResult<Snapshot> {
    authorize(state, principal, Purpose::Report, false)?;
    principal.require(state, "findings", "read").map_err(|error| error.error)?;
    principal.require(state, "alerts", "read").map_err(|error| error.error)?;
    let mut snapshot = Snapshot::new(principal.tenant, Purpose::Report, id);
    let mut rows = state.store.finding_list_all_durable(principal.tenant).await?;
    rows.retain(|row| row.first_seen_at >= range.from && row.first_seen_at < range.to);
    rows.sort_by_key(|row| (std::cmp::Reverse(row.first_seen_at), row.id));
    // Report inputs are bounded independently of report tables; selected evidence and truncation are explicit.
    snapshot.truncated = rows.len() > 8;
    snapshot.omitted_records = rows.len().saturating_sub(8);
    for row in rows.into_iter().take(8) {
        findings(state, principal, &mut snapshot, &[row.id]).await?;
    }
    let mut alerts = state.store.alert_list_durable(principal.tenant, None, None).await?;
    alerts.retain(|row| row.first_seen_at >= range.from && row.first_seen_at < range.to);
    alerts.sort_by_key(|row| (std::cmp::Reverse(row.first_seen_at), row.id));
    snapshot.truncated |= alerts.len() > 8;
    snapshot.omitted_records += alerts.len().saturating_sub(8);
    for row in alerts.into_iter().take(8) {
        alert(state, principal, &mut snapshot, row).await?;
    }
    snapshot.add(EvidenceFact {
        reference: format!("report-window:{id}"),
        kind: "report-window".into(),
        observed_at: Some(range.to),
        content_hash: None,
        metadata: json!({"kind":kind,"from":range.from,"to":range.to}),
    })?;
    Ok(snapshot)
}

#[cfg(test)]
pub(super) fn fixture(tenant: TenantId) -> Snapshot {
    Snapshot::new(tenant, Purpose::Alert, Id::new())
}
