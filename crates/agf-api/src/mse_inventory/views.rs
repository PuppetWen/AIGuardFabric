//! Current views use exact configured scope; retained old snapshots never become a new account's inventory.
use super::{
    NAME, archive,
    contract::{Run, Scope},
    publication, scope, store,
};
use crate::{cloud_store, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};
use serde_json::{Value, json};

pub(super) async fn current_scope(state: &AppState, tenant: TenantId) -> DomainResult<Option<Scope>> {
    let Some(row) = cloud_store::load(state, tenant, NAME).await?.filter(|row| row.enabled) else {
        return Ok(None);
    };
    match scope::from_row(state, tenant, &row) {
        Ok(scope) => Ok(Some(scope)),
        Err(DomainError::Validation(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) async fn list(state: &AppState, tenant: TenantId) -> DomainResult<Value> {
    let current = current_scope(state, tenant).await?;
    let record = store::load(state, tenant).await?;
    let snapshot = publication::snapshot(state, tenant, &record)?;
    let visible = snapshot.as_ref().filter(|snapshot| current.as_ref() == Some(&snapshot.scope));
    let items = visible
        .into_iter()
        .flat_map(|snapshot| snapshot.services.iter())
        .map(|service| {
            json!({
                "key":service.key,"name":service.name,"groupName":service.group,"assetId":service.asset_id,
                "instanceCount":service.instance_count,"healthyInstanceCount":service.healthy_count,
                "clusterCount":service.cluster_count,"source":service.source,
                "endpoint":null,"protocol":null,"runtime":null,"networkZone":null,"metadata":null,
                "evidence":"ListAnsServices"
            })
        })
        .collect::<Vec<_>>();
    let now = Timestamp::now();
    let mut operations = record.runs.values().collect::<Vec<_>>();
    operations.sort_by(|left, right| {
        right.started_at.cmp(&left.started_at).then_with(|| right.request_id.cmp(&left.request_id))
    });
    operations.truncate(50);
    if let Some(active) = record.active.as_ref().and_then(|active| record.runs.get(&active.run_id)) {
        if !operations.iter().any(|run| run.request_id == active.request_id) {
            operations.pop();
            operations.insert(0, active);
        }
    }
    let operations = operations
        .into_iter()
        .map(|run| {
            let mut result = operation_at(run, current.as_ref(), now);
            result["archivable"] = json!(archive::archivable(&record, run));
            result
        })
        .collect::<Vec<_>>();
    let result = json!({
        "configured":current.is_some(),"scopeId":current.as_ref().map(|scope|scope.id),
        "configurationVersion":current.as_ref().map(|scope|scope.configuration_version),
        "sourceIdentity":current.as_ref().map(|scope|scope.source_identity.as_str()),
        "identityEvidence":"configured_source_digest","region":current.as_ref().map(|scope|scope.region.as_str()),
        "instanceId":current.as_ref().map(|scope|scope.instance_id.as_str()),
        "namespaceId":current.as_ref().map(|scope|scope.namespace_id.as_str()),
        "mocked":current.as_ref().map(|scope|scope.mocked),"inventoryAvailable":visible.is_some(),
        "totalServices":visible.map(|snapshot|snapshot.services.len()),"checkedAt":visible.map(|snapshot|snapshot.checked_at),
        "pagesRead":visible.map(|snapshot|snapshot.pages_read),"listingComplete":visible.is_some(),
        "coverage":"observed_pages","consistency":"not_strong_snapshot","items":items,"operations":operations,
        "generation":record.generation,"archivedCount":record.archived_count,
        "unavailableReason":if current.is_none(){Some("current_scope_unavailable")}else if snapshot.is_none(){Some("inventory_not_observed")}else if visible.is_none(){Some("snapshot_scope_mismatch")}else{None},
        "limits":{"maxServices":2000,"maxPages":20,"pageSize":100,"maxSeconds":110,"maxRuns":512,"maxRecordBytes":4_194_304}
    });
    if current_scope(state, tenant).await? != current {
        return Err(scope::stale());
    }
    Ok(result)
}

pub(super) fn operation(run: &Run, current: Option<&Scope>) -> Value {
    operation_at(run, current, Timestamp::now())
}

fn operation_at(run: &Run, current: Option<&Scope>, now: Timestamp) -> Value {
    let status = if run.status == "running" && now >= run.started_at.offset_secs(super::LEASE_SECS) {
        "interrupted"
    } else {
        &run.status
    };
    json!({"requestId":run.request_id,"scopeId":run.scope.id,"configurationVersion":run.scope.configuration_version,
        "mocked":run.scope.mocked,"region":run.scope.region,"instanceId":run.scope.instance_id,"namespaceId":run.scope.namespace_id,
        "sourceIdentity":run.scope.source_identity,"identityEvidence":"configured_source_digest",
        "status":status,"startedAt":run.started_at,"finishedAt":run.finished_at,
        "leaseExpiresAt":run.started_at.offset_secs(super::LEASE_SECS),"pagesRead":run.pages_read,
        "servicesObserved":run.services_observed,"published":run.published,"current":current == Some(&run.scope),
        "canCancel":run.status=="running","canRedispatch":false,"note":run.note,
        "archived":run.archived,"archivable":!run.archived && archive::terminal(run),
        "archivedAt":run.archived_at,"originalStatus":run.original_status})
}
