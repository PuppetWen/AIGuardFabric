//! Exact current scope determines visibility; retained historical observations stay local and explicit.
use super::{
    NAME, archive,
    contract::{Run, Scope, Snapshot},
    graph, publication, scope, store,
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
    let graph = visible.map(graph::project).transpose()?.unwrap_or_else(|| json!({"nodes":[],"edges":[]}));
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
    let now = Timestamp::now();
    let operations = operations
        .into_iter()
        .map(|run| {
            let mut result = operation_at(run, current.as_ref(), now);
            result["archivable"] = json!(archive::archivable(&record, run));
            result
        })
        .collect::<Vec<_>>();
    let unavailable = if current.is_none() {
        Some("current_scope_unavailable")
    } else if snapshot.is_none() {
        Some("topology_not_observed")
    } else if visible.is_none() {
        Some("snapshot_scope_mismatch")
    } else {
        None
    };
    let result = json!({
        "configured":current.is_some(),"scopeId":current.as_ref().map(|scope|scope.id),
        "configurationVersion":current.as_ref().map(|scope|scope.configuration_version),
        "sourceIdentity":current.as_ref().map(|scope|scope.source_identity.as_str()),"identityEvidence":"configured_source_digest",
        "region":current.as_ref().map(|scope|scope.region.as_str()),"endpointId":current.as_ref().map(|scope|scope.endpoint_id.as_str()),
        "mocked":current.as_ref().map(|scope|scope.mocked),"topologyAvailable":visible.is_some(),"checkedAt":visible.map(|snapshot|snapshot.checked_at),
        "pagesRead":visible.map(|snapshot|snapshot.pages_read),"listingComplete":visible.is_some(),
        "coverage":"selected_endpoint","consistency":"not_strong_snapshot","networkReachability":null,"authorizationAllowed":null,
        "endpoint":visible.map(endpoint),"graph":graph,"operations":operations,"generation":record.generation,
        "archivedCount":record.archived_count,"unavailableReason":unavailable,
        "limits":{"maxPages":40,"maxPagesPerList":20,"pageSize":50,"maxChildRecords":2000,"maxSeconds":110,"maxRuns":512,"maxRecordBytes":4_194_304}
    });
    if current_scope(state, tenant).await? != current {
        return Err(scope::stale());
    }
    Ok(result)
}

fn endpoint(snapshot: &Snapshot) -> Value {
    let endpoint = &snapshot.endpoint;
    let zones = snapshot
        .zones
        .iter()
        .map(|zone| {
            json!({"zoneId":zone.id,"region":zone.region,"status":zone.status,
        "eniId":zone.eni_id,"vSwitchId":zone.vswitch_id,"eniIp":zone.eni_ip,"ipv6":zone.ipv6,"domain":zone.domain})
        })
        .collect::<Vec<_>>();
    let groups = snapshot
        .security_groups
        .iter()
        .map(|group| json!({"securityGroupId":group.id,"status":group.status}))
        .collect::<Vec<_>>();
    json!({"assetId":snapshot.asset_id,"endpointId":endpoint.id,"name":endpoint.name,"region":endpoint.region,
        "vpcId":endpoint.vpc_id,"serviceId":endpoint.service_id,"serviceRegionId":endpoint.service_region_id,
        "domain":endpoint.domain,"endpointType":endpoint.endpoint_type,"endpointStatus":endpoint.status,
        "connectionStatus":endpoint.connection_status,"businessStatus":endpoint.business_status,
        "zonesAvailable":true,"securityGroupsAvailable":true,"zones":zones,"securityGroups":groups})
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
        "mocked":run.scope.mocked,"region":run.scope.region,"endpointId":run.scope.endpoint_id,"sourceIdentity":run.scope.source_identity,
        "identityEvidence":"configured_source_digest","status":status,"startedAt":run.started_at,"finishedAt":run.finished_at,
        "leaseExpiresAt":run.started_at.offset_secs(super::LEASE_SECS),"pagesRead":run.pages_read,"endpointsObserved":run.endpoints_observed,
        "zonesObserved":run.zones_observed,"securityGroupsObserved":run.security_groups_observed,"published":run.published,
        "current":current==Some(&run.scope),"canCancel":run.status=="running","canRedispatch":false,"note":run.note,
        "archived":run.archived,"archivable":!run.archived && archive::terminal(run),"archivedAt":run.archived_at,"originalStatus":run.original_status})
}
