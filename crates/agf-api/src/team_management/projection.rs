//! Public fields are an explicit whitelist; encrypted provider receipts stay separate.
use super::{
    DIRECTORIES, context,
    contract::{DirectoryState, Operation, Preview, Record, Scope},
    input::ListQuery,
    store, users, validation,
};
use crate::{Principal, cloud_store, state::AppState};
use agf_core::{error::DomainResult, time::Timestamp};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) fn operation(op: &Operation, row: &Record, current: Option<&Scope>) -> Value {
    let busy = row.active.as_ref().is_some_and(|lease| lease.run == op.id && lease.expires_at > Timestamp::now());
    let recovery = current.filter(|scope| row.version == op.resource_version && context::same_target(scope, &op.scope));
    let current = recovery.is_some();
    let status = if !current {
        "superseded"
    } else if op.status == "started" && !busy {
        "uncertain"
    } else {
        &op.status
    };
    let mut actions = vec!["read_receipt"];
    if current && !busy {
        actions.push("observe");
        if matches!(op.readback.status.as_str(), "matched" | "absent") && op.inventory_publish.status != "published" {
            actions.push("retry_inventory");
        }
    }
    json!({"id":op.id,"requestId":op.request_id,"previewId":op.preview_id,"action":op.change.action(),"teamName":op.change.team(),
        "scopeId":op.scope.id,"configurationVersion":op.scope.configuration_version,"mocked":op.scope.mocked,"status":status,
        "recoveryScopeId":recovery.map(|scope|scope.id),"recoveryConfigurationVersion":recovery.map(|scope|scope.configuration_version),
        "startedAt":op.started_at,"finishedAt":op.finished_at,"leaseExpiresAt":op.lease_expires_at,"busy":busy,
        "cloudWrite":op.cloud_write,"readback":op.readback,"inventoryPublish":op.inventory_publish,"safeError":op.safe_error,"allowedActions":actions})
}
pub(super) fn preview(value: &Preview, row: &Record, current: Option<&Scope>) -> Value {
    let reason = if value.consumed_at.is_some() {
        Some("consumed")
    } else if value.expires_at <= Timestamp::now() {
        Some("expired")
    } else if current
        .is_none_or(|scope| !context::same_scope(scope, &value.scope) || scope.inventory_at != value.scope.inventory_at)
    {
        Some("scope-changed")
    } else if row.version != value.state_version {
        Some("version-changed")
    } else if row.unresolved_delete.is_some() {
        Some("unresolved-delete")
    } else if store::idle(row).is_err() {
        Some("operation-in-flight")
    } else {
        None
    };
    let before = value.baseline.as_ref();
    let before_members = before.and_then(|before| before.member_names.as_ref());
    let desired = value.change.members().map(|names| names.iter().cloned().collect::<BTreeSet<_>>());
    let existing = before_members.map(|names| names.iter().cloned().collect::<BTreeSet<_>>()).unwrap_or_default();
    let added =
        desired.as_ref().map(|names| names.difference(&existing).cloned().collect::<Vec<_>>()).unwrap_or_default();
    let removed =
        desired.as_ref().map(|names| existing.difference(names).cloned().collect::<Vec<_>>()).unwrap_or_default();
    let description_changed = value
        .change
        .description()
        .is_some_and(|desired| before.and_then(|before| before.description.as_deref()) != Some(desired));
    let members_changed = desired.as_ref().is_some_and(|desired| desired != &existing);
    let delete_impact=(value.change.action()=="delete").then(||json!({"workerCount":before.and_then(|before|before.worker_names.as_ref()).map(Vec::len),
        "humanCount":before_members.map(Vec::len),"roomCount":before.and_then(|before|before.rooms.as_ref()).map(Vec::len),"taskCount":value.task_count,"asyncCleanup":true}));
    let mut desired_fields = json!({});
    if let Some(description) = value.change.description() {
        desired_fields["description"] = json!(description);
    }
    if let Some(members) = value.change.members() {
        desired_fields["memberNames"] = json!(members);
    }
    if let Some(admin) = value.change.admin() {
        desired_fields["adminName"] = json!(admin);
    }
    json!({"id":value.id,"action":value.change.action(),"scopeId":value.scope.id,"configurationVersion":value.scope.configuration_version,"mocked":value.scope.mocked,
        "region":value.scope.region,"instanceId":value.scope.instance_id,"teamName":value.change.team(),"expectedStateVersion":value.state_version,
        "baselineObservedAt":value.observed_at,"baselineComplete":true,"baselineHash":value.baseline_hash,"descriptionChanged":description_changed,"membersChanged":members_changed,
        "before":{"description":before.and_then(|before|before.description.as_deref()),"memberNames":before_members,"memberNamesAvailable":before_members.is_some(),
            "adminName":before.and_then(|before|before.admin_name.as_deref()),"leaderName":before.and_then(|before|before.leader_name.as_deref()),
            "workerNames":before.and_then(|before|before.worker_names.as_ref()),"workerNamesAvailable":before.is_some_and(|before|before.worker_names.is_some())},
        "desired":desired_fields,"addedMembers":added,"removedMembers":removed,
        "verifiedUsers":value.verified_users,"deleteImpact":delete_impact,"expiresAt":value.expires_at,"previewUsable":reason.is_none(),"unusableReason":reason})
}
pub(super) async fn list(state: &AppState, principal: &Principal, query: ListQuery) -> DomainResult<Value> {
    let ctx = context::available(state, principal.tenant).await?;
    let cfg = cloud_store::load(state, principal.tenant, crate::cloud_inventory::NAME).await?;
    let rows = store::list(state, principal.tenant).await?;
    let mut teams = BTreeSet::new();
    if let Some(ctx) = &ctx {
        for team in &ctx.inventory.teams {
            if let Some(name) = team["Name"].as_str() {
                teams.insert(name.to_owned());
            }
        }
    }
    for row in &rows {
        teams.insert(row.team_name.clone());
    }
    let mut items = Vec::new();
    let mut operations = Vec::new();
    for name in teams {
        let row = rows.iter().find(|row| {
            row.team_name == name
                && ctx
                    .as_ref()
                    .is_none_or(|ctx| context::record_id(principal.tenant, &ctx.scope, &name).ok() == Some(row.id))
        });
        let current = ctx
            .as_ref()
            .and_then(|ctx| {
                ctx.inventory
                    .teams
                    .iter()
                    .find(|team| team["Name"] == name)
                    .map(|team| validation::team(team, &name, &ctx.scope.instance_id))
            })
            .transpose()?;
        items.push(json!({"teamName":name,"stateVersion":row.map_or(0,|row|row.version),"busy":row.is_some_and(|row|store::idle(row).is_err()),
            "unresolvedDelete":row.is_some_and(|row|row.unresolved_delete.is_some()),"currentAvailable":current.is_some(),"description":current.as_ref().and_then(|team|team.description.as_deref()),
            "memberNames":current.as_ref().and_then(|team|team.member_names.as_ref()),"memberNamesAvailable":current.as_ref().is_some_and(|team|team.member_names.is_some()),
            "adminName":current.as_ref().and_then(|team|team.admin_name.as_deref()),"leaderName":current.as_ref().and_then(|team|team.leader_name.as_deref()),
            "workerNames":current.as_ref().and_then(|team|team.worker_names.as_ref()),"relationshipAvailable":current.as_ref().is_some_and(|team|team.worker_names.is_some())}));
    }
    for row in &rows {
        for op in row.operations.values().filter(|op| query.request_id.is_none_or(|request| request == op.request_id)) {
            operations.push(operation(op, row, ctx.as_ref().map(|ctx| &ctx.scope)));
        }
    }
    operations.sort_by(|a, b| b["startedAt"].as_str().cmp(&a["startedAt"].as_str()));
    let directory = state
        .configurations
        .get::<Option<DirectoryState>>(principal.tenant, DIRECTORIES, users::key(principal.tenant))
        .await?
        .flatten();
    let mut directory = directory
        .filter(|row| ctx.as_ref().is_some_and(|ctx| context::same_scope(&row.scope, &ctx.scope)))
        .and_then(|row| row.latest);
    if let Some(page) = &mut directory {
        if page.observed_at.age_secs() >= 300 {
            page.selection_usable = false;
            page.unusable_reason = Some("expired".into());
        }
    }
    let can_prepare = ctx.is_some() && principal.require(state, "alicloud", "write").is_ok();
    Ok(
        json!({"scopeId":ctx.as_ref().map(|ctx|ctx.scope.id),"region":ctx.as_ref().map(|ctx|&ctx.scope.region),"instanceId":ctx.as_ref().map(|ctx|&ctx.scope.instance_id),
        "configurationVersion":cfg.as_ref().map_or(0,|cfg|cfg.version),"mocked":ctx.as_ref().map(|ctx|ctx.scope.mocked),"inventoryAvailable":ctx.is_some(),"enabled":cfg.is_some_and(|cfg|cfg.enabled),
        "canPrepare":can_prepare,"canWrite":can_prepare&&principal.require(state,"assets","write").is_ok(),"items":items,"userDirectory":directory,"operations":operations}),
    )
}
