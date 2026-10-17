//! Full inventory publication and native receipt advancement share one SQL transaction.
use super::{
    KIND, context,
    contract::{Operation, Scope},
    store, validation,
};
use crate::{
    Principal,
    cloud_inventory::{self, Snapshot, SyncRequest},
    state::AppState,
    store::asset_transaction::AssetTransaction,
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    time::Timestamp,
};
use serde_json::Value;

#[async_trait::async_trait]
pub(crate) trait InventoryPublication: Send + Sync {
    fn validate_snapshot(&self, snapshot: &Snapshot) -> DomainResult<()>;
    async fn in_transaction(&self, tx: &AssetTransaction<'_>, snapshot: &Snapshot) -> DomainResult<()>;
    async fn offline(&self, state: &AppState, snapshot: &Snapshot) -> DomainResult<()>;
}
struct Publication<'a> {
    state: &'a AppState,
    principal: &'a Principal,
    scope: &'a Scope,
    operation: &'a Operation,
    claim: Id,
    authorized_at: Timestamp,
}
impl Publication<'_> {
    fn advance(&self, row: &mut super::contract::Record, snapshot: &Snapshot) -> DomainResult<()> {
        if row.version != self.operation.resource_version {
            return Err(super::stale());
        }
        store::owns(row, self.operation.id, self.claim)?;
        let op = row.operations.get_mut(&self.operation.id).ok_or_else(super::stale)?;
        if !matches!(op.readback.status.as_str(), "matched" | "absent") {
            return Err(super::stale());
        }
        op.inventory_publish.status = "published".into();
        op.inventory_publish.checked_at = Some(snapshot.checked_at);
        op.inventory_publish.error_code = None;
        op.status = "verified".into();
        op.finished_at = Some(Timestamp::now());
        op.safe_error = None;
        row.active = None;
        row.scope = Some(self.scope.clone());
        store::bounded(row)
    }
}
#[async_trait::async_trait]
impl InventoryPublication for Publication<'_> {
    fn validate_snapshot(&self, snapshot: &Snapshot) -> DomainResult<()> {
        if snapshot.version != self.scope.configuration_version
            || snapshot.mocked != self.scope.mocked
            || snapshot.region != self.scope.region
            || snapshot.instance_id != self.scope.instance_id
        {
            return Err(super::stale());
        }
        let data = snapshot.teams.iter().find(|team| team["Name"] == self.operation.change.team());
        let team =
            data.map(|data| validation::team(data, self.operation.change.team(), &snapshot.instance_id)).transpose()?;
        if !validation::matches(&self.operation.change, team.as_ref()) {
            return Err(DomainError::Conflict("完整盘点中的团队内容与已确认目标不一致，未发布新快照".into()));
        }
        Ok(())
    }
    async fn in_transaction(&self, tx: &AssetTransaction<'_>, snapshot: &Snapshot) -> DomainResult<()> {
        context::authority(self.state, self.principal, true, self.authorized_at).await?;
        tx.configuration_lock(KIND, self.operation.record_id).await?;
        let mut row = tx
            .configuration::<super::contract::Record>(KIND, self.operation.record_id)
            .await?
            .ok_or_else(super::stale)?;
        self.advance(&mut row, snapshot)?;
        store::save_indexes(tx, &row).await
    }
    async fn offline(&self, state: &AppState, snapshot: &Snapshot) -> DomainResult<()> {
        context::authority(state, self.principal, true, self.authorized_at).await?;
        state
            .configurations
            .mutate::<super::contract::Record, _>(self.principal.tenant, KIND, self.operation.record_id, |row| {
                self.advance(row, snapshot)
            })
            .await?;
        Ok(())
    }
}
pub(super) async fn run(
    state: &AppState,
    principal: &Principal,
    op: &Operation,
    scope: &Scope,
    claim: Id,
    live: bool,
) -> DomainResult<Value> {
    principal.require(state, "assets", "write").map_err(|error| error.error)?;
    context::checked(state, principal, scope, live).await?;
    let row = store::get(state, principal.tenant, op.record_id).await?;
    store::owns(&row, op.id, claim)?;
    let authorized_at = row.active.as_ref().ok_or_else(super::stale)?.authorized_at;
    context::authority(state, principal, true, authorized_at).await?;
    let hook = Publication { state, principal, scope, operation: op, claim, authorized_at };
    let request = SyncRequest {
        request_id: deterministic_id("agf.team-management.publish", &format!("{}:{claim}", op.id)),
        configuration_version: scope.configuration_version,
        confirm_live: live,
    };
    cloud_inventory::sync_for_team(
        state,
        principal.tenant,
        principal.display(),
        AppState::audit_actor(principal, "agentteams-team-management"),
        request,
        &hook,
    )
    .await
}
