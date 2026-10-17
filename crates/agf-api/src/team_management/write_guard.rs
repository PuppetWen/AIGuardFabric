//! Preflight shares the runtime's resolved client and cannot recursively acquire its mutex.
use super::{context, contract::Preview, input::Change, mock, store, validation};
use crate::{Principal, state::AppState};
use agf_alicloud::{
    http::RpcClient,
    openapi::{ResourceObservation, contract},
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde_json::{Value, json};

pub(super) struct Guard<'a> {
    pub state: &'a AppState,
    pub principal: &'a Principal,
    pub preview: &'a Preview,
    pub run: Id,
    pub live: bool,
}
#[async_trait::async_trait]
impl crate::cloud_runtime::WritePrecondition for Guard<'_> {
    async fn validate(&self) -> DomainResult<()> {
        let ctx = context::checked(self.state, self.principal, &self.preview.scope, self.live).await?;
        if ctx.scope.inventory_at != self.preview.scope.inventory_at {
            return Err(super::stale());
        }
        let row = store::get(self.state, self.principal.tenant, self.preview.record_id).await?;
        let op = row.operations.get(&self.run).ok_or_else(super::stale)?;
        context::authority(self.state, self.principal, true, op.started_at).await?;
        store::owns(&row, self.run, op.request_id)?;
        if row.operations.get(&self.run).is_none_or(|op| op.preview_id != self.preview.id) {
            return Err(super::stale());
        }
        Ok(())
    }
    async fn preflight(&self, client: Option<&RpcClient>) -> DomainResult<()> {
        let data = self.read(client, "GetTeam", self.preview.change.team()).await?;
        let observed = data
            .map(|value| validation::team(&value, self.preview.change.team(), &self.preview.scope.instance_id))
            .transpose()?;
        if validation::hash(&observed)? != self.preview.baseline_hash {
            return Err(DomainError::Conflict("云端团队内容改变，旧预览已失效；请重新观察和预览".into()));
        }
        if matches!(self.preview.change, Change::Create { .. }) && observed.is_some() {
            return Err(super::stale());
        }
        for user in &self.preview.verified_users {
            let value = self
                .read(client, "GetUser", &user.name)
                .await?
                .ok_or_else(|| DomainError::PreconditionFailed("目标云用户已不存在".into()))?;
            validation::user(&value, &self.preview.scope.instance_id, Some(&user.name))?;
        }
        Ok(())
    }
}
impl Guard<'_> {
    async fn read(&self, client: Option<&RpcClient>, action: &str, name: &str) -> DomainResult<Option<Value>> {
        let Some(client) = client else {
            return mock::resource_direct(self.state, self.principal.tenant, &self.preview.scope, action, name).await;
        };
        match contract(AliCloudService::AgentTeams, action)?
            .observe_resource(client, &json!({"InstanceId":self.preview.scope.instance_id,"Name":name}))
            .await?
        {
            ResourceObservation::Present(response) => Ok(Some(response.body["Data"].clone())),
            ResourceObservation::Absent { .. } => Ok(None),
        }
    }
}
