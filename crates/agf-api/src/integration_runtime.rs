//! Tenant/version scoped adapters and durable, idempotent operation receipts.
use crate::{integration_store as config, state::AppState};
use agf_adapters::{
    contract::{AdapterMessage, SyncRequest, VendorAdapter},
    health::AdapterHealthRecord,
};
use agf_core::{
    adapter::{PullRequest, PushPayload},
    audit::AuditActor,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::integration_receipts::Run;
type Entries = BTreeMap<(TenantId, String), Arc<Mutex<Option<Entry>>>>;
struct Entry {
    version: u64,
    adapter: Box<dyn VendorAdapter>,
}
#[derive(Default)]
pub struct Registry {
    entries: Mutex<Entries>,
}
impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntegrationRegistry").finish_non_exhaustive()
    }
}
impl Registry {
    async fn acquire(&self, tenant: TenantId, name: &str) -> OwnedMutexGuard<Option<Entry>> {
        let slot = self
            .entries
            .lock()
            .await
            .entry((tenant, name.into()))
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();
        slot.lock_owned().await
    }
    pub async fn health(
        &self,
        tenant: TenantId,
        name: &str,
        version: u64,
    ) -> DomainResult<Option<AdapterHealthRecord>> {
        let slot = self.entries.lock().await.get(&(tenant, name.into())).cloned();
        let Some(slot) = slot else {
            return Ok(None);
        };
        let Ok(entry) = slot.try_lock() else {
            return Ok(None);
        };
        match entry.as_ref().filter(|entry| entry.version == version) {
            Some(entry) => Ok(Some(entry.adapter.health_check().await?)),
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", content = "payload", rename_all = "lowercase")]
pub enum Operation {
    Send(AdapterMessage),
    Push(PushPayload),
    Pull(PullRequest),
    Sync(SyncRequest),
}
impl Operation {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Send(_) => "send",
            Self::Push(_) => "push",
            Self::Pull(_) => "pull",
            Self::Sync(_) => "sync",
        }
    }
    fn validate(&mut self) -> DomainResult<()> {
        let limit = match self {
            Self::Pull(req) => Some(&mut req.limit),
            Self::Sync(req) => Some(&mut req.limit),
            _ => None,
        };
        if let Some(limit) = limit {
            if limit.is_some_and(|n| !(1..=1000).contains(&n)) {
                return Err(DomainError::Validation("每次读取条数必须在 1 到 1000 之间".into()));
            }
            *limit = Some(limit.unwrap_or(100));
        }
        if let Self::Send(msg) = self {
            if msg.title.trim().is_empty() || msg.title.len() > 1024 || msg.idempotency_key.trim().is_empty() {
                return Err(DomainError::Validation("请输入标题（最多 1024 字节）和业务幂等键".into()));
            }
        }
        if let Self::Sync(req) = self {
            if req.local.len() > 1000 {
                return Err(DomainError::Validation("每次同步最多 1000 个本地快照".into()));
            }
        }
        Ok(())
    }
    async fn invoke(&self, adapter: &mut dyn VendorAdapter) -> DomainResult<Value> {
        match self {
            Self::Send(body) => Ok(serde_json::to_value(adapter.send(body).await?)?),
            Self::Push(body) => Ok(serde_json::to_value(adapter.push(body).await?)?),
            Self::Pull(body) => Ok(serde_json::to_value(adapter.pull(body).await?)?),
            Self::Sync(body) => Ok(serde_json::to_value(adapter.sync(body).await?)?),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub request_id: Id,
    pub configuration_version: u64,
    #[serde(default)]
    pub confirm_live: bool,
    #[serde(flatten)]
    pub action: Operation,
}
pub async fn history(state: &AppState, tenant: TenantId, name: &str) -> DomainResult<Vec<Value>> {
    config::vendor(name)?;
    crate::integration_receipts::history(state, tenant, name).await
}
pub async fn execute(
    state: &AppState,
    tenant: TenantId,
    name: &str,
    actor: String,
    body: Request,
) -> DomainResult<Value> {
    execute_inner(
        state,
        tenant,
        name,
        actor,
        body,
        false,
        crate::integration_receipts::internal_actor("integration-runtime"),
    )
    .await
}

pub(crate) async fn execute_authorized(
    state: &AppState,
    principal: &crate::Principal,
    name: &str,
    body: Request,
) -> DomainResult<Value> {
    execute_inner(
        state,
        principal.tenant,
        name,
        principal.display(),
        body,
        false,
        AppState::audit_actor(principal, "integration-operation"),
    )
    .await
}

/// Only the approved, durable case executor may send a live EDR isolation command.
pub(crate) async fn execute_approved_edr(
    state: &AppState,
    tenant: TenantId,
    actor: AuditActor,
    body: Request,
) -> DomainResult<Value> {
    if !matches!(&body.action, Operation::Send(_)) {
        return Err(DomainError::Validation("案件 EDR 审批只接受隔离指令".into()));
    }
    execute_inner(state, tenant, "edr-isolation", actor.name.clone(), body, true, actor).await
}

/// Only the durable case worker may deactivate a Live SCIM identity.
pub(crate) async fn execute_approved_iam(
    state: &AppState,
    tenant: TenantId,
    actor: AuditActor,
    body: Request,
) -> DomainResult<Value> {
    if !matches!(&body.action, Operation::Send(_)) {
        return Err(DomainError::Validation("案件 IAM 审批只接受身份停用指令".into()));
    }
    execute_inner(state, tenant, "iam-scim", actor.name.clone(), body, true, actor).await
}

async fn execute_inner(
    state: &AppState,
    tenant: TenantId,
    name: &str,
    actor: String,
    mut body: Request,
    approved_case_action: bool,
    audit_actor: AuditActor,
) -> DomainResult<Value> {
    body.action.validate()?;
    let encoded = serde_json::to_vec(&body)?;
    if encoded.len() > 65536 {
        return Err(DomainError::Validation("集成调用载荷最多 64 KiB".into()));
    }
    let request_hash = format!("{:x}", Sha256::digest(&encoded));
    let id = deterministic_id("agf.integration.run", &format!("{tenant}:{name}:{}", body.request_id));
    let mut guard = state.integration_runtime.acquire(tenant, name).await;
    let row = config::load(state, tenant, name)
        .await?
        .filter(|row| row.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("请先启用集成配置".into()))?;
    let mocked = state.config.mock_mode || row.mock;
    if name == "edr-isolation" && !mocked && !approved_case_action && !matches!(&body.action, Operation::Pull(_)) {
        return Err(DomainError::PreconditionFailed(
            "EDR 真实写操作只能从关联资产的持久化案件任务审批后执行；集成中心仅允许读取或 Mock 验证".into(),
        ));
    }
    if name == "iam-scim" && !mocked && !approved_case_action {
        return Err(DomainError::PreconditionFailed(
            "SCIM 真实身份停用只能从关联资产的持久化案件任务审批后执行；集成中心仅允许 Mock 验证".into(),
        ));
    }
    if row.version != body.configuration_version {
        return Err(DomainError::Conflict("配置已改变，请重新加载后确认目标".into()));
    }
    if !mocked && !body.confirm_live {
        return Err(DomainError::PreconditionFailed("真实业务调用需要 confirm_live=true".into()));
    }
    let private = config::decrypt(state, tenant, &row)?;
    if guard.as_ref().is_none_or(|entry| entry.version != row.version) {
        *guard = Some(Entry { version: row.version, adapter: config::adapter(state, tenant, &row, &private)? });
    }
    let run = Run {
        id,
        request_id: body.request_id,
        adapter: name.into(),
        operation: body.action.name().into(),
        configuration_version: row.version,
        request_hash,
        actor,
        started_at: Timestamp::now(),
        finished_at: None,
        status: "started".into(),
        mocked,
        result: None,
    };
    let entry = guard.as_mut().ok_or_else(|| DomainError::Config("适配器未初始化".into()))?;
    let can_write = !matches!(body.action, Operation::Pull(_));
    Box::pin(crate::integration_receipts::execute_audited(
        state,
        tenant,
        run,
        &private.secrets,
        can_write,
        audit_actor,
        body.action.invoke(entry.adapter.as_mut()),
    ))
    .await
}
