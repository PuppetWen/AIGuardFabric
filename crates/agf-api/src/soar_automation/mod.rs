//! Versioned alert automations: one durable decision per template and alert identity.
use crate::{
    middleware::Principal,
    soar_workflow::{self as workflow, Actor},
    state::AppState,
};
use agf_core::{
    alert::Alert,
    audit::{AuditAction, AuditOutcome, AuditTarget},
    case::Playbook,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use agf_storage::configuration::AuditedMutation;
use serde::{Deserialize, Serialize};

mod external_targets;
mod inputs;
mod storage;
mod worker;
pub use inputs::preview;
pub use storage::deliveries;
pub use storage::summaries;
pub use worker::tick;
pub const KIND: &str = "soar-automation";
pub const DELIVERY: &str = "soar-automation-delivery";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    pub version: u64,
    pub at: Timestamp,
    pub actor: String,
    pub note: String,
    pub enabled: bool,
    pub playbook: Playbook,
    pub separate_approver: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Automation {
    pub id: Id,
    pub tenant_id: TenantId,
    pub playbook: Playbook,
    pub enabled: bool,
    pub separate_approver: bool,
    pub version: u64,
    pub published_by: Actor,
    pub mock_mode: bool,
    pub since: Timestamp,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    #[serde(default)]
    pub history: Vec<Revision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delivery {
    pub id: Id,
    pub automation_id: Id,
    pub automation_version: u64,
    pub alert_id: Id,
    pub alert_title: String,
    pub status: String,
    pub reason: String,
    pub case_id: Option<Id>,
    pub run_id: Option<Id>,
    pub attempts: u32,
    pub at: Timestamp,
    #[serde(default)]
    pub history: Vec<Attempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attempt {
    pub at: Timestamp,
    pub actor: String,
    pub status: String,
    pub reason: String,
}
impl Delivery {
    fn record(&mut self, actor: String) {
        self.history.push(Attempt { at: self.at, actor, status: self.status.clone(), reason: self.reason.clone() });
        if self.history.len() > 20 {
            self.history.remove(0);
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Change {
    pub expected_version: u64,
    pub playbook: Playbook,
    pub enabled: bool,
    #[serde(default)]
    pub separate_approver: bool,
    pub reason: String,
}

pub fn can_manage(state: &AppState, principal: &Principal) -> bool {
    workflow::can_approve(state, principal) && principal.require(state, "alerts", "read").is_ok()
}

pub async fn get(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Automation> {
    state
        .configurations
        .get(tenant, KIND, id)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "soar-automation", id: id.to_string() })
}

pub async fn save(state: &AppState, principal: &Principal, id: Id, input: Change) -> DomainResult<Automation> {
    if !can_manage(state, principal) {
        return Err(DomainError::Forbidden("自动响应配置需要人工账号 cases:admin 和 alerts:read 权限".into()));
    }
    workflow::validate(&input.playbook)?;
    if input.enabled {
        external_targets::validate(state, principal, &input.playbook).await?;
    }
    if input.enabled && !input.playbook.enabled {
        return Err(DomainError::Validation("启用自动响应前请将剧本 enabled 设为 true".into()));
    }
    if input.reason.trim().is_empty() || input.reason.len() > 2000 {
        return Err(DomainError::Validation("变更说明须为 1–2000 字节".into()));
    }
    let actor = Actor::from_principal(principal)?;
    let now = Timestamp::now();
    let version =
        input.expected_version.checked_add(1).ok_or_else(|| DomainError::Conflict("配置版本超出范围".into()))?;
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Update,
        AuditOutcome::Success,
        AppState::audit_actor(principal, "soar-automation"),
        AuditTarget::new("soar-automation", Some(id.to_string()), Some(input.playbook.name.clone())),
        &format!("自动响应版本 {version}，enabled={}", input.enabled),
    );
    // Offline memory has one shared lock; SQL uses the same advisory record lock as the worker commit.
    let _guard = state.soar_automation_lock.lock().await;
    let (row, sealed) = state
        .configurations
        .mutate_bounded_audited_with::<Option<Automation>, _, _>(
            principal.tenant,
            KIND,
            id,
            AuditedMutation { limit: Some(50), audit },
            |slot| {
                let previous = slot.as_ref();
                if previous.map_or(0, |row| row.version) != input.expected_version {
                    return Err(DomainError::Conflict("配置已被其他人更新，请重新读取后核对".into()));
                }
                let mut history = previous.map_or_else(Vec::new, |row| row.history.clone());
                history.push(Revision {
                    version,
                    at: now,
                    actor: actor.display(),
                    note: input.reason.trim().into(),
                    enabled: input.enabled,
                    playbook: input.playbook.clone(),
                    separate_approver: input.separate_approver,
                });
                if history.len() > 20 {
                    history.remove(0);
                }
                *slot = Some(Automation {
                    id,
                    tenant_id: principal.tenant,
                    playbook: input.playbook,
                    enabled: input.enabled,
                    separate_approver: input.separate_approver,
                    version,
                    published_by: actor,
                    mock_mode: state.config.mock_mode,
                    since: previous.filter(|row| row.enabled && input.enabled).map_or(now, |row| row.since),
                    created_at: previous.map_or(now, |row| row.created_at),
                    updated_at: now,
                    history,
                });
                Ok(())
            },
            |audit| state.store.audit_append(audit).map(Some),
        )
        .await?;
    // SQL is authoritative; its projection refresh cannot turn a committed revision into a failed save.
    // Offline mode appended under the configuration lock and must not append or hydrate a second time.
    if state.store.database().is_some() {
        if let Some(sealed) = sealed {
            if let Err(error) = state.store.hydrate_audit(&sealed) {
                tracing::warn!(%error, "已提交的自动响应审计内存投影刷新失败");
            }
        }
    }
    row.ok_or_else(|| DomainError::Internal("自动响应配置保存失败".into()))
}

pub async fn retry(
    state: &AppState,
    principal: &Principal,
    automation: Id,
    id: Id,
    version: u64,
) -> DomainResult<Delivery> {
    if !can_manage(state, principal) {
        return Err(DomainError::Forbidden("重试需要自动响应管理权限".into()));
    }
    let _guard = state.soar_automation_lock.lock().await;
    let template = get(state, principal.tenant, automation).await?;
    if !template.enabled || template.version != version {
        return Err(DomainError::Conflict("配置版本改变或已停用，请重新核对".into()));
    }
    state
        .configurations
        .mutate::<Option<Delivery>, _>(principal.tenant, DELIVERY, id, |slot| {
            let row =
                slot.as_mut().ok_or_else(|| DomainError::NotFound { entity: "soar-delivery", id: id.to_string() })?;
            if row.automation_id != automation {
                return Err(DomainError::NotFound { entity: "soar-delivery", id: id.to_string() });
            }
            if row.status != "failed" || row.automation_version != version {
                return Err(DomainError::Conflict("只可重试当前版本的失败触发；已提交任务请到案件查看".into()));
            }
            row.status = "pending".into();
            row.reason = format!("{} 请求重新评估", principal.display());
            row.at = Timestamp::now();
            row.record(principal.display());
            Ok(())
        })
        .await?
        .ok_or_else(|| DomainError::Internal("触发记录消失".into()))
}

fn delivery_id(tenant: TenantId, automation: Id, alert: Id) -> Id {
    deterministic_id("agf.soar.trigger", &format!("{tenant}:{automation}:{alert}"))
}
