//! SOAR actions affect managed gateways, stored credentials and configured notification channels.
use crate::{
    containment::{self, Control},
    error::ApiResult,
    middleware::Principal,
    state::AppState,
};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    case::ContainmentAction,
    enums::{AssetKind, CaseState},
    error::DomainError,
    ids::Id,
    time::Timestamp,
};
use agf_correlate::playbook::{ActionExecutor, ApprovalGate, NotifySink, RunContext, WaitOutcome};
use async_trait::async_trait;

mod edr;
mod iam;
pub use edr::WorkflowStep;

#[derive(Clone)]
pub struct Executor {
    pub state: AppState,
    pub principal: Principal,
    pub workflow_step: Option<WorkflowStep>,
}
impl std::fmt::Debug for Executor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SoarExecutor")
    }
}
#[derive(Debug)]
pub struct Approval {
    pub approved: bool,
}
#[async_trait]
impl ApprovalGate for Approval {
    async fn approve(&self, _: &RunContext, _: &str) -> Result<bool, String> {
        Ok(self.approved)
    }
}
impl Executor {
    fn parameter<'a>(ctx: &'a RunContext, key: &str) -> ApiResult<&'a str> {
        ctx.params
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.trim().is_empty() && v.len() <= 1024)
            .ok_or_else(|| DomainError::Validation(format!("动作缺少有效参数 {key}")).into())
    }
    async fn action(&self, action: ContainmentAction, ctx: &RunContext) -> ApiResult<String> {
        if ctx.tenant_id != self.principal.tenant {
            return Err(DomainError::Forbidden("处置租户不匹配".into()).into());
        }
        let case_id = ctx.case_id.ok_or_else(|| DomainError::Validation("处置缺少案件".into()))?;
        let case = self
            .state
            .store
            .case_get_durable(ctx.tenant_id, case_id)
            .await?
            .ok_or_else(|| DomainError::NotFound { entity: "case", id: case_id.to_string() })?;
        if action == ContainmentAction::IsolateHost {
            return self.isolate_host(ctx, &case).await;
        }
        if action == ContainmentAction::DeactivateExternalUser {
            return self.deactivate_external_user(ctx, &case).await;
        }
        if action == ContainmentAction::NotifyOwner {
            return self
                .notify_impl(ctx.params.get("channel").map_or("in-app", String::as_str), ctx, &case.title)
                .await;
        }
        if action == ContainmentAction::Archive {
            self.principal.require(&self.state, "cases", "write")?;
            let reason = Self::parameter(ctx, "reason")?;
            // Never invent intermediate investigation/resolution transitions.
            self.state
                .store
                .case_set_state_durable(
                    ctx.tenant_id,
                    case_id,
                    CaseState::Closed,
                    Some(reason.into()),
                    &self.principal.display(),
                )
                .await?;
            return Ok("案件已关闭归档".into());
        }
        if action == ContainmentAction::RevokeCredential {
            self.principal.require(&self.state, "settings", "admin")?;
            let id = crate::routes::parse_id(Self::parameter(ctx, "api_key_id")?, "api-key")?;
            let mut audit = AppState::audit_entry(
                ctx.tenant_id,
                AuditAction::Grant,
                AuditOutcome::Success,
                AppState::audit_actor(&self.principal, "soar-api-key-revoke"),
                AuditTarget::new("api-key", Some(id.to_string()), None),
                "SOAR revoked a platform API Key; other playbook steps keep their own outcomes",
            );
            audit.after = Some(serde_json::json!({"id":id,"revoked":true,"case_id":case_id}));
            self.state.store.api_key_revoke_audited(ctx.tenant_id, id, audit).await?;
            return Ok(format!("API Key {id} 已吊销；请创建新密钥重新接入"));
        }
        self.principal.require(&self.state, "policies", "write")?;
        let mut row = Control {
            id: Id::new(),
            case_id,
            action,
            target: String::new(),
            tools: Vec::new(),
            endpoint_id: None,
            active: true,
            actor: self.principal.display(),
            reason: ctx.params.get("reason").cloned().unwrap_or_else(|| format!("案件 {} 处置", case.code)),
            created_at: Timestamp::now(),
            released_by: None,
            released_at: None,
        };
        match action {
            ContainmentAction::IsolateAgent
            | ContainmentAction::ForceLocalModel
            | ContainmentAction::DisableMcpServer
            | ContainmentAction::RevokeSkill => {
                let expected = match action {
                    ContainmentAction::DisableMcpServer => AssetKind::McpServer,
                    ContainmentAction::RevokeSkill => AssetKind::Skill,
                    _ => AssetKind::Agent,
                };
                let id = if let Some(value) = ctx.params.get("asset_id") {
                    crate::routes::parse_id(value, "asset")?
                } else {
                    let mut candidates = Vec::new();
                    for id in &ctx.asset_ids {
                        if self
                            .state
                            .store
                            .asset_get_durable(ctx.tenant_id, *id)
                            .await?
                            .is_some_and(|asset| asset.kind == expected)
                        {
                            candidates.push(*id);
                        }
                    }
                    if candidates.len() != 1 {
                        return Err(DomainError::Validation(format!(
                            "关联的 {} 资产不是唯一目标，请明确填写 asset_id",
                            expected.as_str()
                        ))
                        .into());
                    }
                    candidates[0]
                };
                if !case.asset_ids.contains(&id) {
                    return Err(DomainError::Validation("只能处置当前案件关联资产".into()).into());
                }
                let asset = self
                    .state
                    .store
                    .asset_get_durable(ctx.tenant_id, id)
                    .await?
                    .filter(|asset| asset.kind == expected)
                    .ok_or_else(|| {
                        DomainError::Validation(format!("处置目标必须是当前租户的 {}", expected.as_str()))
                    })?;
                row.target = id.to_string();
                if action == ContainmentAction::DisableMcpServer
                    && crate::mcp_gateway::config::list(&self.state, ctx.tenant_id)
                        .await?
                        .iter()
                        .any(|endpoint| endpoint.id == id)
                {
                    row.endpoint_id = Some(id);
                }
                if matches!(action, ContainmentAction::DisableMcpServer | ContainmentAction::RevokeSkill) {
                    row.tools = asset
                        .attributes
                        .get("tools")
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|tool| {
                            tool.as_str().or_else(|| tool.get("name").and_then(serde_json::Value::as_str))
                        })
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned)
                        .collect();
                    if row.tools.is_empty() && row.endpoint_id.is_none() {
                        return Err(DomainError::Validation(
                            "资产没有已登记工具清单，请先登记 tools；无法确认实际拦截目标".into(),
                        )
                        .into());
                    }
                }
                if action == ContainmentAction::ForceLocalModel {
                    let endpoint = crate::routes::parse_id(Self::parameter(ctx, "endpoint_id")?, "model-endpoint")?;
                    self.state
                        .configurations
                        .get::<crate::model_gateway::StoredEndpoint>(
                            ctx.tenant_id,
                            crate::model_gateway::ENDPOINT_KIND,
                            endpoint,
                        )
                        .await?
                        .filter(|record| record.endpoint.enabled && record.endpoint.local_deployment)
                        .ok_or_else(|| DomainError::Validation("请选择当前租户已启用的本地模型端点".into()))?;
                    row.endpoint_id = Some(endpoint);
                }
            }
            ContainmentAction::KillSession => {
                row.target = Self::parameter(ctx, "session_id")?.into();
                if row.target.len() > 128 {
                    return Err(DomainError::Validation("session_id 最长 128 字符".into()).into());
                }
            }
            ContainmentAction::BlockDomain => {
                let raw = Self::parameter(ctx, "domain")?.trim().trim_end_matches('.').to_ascii_lowercase();
                let host = url::Host::parse(&raw)
                    .map_err(|_| DomainError::Validation("请输入有效域名，不含协议或路径".into()))?;
                if !matches!(host, url::Host::Domain(_)) || raw.contains(['/', ':', '*']) || !raw.contains('.') {
                    return Err(DomainError::Validation("请输入完整域名；IP 请使用 block-ip".into()).into());
                }
                row.target = host.to_string();
            }
            ContainmentAction::BlockIp => {
                row.target = Self::parameter(ctx, "ip")?
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| DomainError::Validation("请输入有效 IPv4/IPv6 地址".into()))?
                    .to_string();
            }
            _ => return Err(DomainError::Validation("无效处置动作".into()).into()),
        }
        self.state.configurations.put(ctx.tenant_id, containment::KIND, row.id, &row).await?;
        Ok(format!(
            "处置 {} 已保存；作用于 AIGuardFabric 代理后的新请求和返回检查。目标 {}，控制记录 {}",
            action.as_str(),
            row.target,
            row.id
        ))
    }
    async fn notify_impl(&self, channel: &str, ctx: &RunContext, note: &str) -> ApiResult<String> {
        self.principal.require(&self.state, "notifications", "write")?;
        let kind = crate::notification_config::parse(channel)?;
        let rows: Vec<crate::notification_config::StoredChannel> =
            self.state.configurations.list(ctx.tenant_id, crate::notification_config::KIND).await?;
        let rows: Vec<_> = rows.into_iter().filter(|row| row.channel == kind && row.enabled).collect();
        if rows.is_empty() {
            return Err(DomainError::PreconditionFailed(format!("请先启用通知渠道 {channel}")).into());
        }
        if self.state.config.mock_mode && kind != agf_core::notify::ChannelKind::InApp {
            return Err(
                DomainError::PreconditionFailed("模拟模式不能执行真实外部通知；可改用站内信或演练".into()).into()
            );
        }
        let id = ctx.case_id.ok_or_else(|| DomainError::Validation("缺少案件".into()))?;
        let result = crate::notification_delivery::dispatch(
            &self.state,
            ctx.tenant_id,
            rows,
            "case",
            id,
            "案件处置通知",
            note,
            ctx.severity,
        )
        .await?;
        if result["any_delivered"] != true {
            return Err(DomainError::PreconditionFailed(format!("通知未投递：{result}")).into());
        }
        Ok(format!("通知已投递：{result}"))
    }
}
#[async_trait]
impl ActionExecutor for Executor {
    async fn execute(&self, action: ContainmentAction, ctx: &RunContext) -> Result<String, String> {
        self.action(action, ctx).await.map_err(|error| error.to_string())
    }
    async fn wait(&self, secs: i64, _: &RunContext) -> Result<WaitOutcome, String> {
        if !(0..=30).contains(&secs) {
            return Err("同步剧本等待仅支持 0–30 秒，请拆分长时间任务".into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(secs as u64)).await;
        Ok(WaitOutcome::Completed)
    }
}
#[async_trait]
impl NotifySink for Executor {
    async fn notify(&self, channel: &str, ctx: &RunContext, note: &str) -> Result<String, String> {
        self.notify_impl(channel, ctx, note).await.map_err(|error| error.to_string())
    }
}
