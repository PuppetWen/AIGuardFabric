//! Approved, durable EDR isolation uses the same encrypted receipt path as manual operations.
use super::*;
use agf_adapters::{contract::AdapterMessage, vendors::require_safe_id};
use agf_core::case::Case;
use agf_core::enums::LifecycleState;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct WorkflowStep {
    pub request_id: Id,
    pub occurred_at: Timestamp,
}

impl Executor {
    pub(super) async fn isolate_host(&self, ctx: &RunContext, case: &Case) -> ApiResult<String> {
        self.principal.require(&self.state, "integrations", "write")?;
        self.principal.require(&self.state, "policies", "write")?;
        let step = self
            .workflow_step
            .as_ref()
            .ok_or_else(|| DomainError::PreconditionFailed("EDR 隔离只能通过持久化案件任务提交并审批".into()))?;
        let asset_id = crate::routes::parse_id(Self::parameter(ctx, "asset_id")?, "asset")?;
        if !case.asset_ids.contains(&asset_id) {
            return Err(DomainError::Validation("EDR 目标资产必须关联当前案件".into()).into());
        }
        let asset = self
            .state
            .store
            .asset_get_durable(ctx.tenant_id, asset_id)
            .await?
            .ok_or_else(|| DomainError::NotFound { entity: "asset", id: asset_id.to_string() })?;
        if matches!(asset.lifecycle, LifecycleState::Archived | LifecycleState::Rejected) {
            return Err(DomainError::PreconditionFailed("已归档或拒绝的资产不能作为 EDR 隔离目标".into()).into());
        }
        let host = require_safe_id("edr-isolation", Self::parameter(ctx, "host_id")?, "host id")?;
        let registered_host = asset
            .attributes
            .get("edr_host_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| DomainError::PreconditionFailed("请先在资产详情绑定 EDR 主机编号".into()))?;
        if registered_host != host {
            return Err(DomainError::Validation("EDR 主机编号与关联资产登记的 edr_host_id 不一致".into()).into());
        }
        let version = Self::parameter(ctx, "configuration_version")?
            .parse::<u64>()
            .map_err(|_| DomainError::Validation("configuration_version 必须是配置版本号".into()))?;
        if version == 0 {
            return Err(DomainError::Validation("请先启用 EDR 集成并核对配置版本".into()).into());
        }
        let configuration = crate::integration_store::load(&self.state, ctx.tenant_id, "edr-isolation")
            .await?
            .ok_or_else(|| DomainError::PreconditionFailed("请先配置 EDR 集成".into()))?;
        let private = crate::integration_store::decrypt(&self.state, ctx.tenant_id, &configuration)?;
        let edr_dry_run = private.settings.get("dry_run").and_then(serde_json::Value::as_bool).unwrap_or(true);
        let reason = Self::parameter(ctx, "reason")?;
        let mut message = AdapterMessage::event(
            "enforce.isolate",
            ctx.severity,
            "案件 EDR 主机隔离",
            reason,
            json!({"case_id":case.id,"asset_id":asset_id}),
        )
        .with_label("action", "isolate")
        .with_label("host_id", &host)
        .with_label("case_id", case.id.to_string())
        .with_idempotency_key(step.request_id.to_string());
        message.occurred_at = step.occurred_at;
        let result = crate::integration_runtime::execute_approved_edr(
            &self.state,
            ctx.tenant_id,
            crate::state::AppState::audit_actor(&self.principal, "soar-edr-operation"),
            crate::integration_runtime::Request {
                request_id: step.request_id,
                configuration_version: version,
                confirm_live: true,
                action: crate::integration_runtime::Operation::Send(message),
            },
        )
        .await;
        let result = match result {
            Ok(value) => value,
            Err(error) => {
                let receipt_id = agf_core::ids::deterministic_id(
                    "agf.integration.run",
                    &format!("{}:edr-isolation:{}", ctx.tenant_id, step.request_id),
                );
                if crate::integration_receipts::get(&self.state, ctx.tenant_id, "edr-isolation", receipt_id)
                    .await
                    .is_ok()
                {
                    return Err(DomainError::PreconditionFailed(format!(
                        "EDR_UNCERTAIN: 已存在调用回执 {receipt_id}，但本次无法确认状态；请先核对远端任务"
                    ))
                    .into());
                }
                return Err(error.into());
            }
        };
        let receipt_id = result["id"].as_str().unwrap_or("unknown");
        match result["status"].as_str() {
            Some("succeeded") => {
                let mode = if result["mocked"] == true {
                    "Mock"
                } else if edr_dry_run {
                    "dry-run"
                } else {
                    "Live"
                };
                Ok(format!(
                    "EDR {mode} 隔离调用已记录：主机 {host}，资产 {asset_id}，回执 {receipt_id}；请以 EDR 任务状态核对实际隔离"
                ))
            }
            Some("uncertain" | "started") => Err(DomainError::PreconditionFailed(format!(
                "EDR_UNCERTAIN: 主机 {host} 的结果不确定，回执 {receipt_id}；先检查 EDR 远端任务，禁止盲目重试"
            ))
            .into()),
            _ => Err(DomainError::PreconditionFailed(format!(
                "EDR 隔离未成功：主机 {host}，回执 {receipt_id}；请查看集成调用记录"
            ))
            .into()),
        }
    }
}
