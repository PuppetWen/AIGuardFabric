//! Approved SCIM deactivation of the exact identity bound to a case asset.
use super::*;
use agf_adapters::{contract::AdapterMessage, vendors::require_safe_id};
use agf_core::{
    case::Case,
    enums::{AssetKind, LifecycleState},
    ids::deterministic_id,
};
use serde_json::json;

impl Executor {
    pub(super) async fn deactivate_external_user(&self, ctx: &RunContext, case: &Case) -> ApiResult<String> {
        self.principal.require(&self.state, "integrations", "write")?;
        self.principal.require(&self.state, "policies", "write")?;
        let step = self
            .workflow_step
            .as_ref()
            .ok_or_else(|| DomainError::PreconditionFailed("SCIM 身份停用只能通过持久化案件任务提交并审批".into()))?;
        let asset_id = crate::routes::parse_id(Self::parameter(ctx, "asset_id")?, "asset")?;
        if !case.asset_ids.contains(&asset_id) {
            return Err(DomainError::Validation("SCIM 目标身份资产必须关联当前案件".into()).into());
        }
        let asset = self
            .state
            .store
            .asset_get_durable(ctx.tenant_id, asset_id)
            .await?
            .ok_or_else(|| DomainError::NotFound { entity: "asset", id: asset_id.to_string() })?;
        if asset.kind != AssetKind::Credential
            || matches!(asset.lifecycle, LifecycleState::Archived | LifecycleState::Rejected)
        {
            return Err(DomainError::PreconditionFailed("SCIM 停用要求未归档的凭据类身份资产".into()).into());
        }
        let user_id = require_safe_id("iam-scim", Self::parameter(ctx, "user_id")?, "SCIM user id")?;
        let registered = asset
            .attributes
            .get("scim_user_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| DomainError::PreconditionFailed("请先在凭据资产详情绑定 SCIM 用户编号".into()))?;
        if registered != user_id {
            return Err(DomainError::Validation("SCIM 用户编号与案件关联身份资产绑定不一致".into()).into());
        }
        let version = Self::parameter(ctx, "configuration_version")?
            .parse::<u64>()
            .map_err(|_| DomainError::Validation("configuration_version 必须是配置版本号".into()))?;
        if version == 0 {
            return Err(DomainError::Validation("请先启用 SCIM 集成并核对配置版本".into()).into());
        }
        let reason = Self::parameter(ctx, "reason")?;
        let mut message = AdapterMessage::event(
            "enforce.deactivate-user",
            ctx.severity,
            "案件 SCIM 身份停用",
            reason,
            json!({"case_id":case.id,"asset_id":asset_id}),
        )
        .with_label("action", "deactivate")
        .with_label("user_id", &user_id)
        .with_label("case_id", case.id.to_string())
        .with_idempotency_key(step.request_id.to_string());
        message.occurred_at = step.occurred_at;
        let result = crate::integration_runtime::execute_approved_iam(
            &self.state,
            ctx.tenant_id,
            crate::state::AppState::audit_actor(&self.principal, "soar-iam-operation"),
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
                let receipt_id =
                    deterministic_id("agf.integration.run", &format!("{}:iam-scim:{}", ctx.tenant_id, step.request_id));
                if crate::integration_receipts::get(&self.state, ctx.tenant_id, "iam-scim", receipt_id).await.is_ok() {
                    return Err(DomainError::PreconditionFailed(format!(
                        "IAM_UNCERTAIN: 已存在调用回执 {receipt_id}，无法确认身份状态；请先在身份平台核对"
                    ))
                    .into());
                }
                return Err(error.into());
            }
        };
        let receipt_id = result["id"].as_str().unwrap_or("unknown");
        match result["status"].as_str() {
            Some("succeeded") => Ok(format!(
                "SCIM {} 身份停用调用已记录：用户 {user_id}，资产 {asset_id}，回执 {receipt_id}；请在身份平台核对 active=false",
                if result["mocked"] == true { "Mock" } else { "Live" }
            )),
            Some("uncertain" | "started") => Err(DomainError::PreconditionFailed(format!(
                "IAM_UNCERTAIN: 用户 {user_id} 的结果不确定，回执 {receipt_id}；先检查身份平台，禁止盲目重试"
            ))
            .into()),
            _ => Err(DomainError::PreconditionFailed(format!(
                "SCIM 身份停用未成功：用户 {user_id}，回执 {receipt_id}；请查看集成调用记录"
            ))
            .into()),
        }
    }
}
