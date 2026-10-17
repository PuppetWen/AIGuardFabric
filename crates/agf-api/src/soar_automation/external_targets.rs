//! Validate external response targets before an alert automation is enabled.
use super::*;
use agf_adapters::vendors::require_safe_id;
use agf_core::{
    case::ContainmentAction,
    enums::{AssetKind, LifecycleState},
};

fn required<'a>(step: &'a agf_core::case::PlaybookStep, key: &str) -> DomainResult<&'a str> {
    step.params
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .ok_or_else(|| DomainError::Validation(format!("自动外部处置步骤 {} 缺少有效参数 {key}", step.name)))
}

fn version(step: &agf_core::case::PlaybookStep) -> DomainResult<u64> {
    let value = step.params.get("configuration_version");
    let version = value
        .and_then(serde_json::Value::as_u64)
        .or_else(|| value.and_then(serde_json::Value::as_str).and_then(|text| text.parse().ok()))
        .unwrap_or_default();
    if version == 0 {
        return Err(DomainError::Validation("自动外部处置须填写当前非零的 configuration_version".into()));
    }
    Ok(version)
}

pub(super) async fn validate(state: &AppState, principal: &Principal, book: &Playbook) -> DomainResult<()> {
    for step in &book.steps {
        let (adapter, binding_key, target_key, credential_only) = match step.action {
            Some(ContainmentAction::IsolateHost) => ("edr-isolation", "edr_host_id", "host_id", false),
            Some(ContainmentAction::DeactivateExternalUser) => ("iam-scim", "scim_user_id", "user_id", true),
            _ => continue,
        };
        if principal.require(state, "integrations", "write").is_err()
            || principal.require(state, "policies", "write").is_err()
        {
            return Err(DomainError::Forbidden("启用自动外部处置需要 integrations:write 和 policies:write".into()));
        }
        let asset_id = Id::parse(required(step, "asset_id")?)
            .map_err(|_| DomainError::Validation("自动外部处置 asset_id 必须是资产 UUID".into()))?;
        let asset = state
            .store
            .asset_get_durable(principal.tenant, asset_id)
            .await?
            .ok_or_else(|| DomainError::NotFound { entity: "asset", id: asset_id.to_string() })?;
        if credential_only && asset.kind != AssetKind::Credential {
            return Err(DomainError::Validation("SCIM 自动处置只接受凭据类身份资产".into()));
        }
        if matches!(asset.lifecycle, LifecycleState::Archived | LifecycleState::Rejected) {
            return Err(DomainError::PreconditionFailed("已归档或拒绝的资产不能用于自动外部处置".into()));
        }
        let target = require_safe_id(adapter, required(step, target_key)?, target_key)?;
        if asset.attributes.get(binding_key).and_then(serde_json::Value::as_str) != Some(target.as_str()) {
            return Err(DomainError::Validation(format!(
                "自动外部处置的 {target_key} 与资产已登记的 {binding_key} 不一致"
            )));
        }
        let reason = required(step, "reason")?;
        if reason.chars().any(char::is_control) {
            return Err(DomainError::Validation("自动外部处置原因不能包含控制字符".into()));
        }
        let expected = version(step)?;
        let config = crate::integration_store::load(state, principal.tenant, adapter)
            .await?
            .filter(|row| row.enabled)
            .ok_or_else(|| DomainError::PreconditionFailed(format!("请先启用 {adapter} 集成")))?;
        if config.version != expected {
            return Err(DomainError::Conflict("外部集成配置版本已改变，请刷新后重新核对目标".into()));
        }
    }
    Ok(())
}
