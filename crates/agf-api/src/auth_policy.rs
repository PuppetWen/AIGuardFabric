//! 租户口令策略。请求级认证服务读取最新配置，避免重启才生效。
use crate::{model_routes::tenant_record_id, routes::console::PasswordPolicyView, state::AppState};
use agf_core::{
    auth::PasswordPolicy,
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use serde::{Deserialize, Serialize};

pub const KIND: &str = "password-policy";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPolicy {
    pub view: PasswordPolicyView,
    pub require_classes: bool,
}

impl TenantPolicy {
    pub async fn load(state: &AppState, tenant: TenantId) -> DomainResult<Self> {
        if let Some(policy) = state.configurations.get(tenant, KIND, tenant_record_id(tenant)).await? {
            return Ok(policy);
        }
        let policy = state.auth.policy();
        Ok(Self {
            view: PasswordPolicyView {
                version: 0,
                min_length: i64::try_from(policy.min_length).unwrap_or(12),
                require_uppercase: false,
                require_lowercase: false,
                require_digit: false,
                require_symbol: false,
                max_age_days: i64::from(policy.max_age_days),
                history_size: i64::from(policy.history_size),
                lockout_threshold: i64::from(policy.max_failures),
                mfa_enforced: false,
                require_classes: policy.require_classes,
            },
            require_classes: policy.require_classes,
        })
    }

    pub fn core(&self, state: &AppState) -> PasswordPolicy {
        PasswordPolicy {
            min_length: usize::try_from(self.view.min_length).unwrap_or(12),
            require_classes: self.require_classes,
            max_age_days: u32::try_from(self.view.max_age_days).unwrap_or(90),
            history_size: u32::try_from(self.view.history_size).unwrap_or(5),
            max_failures: u32::try_from(self.view.lockout_threshold).unwrap_or(5),
            ..state.auth.policy().clone()
        }
    }

    pub fn validate(&self, password: &str) -> DomainResult<()> {
        let checks = [
            (self.view.require_uppercase, password.chars().any(char::is_uppercase), "大写字母"),
            (self.view.require_lowercase, password.chars().any(char::is_lowercase), "小写字母"),
            (self.view.require_digit, password.chars().any(|c| c.is_ascii_digit()), "数字"),
            (self.view.require_symbol, password.chars().any(|c| !c.is_alphanumeric()), "符号"),
        ];
        for (required, present, name) in checks {
            if required && !present {
                return Err(DomainError::Validation(format!("口令必须包含{name}")));
            }
        }
        Ok(())
    }
}

pub async fn service(state: &AppState, tenant: TenantId) -> DomainResult<agf_auth::service::AuthService> {
    Ok(state.auth.with_policy(TenantPolicy::load(state, tenant).await?.core(state)))
}
