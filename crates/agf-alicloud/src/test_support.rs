//! 测试支撑：确定性配置与集成夹具（仅 `#[cfg(test)]`）。
//!
//! 放在独立模块而非各测试文件里，是为了保证六个服务的测试用**同一份**夹具口径
//! （地域、账号、超时、熔断配置一致），避免"某个服务的测试悄悄换了参数"。

use std::collections::BTreeMap;

use agf_core::adapter::{AdapterConfig, CircuitBreakerConfig, RetryConfig};
use agf_core::cloud::{CloudCredentialKind, CloudIntegration, CloudProvider};
use agf_core::enums::{AliCloudService, HealthState};
use agf_core::ids::{Id, TenantId, deterministic_id};
use agf_core::time::Timestamp;

use crate::mock::{FIXTURE_ACCOUNT_ID, FIXTURE_REGION};

/// Ordered public-response samples; fails if an adapter sends an unexpected extra call.
pub(crate) struct ScriptedTransport {
    responses: std::sync::Mutex<std::collections::VecDeque<serde_json::Value>>,
    pub requests: std::sync::Mutex<Vec<crate::http::RpcRequest>>,
}
impl ScriptedTransport {
    pub(crate) fn new(responses: Vec<serde_json::Value>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            responses: std::sync::Mutex::new(responses.into()),
            requests: std::sync::Mutex::new(Vec::new()),
        })
    }
}
impl crate::http::Transport for ScriptedTransport {
    fn send(&self, request: &crate::http::RpcRequest) -> agf_core::error::DomainResult<crate::http::RpcResponse> {
        self.requests.lock().unwrap().push(request.clone());
        let body = self.responses.lock().unwrap().pop_front().expect("unexpected cloud request");
        Ok(crate::http::RpcResponse { status: 200, raw: body.to_string(), body })
    }
}

/// 确定性适配器配置。
///
/// `mock = true` 时走 Mock 模式；`mock = false` 时不带凭据引用（`init` 之后应为未配置态）。
#[must_use]
pub(crate) fn fixture_config(service: AliCloudService, mock: bool) -> AdapterConfig {
    let now = Timestamp::now();
    let mut settings = BTreeMap::new();
    settings.insert("region_id".to_string(), serde_json::Value::from(FIXTURE_REGION));
    settings.insert("account_id".to_string(), serde_json::Value::from(FIXTURE_ACCOUNT_ID));
    settings.insert("endpoint_style".to_string(), serde_json::Value::from("public"));
    AdapterConfig {
        id: deterministic_id("aiguardfabric.adapter_config", service.as_str()),
        tenant_id: TenantId::default_tenant(),
        adapter: service.as_str().to_string(),
        display_name: crate::mock::display_name_of(service).to_string(),
        enabled: true,
        settings,
        secret_refs: BTreeMap::new(),
        circuit_breaker: CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 3,
            open_secs: 30,
            half_open_probes: 1,
        },
        retry: RetryConfig {
            max_attempts: 2,
            initial_backoff_ms: 1,
            multiplier: 1.0,
            max_backoff_ms: 2,
            jitter: false,
        },
        timeout_secs: 5,
        mock,
        is_default: true,
        created_at: now,
        updated_at: now,
    }
}

/// 带凭据引用的适配器配置（用于构造真实模式客户端）。
#[must_use]
pub(crate) fn fixture_config_with_secrets(service: AliCloudService, mock: bool) -> AdapterConfig {
    let mut config = fixture_config(service, mock);
    config.secret_refs.insert("access_key_id".to_string(), Id::new());
    config.secret_refs.insert("access_key_secret".to_string(), Id::new());
    config
}

/// 确定性云集成。
#[must_use]
pub(crate) fn fixture_integration(kind: CloudCredentialKind, account_id: &str) -> CloudIntegration {
    let now = Timestamp::now();
    CloudIntegration {
        id: deterministic_id("aiguardfabric.alicloud", account_id),
        tenant_id: TenantId::default_tenant(),
        provider: CloudProvider::AliCloud,
        name: format!("测试账号 {account_id}"),
        account_id: account_id.to_string(),
        region_id: FIXTURE_REGION.to_string(),
        credential_kind: kind,
        credential_ref: None,
        assume_role_arn: None,
        role_session_name: None,
        sts_expires_at: None,
        endpoints: BTreeMap::new(),
        enabled: true,
        health: HealthState::Unconfigured,
        last_sync_at: None,
        last_error: None,
        permission_checks: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_config_is_deterministic_and_complete() {
        let a = fixture_config(AliCloudService::Cms, true);
        let b = fixture_config(AliCloudService::Cms, true);
        assert_eq!(a.id, b.id, "夹具配置 id 必须稳定");
        assert_eq!(a.adapter, "alicloud-cms");
        assert!(a.mock);
        assert_eq!(a.get_str("region_id"), Some(FIXTURE_REGION));
        assert_eq!(a.get_str("account_id"), Some(FIXTURE_ACCOUNT_ID));
        assert_eq!(a.timeout_secs, 5);
        assert!(a.secret_refs.is_empty(), "mock 夹具不带凭据引用");
    }

    #[test]
    fn fixture_configs_differ_per_service() {
        let mut ids: Vec<Id> = AliCloudService::all().iter().map(|s| fixture_config(*s, true).id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 6, "六个服务的配置 id 必须互不相同");
    }

    #[test]
    fn config_with_secrets_has_both_refs() {
        let config = fixture_config_with_secrets(AliCloudService::Apig, false);
        assert!(config.has_secrets(&["access_key_id", "access_key_secret"]));
        assert!(!config.mock);
    }

    #[test]
    fn fixture_integration_reflects_kind_and_account() {
        let integration = fixture_integration(CloudCredentialKind::AssumeRole, "9999999999");
        assert_eq!(integration.account_id, "9999999999");
        assert_eq!(integration.credential_kind, CloudCredentialKind::AssumeRole);
        assert_eq!(integration.region_id, FIXTURE_REGION);
        assert!(!integration.is_cross_account(), "默认不带 ARN");
        assert!(!integration.has_long_lived_risk());
        let long_lived = fixture_integration(CloudCredentialKind::LongTermAk, "1");
        assert!(long_lived.has_long_lived_risk());
    }
}
