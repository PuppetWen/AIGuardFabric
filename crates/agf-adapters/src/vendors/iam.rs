//! SCIM 2.0 identity deactivation. The endpoint is the tenant's SCIM base URL.
//! Only an approved case may send a Live request; the runtime enforces that gate.

use agf_core::error::{DomainError, DomainResult};
use serde_json::json;

use crate::contract::{AdapterCategory, AdapterMessage, AdapterMetadata, SemanticProfile};
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec;

/// Standard SCIM 2.0 PATCH adapter for setting an existing User's `active` to false.
#[derive(Debug)]
pub struct ScimIdentity;

impl VendorSpec for ScimIdentity {
    const NAME: &'static str = "iam-scim";
    const REAL_TRANSPORT: bool = true;
    const REQUIRED_SETTINGS: &'static [&'static str] = &["endpoint"];

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("iam-scim", "SCIM 身份停用", "企业身份平台", AdapterCategory::SecurityPlatform)
            .with_secrets(&["api_token"], &[])
            .with_endpoint_key("endpoint")
            .with_capabilities(vec![
                agf_core::adapter::AdapterCapability::EnforcePolicy,
                agf_core::adapter::AdapterCapability::SelfCheck,
            ])
            .with_semantics(SemanticProfile::send_only(
                "SCIM 停用只通过已审批案件的 send 提交；通用 push 不能绕过案件目标校验",
                "此适配器不读取身份目录，避免在平台复制个人信息",
                "未读取身份目录，无法执行双向身份对账",
            ))
            .with_degradation("未配置 endpoint/api_token 时不调用外部平台；Mock 零网络；Live 仅案件审批后执行")
            .with_mock_location("crates/agf-adapters/src/vendors/iam.rs#MockScimIdentityAdapter（注册名 iam-scim）")
            .with_real_transport(true)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        if let Some(endpoint) = settings.get_str("endpoint") {
            crate::settings::validate_endpoint(endpoint)?;
            let parsed =
                url::Url::parse(endpoint).map_err(|e| DomainError::Config(format!("SCIM endpoint 非法: {e}")))?;
            let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
            if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local) {
                return Err(DomainError::Config("SCIM endpoint 必须使用 HTTPS；仅本机测试可使用 HTTP".into()));
            }
            if parsed.query().is_some()
                || parsed.fragment().is_some()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err(DomainError::Config("SCIM endpoint 不能包含凭据、查询串或片段".into()));
            }
        }
        Ok(())
    }

    fn subscribes(msg: &AdapterMessage) -> bool {
        msg.event_type == "enforce.deactivate-user"
            && msg.labels.get("action").is_some_and(|action| action == "deactivate")
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let user = msg.labels.get("user_id").map(String::as_str).unwrap_or_default();
        let user = crate::vendors::require_safe_id(Self::NAME, user, "SCIM user id")?;
        let endpoint = crate::vendors::require_setting(settings, "endpoint")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let mut request = VendorRequest::channel(
            "PATCH",
            format!("{}/Users/{user}", endpoint.trim_end_matches('/')),
            json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"replace","path":"active","value":false}]}),
        );
        request.content_type = "application/scim+json".into();
        Ok(request
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, msg.idempotency_key.clone()))
    }

    fn parse_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        if body.trim().is_empty() {
            return Ok(None);
        }
        let value: serde_json::Value = serde_json::from_str(body)
            .map_err(|_| DomainError::Validation("SCIM PATCH 返回非 JSON 响应，无法确认身份状态".into()))?;
        if value.get("active").and_then(serde_json::Value::as_bool) == Some(true) {
            return Err(DomainError::Validation("SCIM PATCH 返回 active=true，身份未确认停用".into()));
        }
        Ok(value.get("id").and_then(serde_json::Value::as_str).map(str::to_owned))
    }
}

/// Mock never contacts the identity platform.
pub type MockScimIdentityAdapter = crate::vendor::VendorAdapterImpl<ScimIdentity>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::settings_for;
    use agf_core::enums::Severity;

    #[test]
    fn encodes_exact_scim_patch_and_rejects_unsafe_targets() {
        let config = settings_for(
            &ScimIdentity::metadata(),
            &[("endpoint", json!("https://identity.example.invalid/scim/v2"))],
            &[("api_token", "test-token")],
        )
        .unwrap();
        let msg = AdapterMessage::event("enforce.deactivate-user", Severity::High, "Disable", "case", json!({}))
            .with_label("action", "deactivate")
            .with_label("user_id", "user-42");
        let req = ScimIdentity::encode(&msg, &config).unwrap();
        assert_eq!(req.method, "PATCH");
        assert_eq!(req.endpoint, "https://identity.example.invalid/scim/v2/Users/user-42");
        assert_eq!(req.content_type, "application/scim+json");
        assert_eq!(req.body["Operations"][0]["value"], false);
        assert!(ScimIdentity::encode(&msg.with_label("user_id", "../admin"), &config).is_err());
        assert!(ScimIdentity::parse_response(200, r#"{"id":"user-42","active":true}"#).is_err());
    }
}
