//! ServiceNow 适配器（Table API incident 创建 + 状态回写 + 增量拉取）。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | 真实 HTTP `POST <instance_url>/api/now/table/incident` |
//! | 凭据 | `api_token`（必需，OAuth/Bearer 令牌）、`user_name`（可选，台账归属人）、`user_password`（可选，Basic 兜底） |
//! | 设置 | `instance_url`（必需）、`table`（可选，默认 `incident`）、`allow_custom_host`（可选，自建实例） |
//! | 鉴权 | `Authorization: Bearer <api_token>` |
//! | 映射 | 等级 → `urgency`（1 高 / 2 中 / 3 低）；幂等键 → `correlation_id` |
//! | 响应 | 2xx + `{"result":{"sys_id":"...","number":"INC0010001"}}`；远端 id 取 **`sys_id`** |
//! | `push` | `PATCH /api/now/table/{table}/{sys_id}`（`state` / `work_notes`） |
//! | `pull` | `GET /api/now/table/{table}?sysparm_query=sys_updated_on>=<cursor>^ORDERBYsys_updated_on&sysparm_limit=N` |
//! | `sync` | `pull` → 与本地案件快照比对 → 按冲突策略回写 |
//!
//! **远端 id 口径（如实登记）**：回执的 `remote_id` 取 `result.sys_id`——它是 Table API 的
//! 定位键（`push`/`pull` 都用它），而 `number` 只是人读单号；`sys_id` 缺失时才回退 `number`。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `instance_url` 或凭据 | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包**；事件照常落库 |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock sys_id，**绝不发起真实请求** |
//! | 自建实例未开 `allow_custom_host` | `init()` 返回 `Config`，避免把凭据发往非预期主机 |
//! | `instance_url` 非 https（未开 `insecure_http`） | `init()` 返回 `Config`；内网自建实例需显式放行 |
//! | `push` 的 `entity_id` 不是 `sys_id` | `Validation`（单号无法定位记录，提示先用 `pull` 换取 `sys_id`） |
//! | 上游 5xx / 超时 | `DependencyUnavailable` / `Timeout`，**按 `RetryConfig` 重试** |
//! | 上游 4xx | `Validation`/`Forbidden`/`Unauthenticated`，**不重试** |

use agf_core::adapter::PullRequest;
use agf_core::adapter::PushPayload;
use agf_core::enums::Severity;
use agf_core::error::{DomainError, DomainResult};
use serde_json::json;

use crate::contract::{AdapterCategory, AdapterMessage, AdapterMetadata, PullPage, SemanticProfile};
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec;

/// 默认表名。
pub const DEFAULT_TABLE: &str = "incident";

/// ServiceNow 适配器标记类型。
#[derive(Debug)]
pub struct ServiceNow;

impl ServiceNow {
    /// 等级 → `urgency`（ServiceNow 语义：1 高、2 中、3 低）。
    #[must_use]
    pub const fn urgency(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical | Severity::High => "1",
            Severity::Medium => "2",
            Severity::Low | Severity::Info => "3",
        }
    }

    /// 表接口 URL。
    #[must_use]
    pub fn table_endpoint(instance_url: &str, table: &str) -> String {
        format!("{}/api/now/table/{}", instance_url.trim_end_matches('/'), table.trim_matches('/'))
    }

    /// incident 请求体。
    #[must_use]
    pub fn incident_body(msg: &AdapterMessage) -> serde_json::Value {
        json!({
            "short_description": format!("【{}】{}", msg.severity.as_str(), msg.title),
            "description": format!(
                "{}\n\nevent_type={}\nasset={}\nidempotency_key={}\noccurred_at={}",
                msg.summary,
                msg.event_type,
                msg.asset.clone().unwrap_or_else(|| "-".to_string()),
                msg.idempotency_key,
                msg.occurred_at.to_rfc3339()
            ),
            "urgency": Self::urgency(msg.severity),
            "category": "security",
            "subcategory": msg.event_type,
            "correlation_id": msg.idempotency_key,
            "u_source": "aiguardfabric",
        })
    }

    /// 表名（设置 `table`，默认 `incident`）。
    #[must_use]
    pub fn table(settings: &AdapterSettings) -> String {
        settings.get_str("table").map(str::trim).filter(|t| !t.is_empty()).unwrap_or(DEFAULT_TABLE).to_string()
    }
}

impl VendorSpec for ServiceNow {
    const NAME: &'static str = "servicenow";
    const REAL_TRANSPORT: bool = true;
    const REQUIRED_SETTINGS: &'static [&'static str] = &["instance_url"];
    const SYNC_PUSH_ENTITY: &'static str = "ticket.status";

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("servicenow", "ServiceNow", "ServiceNow", AdapterCategory::Itsm)
            .with_secrets(&["api_token"], &["user_name", "user_password"])
            .with_endpoint_key("instance_url")
            .with_capabilities(crate::vendors::itsm_capabilities())
            .with_semantics(SemanticProfile::full())
            .with_degradation(
                "未配置 instance_url 或凭据时不创建任何事件单；事件照常落库并在控制台可见，\
                 可由值班人工建单；自建实例需显式开启 allow_custom_host 才会下发",
            )
            .with_mock_location("crates/agf-adapters/src/vendors/servicenow.rs#MockServiceNowAdapter")
            .with_real_transport(true)
    }

    /// 解析 Table API 响应：远端 id 取 `result.sys_id`（Table API 定位键），缺失时回退 `number`。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 `result` 字段时返回 `DomainError::Validation`。
    fn parse_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        let id = crate::http::extract_id(body, &["result.sys_id", "sys_id", "result.number", "number"]);
        if id.is_none() {
            return Err(DomainError::Validation(format!(
                "servicenow 建单响应缺少 result.sys_id: {}",
                crate::http::snippet(body)
            )));
        }
        Ok(id)
    }

    /// 状态回写（Table API `PATCH`）。
    ///
    /// # Errors
    /// 实体名不支持、`entity_id` 非 `sys_id`、载荷无 `state`/`work_notes` 时返回错误。
    fn encode_push(payload: &PushPayload, settings: &AdapterSettings) -> DomainResult<Vec<VendorRequest>> {
        Self::encode_push_requests(payload, settings)
    }

    /// 增量拉取（`sysparm_query=sys_updated_on>=cursor^ORDERBYsys_updated_on`）。
    ///
    /// # Errors
    /// 资源名不支持或配置缺项时返回错误。
    fn encode_pull(req: &PullRequest, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Self::encode_pull_request(req, settings)
    }

    /// 解析表查询响应并注入规范化字段。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 `result` 数组时返回 `DomainError::Validation`。
    fn parse_pull(status: u16, body: &str, req: &PullRequest) -> DomainResult<PullPage> {
        Self::parse_pull(status, body, req)
    }

    /// 回写响应：`{"result":{"sys_id":...}}`。
    ///
    /// # Errors
    /// 响应体缺 `result.sys_id` 时返回 `DomainError::Validation`。
    fn parse_push_response(status: u16, body: &str) -> DomainResult<Option<String>> {
        Self::parse_push_response(status, body)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        if let Some(instance) = settings.get_str("instance_url") {
            crate::settings::validate_endpoint(instance)?;
            let parsed =
                url::Url::parse(instance).map_err(|e| DomainError::Config(format!("instance_url 非法: {e}")))?;
            let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
            let allow_custom = settings.get_bool("allow_custom_host", false);
            if !allow_custom && !host.ends_with("service-now.com") {
                return Err(DomainError::Config(format!(
                    "instance_url 主机不属于 service-now.com（host={host}）；自建实例请显式设置 allow_custom_host=true"
                )));
            }
            if !settings.get_bool("insecure_http", false) && parsed.scheme() != "https" {
                return Err(DomainError::Config(format!("instance_url 必须使用 https（收到 {}）", parsed.scheme())));
            }
        }
        let table = Self::table(settings);
        if !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(DomainError::Config(format!("ServiceNow 表名非法: {table:?}")));
        }
        Ok(())
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let instance = crate::vendors::require_setting(settings, "instance_url")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let table = Self::table(settings);
        Ok(VendorRequest::post(Self::table_endpoint(&instance, &table), "application/json", Self::incident_body(msg))
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("Accept", "application/json")
            .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, msg.idempotency_key.clone()))
    }
}

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockServiceNowAdapter = crate::vendor::VendorAdapterImpl<ServiceNow>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::VendorAdapter;
    use crate::settings::AdapterMode;
    use crate::test_support::settings_for;

    const INSTANCE: &str = "https://acme.service-now.com";

    fn message() -> AdapterMessage {
        AdapterMessage::event("ai.credential.leak", Severity::High, "凭据泄露", "在 .env 中发现明文密钥", json!({}))
            .with_asset("host3")
            .with_label("owner", "alice")
    }

    fn settings(extra: &[(&str, serde_json::Value)]) -> AdapterSettings {
        let mut base: Vec<(&str, serde_json::Value)> = vec![("instance_url", json!(INSTANCE))];
        base.extend_from_slice(extra);
        settings_for(&ServiceNow::metadata(), &base, &[("api_token", "sn-token-abcdef")]).expect("测试设置必须可构造")
    }

    #[test]
    fn urgency_mapping() {
        assert_eq!(ServiceNow::urgency(Severity::Critical), "1");
        assert_eq!(ServiceNow::urgency(Severity::High), "1");
        assert_eq!(ServiceNow::urgency(Severity::Medium), "2");
        assert_eq!(ServiceNow::urgency(Severity::Low), "3");
        assert_eq!(ServiceNow::urgency(Severity::Info), "3");
    }

    #[test]
    fn table_endpoint_and_default_table() {
        assert_eq!(
            ServiceNow::table_endpoint(INSTANCE, DEFAULT_TABLE),
            "https://acme.service-now.com/api/now/table/incident"
        );
        assert_eq!(
            ServiceNow::table_endpoint("https://acme.service-now.com/", "incident"),
            "https://acme.service-now.com/api/now/table/incident"
        );
        assert_eq!(ServiceNow::table(&settings(&[])), "incident");
        assert_eq!(
            ServiceNow::table(&settings(&[("table", json!("sn_customerservice_case"))])),
            "sn_customerservice_case"
        );
    }

    #[test]
    fn incident_body_carries_correlation_and_urgency() {
        let msg = message();
        let body = ServiceNow::incident_body(&msg);
        assert_eq!(body["urgency"], "1");
        assert_eq!(body["correlation_id"], json!(msg.idempotency_key));
        assert_eq!(body["u_source"], "aiguardfabric");
        assert_eq!(body["subcategory"], "ai.credential.leak");
        assert!(body["short_description"].as_str().unwrap_or_default().contains("凭据泄露"));
    }

    #[test]
    fn validation_matrix_for_instance_and_table() {
        assert!(ServiceNow::validate_settings(&settings(&[])).is_ok());
        assert!(ServiceNow::validate_settings(&settings(&[("table", json!("bad table"))])).is_err());
        // 自建实例默认拒绝
        let custom = settings(&[("instance_url", json!("https://sn.internal.example"))]);
        assert!(ServiceNow::validate_settings(&custom).is_err());
        let allowed =
            settings(&[("instance_url", json!("https://sn.internal.example")), ("allow_custom_host", json!(true))]);
        assert!(ServiceNow::validate_settings(&allowed).is_ok());
        // 非 https 默认拒绝
        let insecure = settings(&[("instance_url", json!("http://acme.service-now.com"))]);
        assert!(ServiceNow::validate_settings(&insecure).is_err());
        let insecure_allowed =
            settings(&[("instance_url", json!("http://acme.service-now.com")), ("insecure_http", json!(true))]);
        assert!(ServiceNow::validate_settings(&insecure_allowed).is_ok());
    }

    #[test]
    fn encode_sets_bearer_header() {
        let req = ServiceNow::encode(&message(), &settings(&[])).expect("编码应成功");
        assert_eq!(req.headers.get("Authorization").map(String::as_str), Some("Bearer sn-token-abcdef"));
        assert_eq!(req.endpoint, "https://acme.service-now.com/api/now/table/incident");
    }

    #[tokio::test]
    async fn mock_and_live_behaviour() {
        let mut mock = crate::vendor::VendorAdapterImpl::<ServiceNow>::mocked();
        let receipt = mock.send(&message()).await.expect("Mock 发送");
        assert!(receipt.mocked);
        assert_eq!(receipt.origin, "mock://servicenow");

        let mut live = crate::vendor::VendorAdapterImpl::<ServiceNow>::new();
        live.init_with(
            &crate::test_support::config_for("servicenow", &[("instance_url", json!(INSTANCE))], false),
            &crate::test_support::secrets(&[("api_token", "sn-token-abcdef")]),
            false,
        )
        .await
        .expect("合法配置");
        assert_eq!(live.mode(), AdapterMode::Live);
        assert!(live.descriptor().real_implementation, "ServiceNow 已实现真实 HTTP 建单");
        assert!(!live.build_record().message.unwrap_or_default().contains("TODO("));
    }

    #[test]
    fn parse_response_prefers_sys_id_for_followup_operations() {
        // 远端 id 取 sys_id：它是 Table API 的定位键（push/pull 都用它），number 只是人读单号
        assert_eq!(
            ServiceNow::parse_response(201, r#"{"result":{"sys_id":"abc123","number":"INC0010001"}}"#)
                .ok()
                .flatten()
                .as_deref(),
            Some("abc123")
        );
        assert_eq!(
            ServiceNow::parse_response(201, r#"{"result":{"number":"INC0010001"}}"#).ok().flatten().as_deref(),
            Some("INC0010001"),
            "sys_id 缺失时才回退 number"
        );
        assert!(ServiceNow::parse_response(200, r#"{"error":{"message":"no table"}}"#).is_err());
    }

    #[tokio::test]
    async fn missing_token_keeps_unconfigured() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<ServiceNow>::new();
        adapter
            .init_with(
                &crate::test_support::config_for("servicenow", &[("instance_url", json!(INSTANCE))], false),
                &crate::settings::NoSecrets,
                false,
            )
            .await
            .expect("未配置不得失败");
        assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
        let error = adapter.send(&message()).await.expect_err("缺凭据必须明确报错");
        assert!(error.to_string().contains("api_token"), "{error}");
    }
}
