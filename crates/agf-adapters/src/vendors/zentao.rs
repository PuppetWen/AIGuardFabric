//! 禅道（ZenTao）适配器（REST v1 bug 提交 + 状态回写 + 增量拉取）。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | 真实 HTTP `POST <base_url>/api.php/v1/bugs` |
//! | 凭据 | `api_token`（必需，禅道「Token」头） |
//! | 设置 | `base_url`（必需，内网常为 http）、`product_id`（必需，数字）、`opened_by`（可选，默认 `aiguardfabric`） |
//! | 映射 | 等级 → 禅道 `severity`（1 严重 / 2 高 / 3 中 / 4 低）与 `pri`（1..4） |
//! | 响应 | 2xx + `{"id":123,...}`；远端 id 取 `id` |
//! | `push` | `PUT /api.php/v1/bugs/{id}`（`status` / `comment`） |
//! | `pull` | `GET /api.php/v1/bugs?product=<id>&limit=N`（REST v1 无 `since` ⇒ **客户端增量过滤**） |
//! | `sync` | `pull` → 与本地缺陷快照比对 → 按冲突策略回写 |
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `base_url`/`product_id` 或凭据 | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包**；事件照常落库 |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock bug id，**绝不发起真实请求** |
//! | `product_id` 非正整数 / `opened_by` 非法 | `init()` 返回 `Config`，旧配置保持不变 |
//! | 禅道部署为内网 http | **允许**（与 ServiceNow 的 https 强制不同，禅道内网常见 http 部署） |
//! | `push` 缺 `entity_id` 或无 `status`/`comment` | `Validation`（不发空包） |
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

/// 缺陷提交路径（禅道 REST v1）。
pub const BUG_PATH: &str = "/api.php/v1/bugs";

/// 禅道适配器标记类型。
#[derive(Debug)]
pub struct Zentao;

impl Zentao {
    /// 等级 → 禅道 `severity`（1 最严重）。
    #[must_use]
    pub const fn severity_code(severity: Severity) -> u8 {
        match severity {
            Severity::Critical => 1,
            Severity::High => 2,
            Severity::Medium => 3,
            Severity::Low | Severity::Info => 4,
        }
    }

    /// 等级 → 禅道 `pri`（1 最高）。
    #[must_use]
    pub const fn priority_code(severity: Severity) -> u8 {
        match severity {
            Severity::Critical => 1,
            Severity::High => 2,
            Severity::Medium => 3,
            Severity::Low | Severity::Info => 4,
        }
    }

    /// 缺陷提交 URL。
    #[must_use]
    pub fn bug_endpoint(base_url: &str) -> String {
        format!("{}{BUG_PATH}", base_url.trim_end_matches('/'))
    }

    /// 缺陷请求体。
    #[must_use]
    pub fn bug_body(msg: &AdapterMessage, product_id: u64, opened_by: &str) -> serde_json::Value {
        let steps = format!(
            "【{}】{}\n\n{}\n\nevent_type={}\nasset={}\nidempotency_key={}\noccurred_at={}",
            msg.severity.as_str(),
            msg.title,
            msg.summary,
            msg.event_type,
            msg.asset.clone().unwrap_or_else(|| "-".to_string()),
            msg.idempotency_key,
            msg.occurred_at.to_rfc3339()
        );
        json!({
            "title": msg.title,
            "product": product_id,
            "severity": Self::severity_code(msg.severity),
            "pri": Self::priority_code(msg.severity),
            "type": "ai-security",
            "steps": steps,
            "openedBy": opened_by,
            "keywords": msg.labels.values().cloned().collect::<Vec<String>>(),
        })
    }
}

impl VendorSpec for Zentao {
    const NAME: &'static str = "zentao";
    const REAL_TRANSPORT: bool = true;
    const REQUIRED_SETTINGS: &'static [&'static str] = &["base_url", "product_id"];
    const SYNC_PUSH_ENTITY: &'static str = "ticket.status";

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("zentao", "禅道（ZenTao）", "易软天创", AdapterCategory::Itsm)
            .with_secrets(&["api_token"], &[])
            .with_endpoint_key("base_url")
            .with_capabilities(crate::vendors::itsm_capabilities())
            .with_semantics(SemanticProfile::full())
            .with_degradation(
                "未配置 base_url/product_id 或凭据时不提交任何缺陷单；事件照常落库并在控制台可见，\
                 可由值班人工建单；禅道内网 http 部署受支持",
            )
            .with_mock_location("crates/agf-adapters/src/vendors/zentao.rs#MockZentaoAdapter")
            .with_real_transport(true)
    }

    /// 状态回写（`PUT /api.php/v1/bugs/{id}`）。
    ///
    /// # Errors
    /// 实体名不支持、`entity_id` 缺失/非法、载荷无 `status`/`comment` 时返回错误。
    fn encode_push(payload: &PushPayload, settings: &AdapterSettings) -> DomainResult<Vec<VendorRequest>> {
        Self::encode_push_requests(payload, settings)
    }

    /// 增量拉取（REST v1 无 `since` 参数，增量在客户端过滤）。
    ///
    /// # Errors
    /// 资源名不支持或配置缺项时返回错误。
    fn encode_pull(req: &PullRequest, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Self::encode_pull_request(req, settings)
    }

    /// 解析缺陷列表并按 `cursor` 做客户端增量过滤，注入规范化字段。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 `bugs` 数组时返回 `DomainError::Validation`。
    fn parse_pull(status: u16, body: &str, req: &PullRequest) -> DomainResult<PullPage> {
        Self::parse_pull(status, body, req)
    }

    /// 回写响应：`{"id":123,...}`。
    ///
    /// # Errors
    /// 响应体缺 `id` 时返回 `DomainError::Validation`。
    fn parse_push_response(status: u16, body: &str) -> DomainResult<Option<String>> {
        Self::parse_push_response(status, body)
    }

    /// 解析建单响应：禅道返回 `{"id":123,...}`（整数 id）。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 `id` 字段时返回 `DomainError::Validation`。
    fn parse_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        let id = crate::http::extract_id(body, &["id", "data.id", "bug.id"]);
        if id.is_none() {
            return Err(DomainError::Validation(format!(
                "zentao 建单响应缺少 id 字段: {}",
                crate::http::snippet(body)
            )));
        }
        Ok(id)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        if let Some(base) = settings.get_str("base_url") {
            crate::settings::validate_endpoint(base)?;
            let parsed = url::Url::parse(base).map_err(|e| DomainError::Config(format!("base_url 非法: {e}")))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(DomainError::Config("禅道 base_url 只支持 http/https".to_string()));
            }
        }
        if let Some(value) = settings.settings.get("product_id") {
            let id = value.as_u64().ok_or_else(|| DomainError::Config("product_id 必须是正整数".to_string()))?;
            if id == 0 {
                return Err(DomainError::Config("product_id 不能为 0".to_string()));
            }
        }
        if let Some(opened_by) = settings.get_str("opened_by") {
            if opened_by.trim().is_empty() || opened_by.chars().any(char::is_whitespace) {
                return Err(DomainError::Config(format!("opened_by 非法: {opened_by:?}")));
            }
        }
        Ok(())
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let base_url = crate::vendors::require_setting(settings, "base_url")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let product_id = settings
            .settings
            .get("product_id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| DomainError::Config("禅道 product_id 未配置或非数字".to_string()))?;
        let opened_by = settings.get_str("opened_by").unwrap_or("aiguardfabric");
        Ok(VendorRequest::post(
            Self::bug_endpoint(&base_url),
            "application/json",
            Self::bug_body(msg, product_id, opened_by),
        )
        .with_header("Token", token)
        .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, msg.idempotency_key.clone()))
    }
}

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockZentaoAdapter = crate::vendor::VendorAdapterImpl<Zentao>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::VendorAdapter;
    use crate::settings::AdapterMode;
    use crate::test_support::settings_for;

    fn message() -> AdapterMessage {
        AdapterMessage::event(
            "ai.mcp.plaintext_secret",
            Severity::Medium,
            "MCP 明文凭据",
            "mcp.json 中 env 含密钥",
            json!({}),
        )
        .with_asset("mcp:filesystem")
        .with_label("file", "~/.cursor/mcp.json")
    }

    fn settings(extra: &[(&str, serde_json::Value)]) -> AdapterSettings {
        let mut base: Vec<(&str, serde_json::Value)> =
            vec![("base_url", json!("http://zentao.internal.example/")), ("product_id", json!(7))];
        base.extend_from_slice(extra);
        settings_for(&Zentao::metadata(), &base, &[("api_token", "zentao-token-abcdef")]).expect("测试设置必须可构造")
    }

    #[test]
    fn severity_and_priority_mapping() {
        assert_eq!(Zentao::severity_code(Severity::Critical), 1);
        assert_eq!(Zentao::severity_code(Severity::High), 2);
        assert_eq!(Zentao::severity_code(Severity::Medium), 3);
        assert_eq!(Zentao::severity_code(Severity::Low), 4);
        assert_eq!(Zentao::severity_code(Severity::Info), 4);
        assert_eq!(Zentao::priority_code(Severity::Critical), 1);
        assert_eq!(Zentao::priority_code(Severity::Info), 4);
    }

    #[test]
    fn endpoint_join_and_body() {
        assert_eq!(Zentao::bug_endpoint("http://z.example/"), "http://z.example/api.php/v1/bugs");
        let body = Zentao::bug_body(&message(), 7, "aiguardfabric");
        assert_eq!(body["product"], 7);
        assert_eq!(body["severity"], 3);
        assert_eq!(body["type"], "ai-security");
        assert!(body["steps"].as_str().unwrap_or_default().contains("ai.mcp.plaintext_secret"));
        assert_eq!(body["keywords"][0], "~/.cursor/mcp.json");
    }

    #[test]
    fn validation_matrix() {
        assert!(Zentao::validate_settings(&settings(&[])).is_ok());
        assert!(Zentao::validate_settings(&settings(&[("product_id", json!("seven"))])).is_err());
        assert!(Zentao::validate_settings(&settings(&[("product_id", json!(0))])).is_err());
        assert!(Zentao::validate_settings(&settings(&[("opened_by", json!("bad user"))])).is_err());
        // 非法 scheme 无法通过通用配置校验，故用 raw_settings 直达厂商校验
        let file_url =
            crate::test_support::raw_settings(&Zentao::metadata(), &[("base_url", json!("file:///tmp/x"))], &[]);
        assert!(Zentao::validate_settings(&file_url).is_err());
        // 内网 http 允许（与 ServiceNow 不同）
        assert!(Zentao::validate_settings(&settings(&[("base_url", json!("http://10.0.0.9"))])).is_ok());
    }

    #[test]
    fn encode_uses_token_header() {
        let req = Zentao::encode(&message(), &settings(&[])).expect("编码应成功");
        assert_eq!(req.headers.get("Token").map(String::as_str), Some("zentao-token-abcdef"));
        assert_eq!(req.endpoint, "http://zentao.internal.example/api.php/v1/bugs");
    }

    #[tokio::test]
    async fn mock_mode_and_missing_product_id() {
        let mut mock = crate::vendor::VendorAdapterImpl::<Zentao>::mocked();
        let receipt = mock.send(&message()).await.expect("Mock 发送");
        assert_eq!(receipt.origin, "mock://zentao");

        let mut adapter = crate::vendor::VendorAdapterImpl::<Zentao>::new();
        adapter
            .init_with(
                &crate::test_support::config_for("zentao", &[("base_url", json!("http://z.example"))], false),
                &crate::test_support::secrets(&[("api_token", "t")]),
                false,
            )
            .await
            .expect("未配置 product_id 不得导致 init 失败");
        assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
        let error = adapter.send(&message()).await.expect_err("缺必需设置必须明确报错");
        assert!(error.to_string().contains("product_id"), "{error}");
    }

    #[tokio::test]
    async fn live_mode_reports_real_transport() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<Zentao>::new();
        let config = crate::test_support::config_for(
            "zentao",
            &[("base_url", json!("http://z.example")), ("product_id", json!(3))],
            false,
        );
        adapter
            .init_with(&config, &crate::test_support::secrets(&[("api_token", "t")]), false)
            .await
            .expect("合法配置");
        assert_eq!(adapter.mode(), AdapterMode::Live);
        assert!(adapter.descriptor().real_implementation, "禅道已实现真实 HTTP 建单");
        assert!(!adapter.build_record().message.unwrap_or_default().contains("TODO("));
        assert_eq!(adapter.encode(&message()).expect("编码应成功").endpoint, "http://z.example/api.php/v1/bugs");
    }

    #[test]
    fn parse_response_reads_integer_id() {
        assert_eq!(Zentao::parse_response(201, r#"{"id":123,"title":"x"}"#).ok().flatten().as_deref(), Some("123"));
        assert_eq!(Zentao::parse_response(200, r#"{"data":{"id":"456"}}"#).ok().flatten().as_deref(), Some("456"));
        assert!(Zentao::parse_response(200, r#"{"error":"forbidden"}"#).is_err());
    }
}
