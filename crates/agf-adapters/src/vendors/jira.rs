//! Jira 适配器（REST v2 issue 创建 + 状态回写 + 增量拉取）。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | 真实 HTTP `POST <base_url>/rest/api/2/issue` |
//! | 凭据 | `api_token`（必需，Jira Cloud API Token）、`user_email`（必需，Atlassian 账号邮箱） |
//! | 设置 | `base_url`（必需）、`project_key`（必需）、`issue_type`（可选，默认 `Task`） |
//! | 鉴权 | `Authorization: Basic base64("{user_email}:{api_token}")` |
//! | 映射 | 等级 → `priority.name`（`Highest`/`High`/`Medium`/`Low`/`Lowest`）；标签 → `labels` |
//! | 响应 | 2xx + `{"id":"10001","key":"SEC-1"}`；远端 id 优先取 `key`（人读工单号，且可直接用于路径） |
//! | `push` | `PUT /rest/api/2/issue/{key}/transitions`（工作流推进）+ `POST /rest/api/2/issue/{key}/comment`（评论） |
//! | `pull` | `GET /rest/api/2/search?jql=project = "SEC" AND updated >= "<cursor>" ORDER BY updated ASC&maxResults=N` |
//! | `sync` | `pull` → 与本地案件快照比对 → 按冲突策略回写（默认外部优先） |
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `base_url`/`project_key`/凭据 | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包**；事件照常落库，可由值班人工建单 |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock 工单号，**绝不发起真实请求** |
//! | `base_url` 非 http/https 或 `project_key` 非法 | `init()` 阶段返回 `Config`，旧配置保持不变 |
//! | `push` 缺 `entity_id`/`comment`/`transition_id` | `Validation`（回写目标或内容不明，**不发空包**） |
//! | `pull` 资源名不在白名单 | `Validation`（列出支持项） |
//! | 上游 5xx / 超时 | `DependencyUnavailable` / `Timeout`，**按 `RetryConfig` 重试** |
//! | 上游 4xx（字段非法/无权限） | `Validation`/`Forbidden`/`Unauthenticated`，**不重试** |

use agf_core::adapter::PullRequest;
use agf_core::adapter::PushPayload;
use agf_core::enums::Severity;
use agf_core::error::{DomainError, DomainResult};
use base64::Engine as _;
use serde_json::json;

use crate::contract::{AdapterCategory, AdapterMessage, AdapterMetadata, PullPage, SemanticProfile};
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec;

/// Jira issue 创建路径（REST v2）。
pub const ISSUE_PATH: &str = "/rest/api/2/issue";

/// Jira 适配器标记类型。
#[derive(Debug)]
pub struct Jira;

impl Jira {
    /// 等级 → Jira 优先级名。
    #[must_use]
    pub const fn priority(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "Highest",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Lowest",
        }
    }

    /// issue 创建 URL（容忍 `base_url` 末尾斜杠）。
    #[must_use]
    pub fn issue_endpoint(base_url: &str) -> String {
        format!("{}{ISSUE_PATH}", base_url.trim_end_matches('/'))
    }

    /// Basic 鉴权头（明文只在内存短暂存在）。
    #[must_use]
    pub fn basic_auth(email: &str, token: &str) -> String {
        let raw = format!("{email}:{token}");
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()))
    }

    /// issue 请求体。
    #[must_use]
    pub fn issue_body(msg: &AdapterMessage, project_key: &str, issue_type: &str) -> serde_json::Value {
        let mut labels: Vec<String> = vec!["aiguardfabric".to_string(), format!("agf-{}", msg.severity.as_str())];
        labels.extend(msg.labels.values().cloned());
        let description = format!(
            "{}\n\n*等级*: {}\n*事件*: {}\n*资产*: {}\n*幂等键*: {}\n*发生时间*: {}",
            msg.summary,
            msg.severity.as_str(),
            msg.event_type,
            msg.asset.clone().unwrap_or_else(|| "-".to_string()),
            msg.idempotency_key,
            msg.occurred_at.to_rfc3339()
        );
        json!({
            "fields": {
                "project": { "key": project_key },
                "summary": msg.title,
                "description": description,
                "issuetype": { "name": issue_type },
                "priority": { "name": Self::priority(msg.severity) },
                "labels": labels,
            }
        })
    }
}

impl VendorSpec for Jira {
    const NAME: &'static str = "jira";
    const REAL_TRANSPORT: bool = true;
    const REQUIRED_SETTINGS: &'static [&'static str] = &["base_url", "project_key"];
    const SYNC_PUSH_ENTITY: &'static str = "ticket.status";

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("jira", "Jira", "Atlassian", AdapterCategory::Itsm)
            .with_secrets(&["api_token", "user_email"], &[])
            .with_endpoint_key("base_url")
            .with_capabilities(crate::vendors::itsm_capabilities())
            .with_semantics(SemanticProfile::full())
            .with_degradation(
                "未配置 base_url/project_key 或凭据时不创建任何工单；事件照常落库并在控制台可见，\
                 可由值班人工建单，不影响主流程",
            )
            .with_mock_location("crates/agf-adapters/src/vendors/jira.rs#MockJiraAdapter")
            .with_real_transport(true)
    }

    /// 状态回写：工作流推进（`transition_id`）+ 评论（`comment`），可同时给出。
    ///
    /// # Errors
    /// 实体名不支持、`entity_id` 缺失/非法、载荷无回写字段时返回错误（见 [`Jira::encode_push_requests`]）。
    fn encode_push(payload: &PushPayload, settings: &AdapterSettings) -> DomainResult<Vec<VendorRequest>> {
        Self::encode_push_requests(payload, settings)
    }

    /// 增量拉取（增量参数走 JQL `updated >= cursor`）。
    ///
    /// # Errors
    /// 资源名不支持或配置缺项时返回错误（见 [`Jira::encode_pull_request`]）。
    fn encode_pull(req: &PullRequest, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Self::encode_pull_request(req, settings)
    }

    /// 解析搜索响应并注入规范化字段（`agf_remote_id`/`agf_updated_at`/`agf_state`）。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 `issues` 数组时返回 `DomainError::Validation`。
    fn parse_pull(status: u16, body: &str, req: &PullRequest) -> DomainResult<PullPage> {
        Self::parse_pull(status, body, req)
    }

    /// 回写响应：评论返回 `{"id":...}`；工作流推进返回空体（`204`）。
    ///
    /// # Errors
    /// 上游拒绝（`errors`/`errorMessages` 非空）时返回 `DomainError::Validation`。
    fn parse_push_response(status: u16, body: &str) -> DomainResult<Option<String>> {
        Self::parse_push_response(status, body)
    }

    /// 解析 issue 创建响应：优先 `key`（人读工单号），回退 `id`。
    ///
    /// # Errors
    /// 响应体非 JSON 或缺少 id/key 字段时返回 `DomainError::Validation`。
    fn parse_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        let id = crate::http::extract_id(body, &["key", "id"]);
        if id.is_none() {
            return Err(DomainError::Validation(format!(
                "jira 创建工单响应缺少 key/id 字段: {}",
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
                return Err(DomainError::Config("Jira base_url 只支持 http/https".to_string()));
            }
        }
        if let Some(key) = settings.get_str("project_key") {
            let key = key.trim();
            if key.is_empty()
                || key.len() > 10
                || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(DomainError::Config(format!("Jira project_key 非法: {key:?}（大写字母/数字，≤10 位）")));
            }
        }
        if let Some(email) = settings.secret_raw("user_email") {
            crate::vendors::email::validate_address(email, "user_email")?;
        }
        Ok(())
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let base_url = crate::vendors::require_setting(settings, "base_url")?;
        let project_key = crate::vendors::require_setting(settings, "project_key")?;
        let email = crate::vendors::require_secret(settings, "user_email")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let issue_type = settings.get_str("issue_type").unwrap_or("Task");
        Ok(VendorRequest::post(
            Self::issue_endpoint(&base_url),
            "application/json",
            Self::issue_body(msg, &project_key, issue_type),
        )
        .with_header("Authorization", Self::basic_auth(&email, &token))
        .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, msg.idempotency_key.clone()))
    }
}

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockJiraAdapter = crate::vendor::VendorAdapterImpl<Jira>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::VendorAdapter;
    use crate::settings::AdapterMode;
    use crate::test_support::settings_for;
    use serde_json::json;

    fn message() -> AdapterMessage {
        AdapterMessage::event(
            "ai.prompt.injection",
            Severity::Critical,
            "提示词注入命中",
            "命中 PA-INJ-001",
            json!({"rule": "PA-INJ-001"}),
        )
        .with_asset("claude-code@host1")
        .with_label("rule", "PA-INJ-001")
    }

    fn settings(extra: &[(&str, serde_json::Value)]) -> AdapterSettings {
        let mut base: Vec<(&str, serde_json::Value)> =
            vec![("base_url", json!("https://acme.atlassian.net/")), ("project_key", json!("SEC"))];
        base.extend_from_slice(extra);
        settings_for(
            &Jira::metadata(),
            &base,
            &[("api_token", "jira-token-abcdef"), ("user_email", "soc@example.invalid")],
        )
        .expect("测试设置必须可构造")
    }

    #[test]
    fn endpoint_join_tolerates_trailing_slash() {
        assert_eq!(Jira::issue_endpoint("https://a.atlassian.net"), "https://a.atlassian.net/rest/api/2/issue");
        assert_eq!(Jira::issue_endpoint("https://a.atlassian.net/"), "https://a.atlassian.net/rest/api/2/issue");
        assert_eq!(Jira::issue_endpoint("https://a.atlassian.net///"), "https://a.atlassian.net/rest/api/2/issue");
    }

    #[test]
    fn priority_mapping_covers_all_levels() {
        for (severity, expected) in [
            (Severity::Critical, "Highest"),
            (Severity::High, "High"),
            (Severity::Medium, "Medium"),
            (Severity::Low, "Low"),
            (Severity::Info, "Lowest"),
        ] {
            assert_eq!(Jira::priority(severity), expected);
        }
    }

    #[test]
    fn basic_auth_encodes_email_and_token() {
        let header = Jira::basic_auth("soc@example.invalid", "tok");
        let encoded = header.strip_prefix("Basic ").unwrap_or_default();
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).unwrap_or_default();
        assert_eq!(String::from_utf8_lossy(&decoded), "soc@example.invalid:tok");
    }

    #[test]
    fn issue_body_carries_project_priority_labels() {
        let body = Jira::issue_body(&message(), "SEC", "Bug");
        assert_eq!(body["fields"]["project"]["key"], "SEC");
        assert_eq!(body["fields"]["priority"]["name"], "Highest");
        assert_eq!(body["fields"]["issuetype"]["name"], "Bug");
        let labels = body["fields"]["labels"].as_array().cloned().unwrap_or_default();
        assert!(labels.contains(&json!("aiguardfabric")));
        assert!(labels.contains(&json!("agf-critical")));
        assert!(labels.contains(&json!("PA-INJ-001")));
        assert!(body["fields"]["description"].as_str().unwrap_or_default().contains("PA-INJ-001"));
    }

    #[test]
    fn encode_sets_auth_and_idempotency_headers() {
        let req = Jira::encode(&message(), &settings(&[])).expect("编码应成功");
        assert_eq!(req.endpoint, "https://acme.atlassian.net/rest/api/2/issue");
        assert!(req.headers.get("Authorization").is_some_and(|v| v.starts_with("Basic ")));
        assert!(req.headers.contains_key(agf_core::constants::HEADER_IDEMPOTENCY_KEY));
    }

    #[test]
    fn validation_matrix() {
        assert!(Jira::validate_settings(&settings(&[])).is_ok());
        assert!(Jira::validate_settings(&settings(&[("project_key", json!("bad key"))])).is_err());
        assert!(Jira::validate_settings(&settings(&[("project_key", json!("TOOLONGPROJECTKEY"))])).is_err());
        // 非法 base_url 无法通过通用配置校验，故用 raw_settings 直达厂商校验
        let ftp = crate::test_support::raw_settings(
            &Jira::metadata(),
            &[("base_url", json!("ftp://jira.example.invalid"))],
            &[],
        );
        assert!(Jira::validate_settings(&ftp).is_err());
        let malformed = crate::test_support::raw_settings(&Jira::metadata(), &[("base_url", json!("not a url"))], &[]);
        assert!(Jira::validate_settings(&malformed).is_err());
        let bad_email = crate::test_support::raw_settings(&Jira::metadata(), &[], &[("user_email", "not-an-email")]);
        assert!(Jira::validate_settings(&bad_email).is_err());
    }

    #[tokio::test]
    async fn debug_does_not_leak_api_token_and_live_transport_is_registered() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<Jira>::new();
        let config = crate::test_support::config_for(
            "jira",
            &[("base_url", json!("https://acme.atlassian.net")), ("project_key", json!("SEC"))],
            false,
        );
        adapter
            .init_with(
                &config,
                &crate::test_support::secrets(&[
                    ("api_token", "jira-token-abcdef"),
                    ("user_email", "soc@example.invalid"),
                ]),
                false,
            )
            .await
            .expect("合法配置");
        assert_eq!(adapter.mode(), AdapterMode::Live);
        let text = format!("{adapter:?}");
        assert!(!text.contains("jira-token-abcdef"), "Debug 不得泄露 token: {text}");
        assert!(adapter.descriptor().real_implementation, "Jira 已实现真实 HTTP 建单");
        assert!(!adapter.build_record().message.unwrap_or_default().contains("TODO("));
    }

    #[test]
    fn parse_response_prefers_ticket_key() {
        assert_eq!(
            Jira::parse_response(201, r#"{"id":"10001","key":"SEC-7","self":"https://x"}"#).ok().flatten().as_deref(),
            Some("SEC-7")
        );
        assert_eq!(
            Jira::parse_response(200, r#"{"id":"10002"}"#).ok().flatten().as_deref(),
            Some("10002"),
            "缺 key 时回退 id"
        );
        let error = Jira::parse_response(200, r#"{"errors":{"summary":"required"}}"#).expect_err("缺 id/key 必须报错");
        assert!(error.to_string().contains("summary"), "{error}");
    }

    #[tokio::test]
    async fn mock_receipt_prefixed_with_adapter_name() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<Jira>::mocked();
        let receipt = adapter.send(&message()).await.expect("Mock 发送");
        assert!(receipt.remote_id.unwrap_or_default().starts_with("mock-"));
        assert_eq!(receipt.origin, "mock://jira");
    }
}
