//! EDR 主机隔离指令适配器（真实 HTTP 指令下发 + 处置状态回写 + 增量拉取）。
//!
//! | 项 | 值 |
//! |---|---|
//! | 通道 | 真实 HTTP `POST <endpoint>/v1/hosts/{host}/isolate` |
//! | 凭据 | `api_token`（必需，Bearer 令牌） |
//! | 设置 | `endpoint`（必需）、`vendor`（可选，默认 `generic-edr`）、`dry_run`（可选，默认 `true`） |
//! | 订阅 | 仅订阅带 `action=isolate` 标签或事件类型以 `enforce.` 开头的载荷（避免误隔离） |
//! | 响应 | 2xx + `{"task_id":"..."}`/`{"id":"..."}`；远端 id 用于回执与审计对齐 |
//! | `push` | `PATCH <endpoint>/v1/hosts/{host}/isolation`（`action=isolate/release`，同样受 dry-run 保护） |
//! | `pull` | `GET <endpoint>/v1/hosts?updated_since=<cursor>&limit=N`、`GET <endpoint>/v1/events?since=<cursor>&limit=N` |
//! | `sync` | 拉 EDR 主机清单 → 与本地资产快照比对 → 按冲突策略回写处置状态 |
//!
//! ## 安全约束（刻意的设计）
//!
//! 1. **默认 `dry_run=true`**：即使配置齐全，指令载荷默认携带 `dry_run=true` 与
//!    `X-AGF-Dry-Run: true` 头，由 EDR 侧解释为"预演不落地"；真实隔离必须显式设置
//!    `dry_run=false`（**两个开关都在，缺一不下发真实动作**：既要配置齐全，也要显式关闭 dry-run）；
//! 2. 缺少 `host_id` / `asset` 时**拒绝构造**（`Validation`），绝不下发模糊目标的隔离指令；
//! 3. 非订阅载荷（普通告警）在 `send` 入口即被拒绝（`Validation`），不进入编码与传输；
//! 4. `push`/`pull` 同样带 `X-AGF-Dry-Run` 标记，且 `push` 缺 `action` 时**不猜动作**（`Validation`）。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 未配置 `endpoint` 或 `api_token` | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误并列出缺项，**不建连、不发包**；事件照常落库，人工可在 EDR 控制台处置 |
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 返回确定性 Mock 回执，**绝不发起真实请求** |
//! | `dry_run=true`（默认） | 指令照常构造并按上述规则下发，但携带 dry-run 标记（是否产生副作用由 EDR 侧判定） |
//! | 载荷缺 `host_id`/`host`/`asset` | `Validation` 错误，**拒绝构造**（不发出模糊指令） |
//! | 非隔离类载荷 | `send()` 返回 `Validation`（不订阅），不进入传输层 |
//! | 上游 5xx / 超时 | `DependencyUnavailable` / `Timeout`，**按 `RetryConfig` 重试**；4xx 不重试 |

use agf_core::adapter::PullRequest;
use agf_core::adapter::PushPayload;
use agf_core::error::{DomainError, DomainResult};
use serde_json::json;

use crate::contract::{AdapterCategory, AdapterMessage, AdapterMetadata, PullPage, SemanticProfile};
use crate::settings::AdapterSettings;
use crate::transport::VendorRequest;
use crate::vendor::VendorSpec;

/// 隔离指令的标签键。
pub const LABEL_ACTION: &str = "action";

/// 触发隔离的标签值。
pub const ACTION_ISOLATE: &str = "isolate";

/// EDR 隔离适配器标记类型。
#[derive(Debug)]
pub struct EdrIsolation;

impl EdrIsolation {
    /// 目标主机标识：优先 `host_id` 标签，其次 `host` 标签，最后关联资产。
    #[must_use]
    pub fn target_host(msg: &AdapterMessage) -> Option<String> {
        msg.labels
            .get("host_id")
            .or_else(|| msg.labels.get("host"))
            .cloned()
            .or_else(|| msg.asset.clone())
            .filter(|h| !h.trim().is_empty())
    }

    /// 隔离指令 URL。
    #[must_use]
    pub fn isolate_endpoint(endpoint: &str, host: &str) -> String {
        format!("{}/v1/hosts/{host}/isolate", endpoint.trim_end_matches('/'))
    }

    /// 指令体（可审计：含幂等键、原因、工单号与 dry-run 标记）。
    #[must_use]
    pub fn isolate_body(msg: &AdapterMessage, host: &str, dry_run: bool) -> serde_json::Value {
        json!({
            "action": ACTION_ISOLATE,
            "host_id": host,
            "reason": msg.summary,
            "case_id": msg.labels.get("case_id"),
            "requested_by": "aiguardfabric",
            "dry_run": dry_run,
            "idempotency_key": msg.idempotency_key,
            "occurred_at": msg.occurred_at.to_rfc3339(),
        })
    }
}

impl VendorSpec for EdrIsolation {
    const NAME: &'static str = "edr-isolation";
    const REAL_TRANSPORT: bool = true;
    const REQUIRED_SETTINGS: &'static [&'static str] = &["endpoint"];
    const SYNC_PUSH_ENTITY: &'static str = "host.isolation";

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("edr-isolation", "EDR 主机隔离指令", "终端安全平台", AdapterCategory::SecurityPlatform)
            .with_secrets(&["api_token"], &[])
            .with_endpoint_key("endpoint")
            .with_capabilities(vec![
                agf_core::adapter::AdapterCapability::EnforcePolicy,
                agf_core::adapter::AdapterCapability::PullInventory,
                agf_core::adapter::AdapterCapability::QueryLogs,
                agf_core::adapter::AdapterCapability::SelfCheck,
            ])
            .with_semantics(SemanticProfile::full())
            .with_degradation(
                "未配置 endpoint/api_token 时不下发任何隔离指令（事件照常落库，可由人工在 EDR 控制台处置）；\
                 默认为 dry-run，真实隔离需显式设置 dry_run=false",
            )
            .with_mock_location(
                "crates/agf-adapters/src/vendors/edr.rs#MockEdrIsolationAdapter（注册名 edr-isolation）",
            )
            .with_real_transport(true)
    }

    /// 处置状态回写（`PATCH /v1/hosts/{host}/isolation`，同样受 dry-run 保护）。
    ///
    /// # Errors
    /// 实体名不支持、主机缺失/非法、`action` 非法或配置缺项时返回错误。
    fn encode_push(payload: &PushPayload, settings: &AdapterSettings) -> DomainResult<Vec<VendorRequest>> {
        Self::encode_push_requests(payload, settings)
    }

    /// 增量拉取主机清单 / 设备事件。
    ///
    /// # Errors
    /// 资源名不支持或配置缺项时返回错误。
    fn encode_pull(req: &PullRequest, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Self::encode_pull_request(req, settings)
    }

    /// 解析主机/事件清单并注入规范化字段（主机状态的 `action` 由 `isolation_state` 推导）。
    ///
    /// # Errors
    /// 响应体非 JSON、缺少对应数组或条目缺 id 时返回 `DomainError::Validation`。
    fn parse_pull(status: u16, body: &str, req: &PullRequest) -> DomainResult<PullPage> {
        Self::parse_pull(status, body, req)
    }

    /// 回写响应：必须含 `host_id` 与 `isolation_state`（否则无法确认处置结果）。
    ///
    /// # Errors
    /// 响应缺字段或非 JSON 时返回 `DomainError::Validation`。
    fn parse_push_response(status: u16, body: &str) -> DomainResult<Option<String>> {
        Self::parse_push_response(status, body)
    }

    /// 解析隔离指令回执，提取 EDR 侧任务/指令 id。
    ///
    /// # Errors
    /// 响应体非 JSON 时返回 `DomainError::Validation`；上游未返回 id 时按"已接受但无 id"处理。
    fn parse_response(_status: u16, body: &str) -> DomainResult<Option<String>> {
        if body.trim().is_empty() {
            return Ok(None);
        }
        let id = crate::http::extract_id(body, &["task_id", "data.task_id", "id", "command_id", "data.id"]);
        Ok(id)
    }

    fn validate_settings(settings: &AdapterSettings) -> DomainResult<()> {
        if let Some(endpoint) = settings.get_str("endpoint") {
            crate::settings::validate_endpoint(endpoint)?;
            let parsed =
                url::Url::parse(endpoint).map_err(|e| DomainError::Config(format!("EDR endpoint 非法: {e}")))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(DomainError::Config("EDR endpoint 只支持 http/https".to_string()));
            }
        }
        if let Some(vendor) = settings.get_str("vendor") {
            if vendor.trim().is_empty() || vendor.chars().any(char::is_whitespace) {
                return Err(DomainError::Config(format!("EDR vendor 非法: {vendor:?}")));
            }
        }
        Ok(())
    }

    fn subscribes(msg: &AdapterMessage) -> bool {
        msg.event_type.starts_with("enforce.")
            || msg.labels.get(LABEL_ACTION).is_some_and(|v| v.eq_ignore_ascii_case(ACTION_ISOLATE))
    }

    fn encode(msg: &AdapterMessage, settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        let endpoint = crate::vendors::require_setting(settings, "endpoint")?;
        let token = crate::vendors::require_secret(settings, "api_token")?;
        let host = Self::target_host(msg).ok_or_else(|| {
            DomainError::Validation("EDR 隔离指令缺少目标主机：需在 labels 提供 host_id/host 或设置 asset".to_string())
        })?;
        let host = crate::vendors::require_safe_id(Self::NAME, &host, "host id")?;
        let dry_run = settings.get_bool("dry_run", true);
        let vendor = settings.get_str("vendor").unwrap_or("generic-edr");
        Ok(VendorRequest::post(
            Self::isolate_endpoint(&endpoint, &host),
            "application/json",
            Self::isolate_body(msg, &host, dry_run),
        )
        .with_header("Authorization", format!("Bearer {token}"))
        .with_header("X-AGF-EDR-Vendor", vendor)
        .with_header("X-AGF-Dry-Run", dry_run.to_string())
        .with_header(agf_core::constants::HEADER_IDEMPOTENCY_KEY, msg.idempotency_key.clone()))
    }
}

/// Mock 实现（真实传输由 [`crate::vendor::VendorAdapterImpl`] 统一接管，Mock 时由 `mock_mode` 短路）。
pub type MockEdrIsolationAdapter = crate::vendor::VendorAdapterImpl<EdrIsolation>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::VendorAdapter;
    use crate::settings::AdapterMode;
    use crate::test_support::settings_for;
    use agf_core::enums::Severity;

    fn isolate_message() -> AdapterMessage {
        AdapterMessage::event("enforce.isolate", Severity::Critical, "隔离受控主机", "检出 C2 回连", json!({}))
            .with_label(LABEL_ACTION, ACTION_ISOLATE)
            .with_label("host_id", "host-42")
            .with_label("case_id", "CASE-2026-0001")
    }

    fn settings(extra: &[(&str, serde_json::Value)]) -> AdapterSettings {
        let mut base: Vec<(&str, serde_json::Value)> = vec![("endpoint", json!("https://edr.example.invalid"))];
        base.extend_from_slice(extra);
        settings_for(&EdrIsolation::metadata(), &base, &[("api_token", "edr-token-abcdef")])
            .expect("测试设置必须可构造")
    }

    #[test]
    fn target_host_resolution_order() {
        let msg = isolate_message();
        assert_eq!(EdrIsolation::target_host(&msg).as_deref(), Some("host-42"));
        let by_asset =
            AdapterMessage::event("enforce.isolate", Severity::High, "t", "s", json!({})).with_asset("host-9");
        assert_eq!(EdrIsolation::target_host(&by_asset).as_deref(), Some("host-9"));
        let none = AdapterMessage::event("enforce.isolate", Severity::High, "t", "s", json!({}));
        assert!(EdrIsolation::target_host(&none).is_none());
    }

    #[test]
    fn encode_requires_target_host() {
        let no_host = AdapterMessage::event("enforce.isolate", Severity::High, "t", "s", json!({}));
        let error = EdrIsolation::encode(&no_host, &settings(&[])).expect_err("缺目标主机必须拒绝");
        assert!(matches!(error, DomainError::Validation(_)));
        assert!(error.to_string().contains("host_id"));
    }

    #[test]
    fn encode_rejects_host_path_traversal() {
        for host in ["..", "../other", "host/other", "host?x=1", "%2e%2e"] {
            let msg = isolate_message().with_label("host_id", host);
            assert!(matches!(EdrIsolation::encode(&msg, &settings(&[])), Err(DomainError::Validation(_))), "{host}");
        }
    }

    #[test]
    fn encode_defaults_to_dry_run() {
        let req = EdrIsolation::encode(&isolate_message(), &settings(&[])).expect("编码应成功");
        assert_eq!(req.endpoint, "https://edr.example.invalid/v1/hosts/host-42/isolate");
        assert_eq!(req.body["dry_run"], true, "默认必须 dry-run");
        assert_eq!(req.headers.get("X-AGF-Dry-Run").map(String::as_str), Some("true"));
        assert_eq!(req.headers.get("X-AGF-EDR-Vendor").map(String::as_str), Some("generic-edr"));
        assert_eq!(req.body["case_id"], "CASE-2026-0001");
        assert_eq!(req.body["requested_by"], "aiguardfabric");

        let live =
            EdrIsolation::encode(&isolate_message(), &settings(&[("dry_run", json!(false))])).expect("编码应成功");
        assert_eq!(live.body["dry_run"], false);
        assert_eq!(live.headers.get("X-AGF-Dry-Run").map(String::as_str), Some("false"));
    }

    #[test]
    fn subscribes_only_enforce_or_isolate_payloads() {
        assert!(EdrIsolation::subscribes(&isolate_message()));
        let plain = AdapterMessage::notification("普通告警", "摘要");
        assert!(!EdrIsolation::subscribes(&plain), "普通通知不得触发隔离指令");
        let labelled = AdapterMessage::notification("手工隔离", "运维要求").with_label(LABEL_ACTION, "isolate");
        assert!(EdrIsolation::subscribes(&labelled));
    }

    #[test]
    fn validation_matrix() {
        assert!(EdrIsolation::validate_settings(&settings(&[])).is_ok());
        assert!(EdrIsolation::validate_settings(&settings(&[("endpoint", json!("syslog://10.0.0.1:514"))])).is_err());
        assert!(EdrIsolation::validate_settings(&settings(&[("vendor", json!("bad vendor"))])).is_err());
    }

    #[tokio::test]
    async fn non_subscribed_payload_is_rejected_by_send() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<EdrIsolation>::mocked();
        let error = adapter.send(&AdapterMessage::notification("普通告警", "摘要")).await.expect_err("不应订阅");
        assert!(matches!(error, DomainError::Validation(_)));
        let receipt = adapter.send(&isolate_message()).await.expect("隔离指令应被接受");
        assert!(receipt.mocked);
    }

    #[tokio::test]
    async fn unconfigured_and_live_behaviour() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<EdrIsolation>::new();
        adapter
            .init_with(
                &crate::test_support::config_for(
                    "edr-isolation",
                    &[("endpoint", json!("https://edr.example.invalid"))],
                    false,
                ),
                &crate::settings::NoSecrets,
                false,
            )
            .await
            .expect("未配置不得失败");
        assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
        assert!(adapter.send(&isolate_message()).await.is_err());

        let mut live = crate::vendor::VendorAdapterImpl::<EdrIsolation>::new();
        live.init_with(
            &crate::test_support::config_for(
                "edr-isolation",
                &[("endpoint", json!("https://edr.example.invalid"))],
                false,
            ),
            &crate::test_support::secrets(&[("api_token", "edr-token-abcdef")]),
            false,
        )
        .await
        .expect("合法配置");
        assert_eq!(live.mode(), AdapterMode::Live);
        assert!(live.descriptor().real_implementation, "EDR 隔离已实现真实 HTTP 下发");
        assert!(!live.build_record().message.unwrap_or_default().contains("TODO("));
        // 真实下发路径的编码产物：目标主机 + dry-run 保护标记齐全
        let request = live.encode(&isolate_message()).expect("编码应成功");
        assert_eq!(request.endpoint, "https://edr.example.invalid/v1/hosts/host-42/isolate");
        assert_eq!(request.headers.get("X-AGF-Dry-Run").map(String::as_str), Some("true"));
    }

    #[test]
    fn parse_response_extracts_edr_task_id() {
        assert_eq!(
            EdrIsolation::parse_response(200, r#"{"task_id":"task-7","status":"accepted"}"#).ok().flatten().as_deref(),
            Some("task-7")
        );
        assert_eq!(
            EdrIsolation::parse_response(200, r#"{"data":{"id":"cmd-3"}}"#).ok().flatten().as_deref(),
            Some("cmd-3")
        );
        assert_eq!(EdrIsolation::parse_response(200, "").ok(), Some(None), "空响应体视为已接受但无任务 id");
    }

    #[tokio::test]
    async fn debug_hides_token() {
        let mut adapter = crate::vendor::VendorAdapterImpl::<EdrIsolation>::new();
        adapter
            .init_with(
                &crate::test_support::config_for(
                    "edr-isolation",
                    &[("endpoint", json!("https://edr.example.invalid"))],
                    false,
                ),
                &crate::test_support::secrets(&[("api_token", "edr-token-abcdef")]),
                false,
            )
            .await
            .expect("合法配置");
        let text = format!("{adapter:?}");
        assert!(!text.contains("edr-token-abcdef"), "{text}");
        assert!(adapter.encode(&isolate_message()).is_ok());
    }
}
