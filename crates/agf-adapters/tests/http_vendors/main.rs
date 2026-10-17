#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! 集成测试：**真实传输往返**（wiremock 本地假服务器 + 真 UDP/TCP 回环）。
//!
//! 与 `registry_routing.rs` 的分工：那边验证注册表/路由/Mock 语义（零网络），
//! 这边验证"配置齐全时确实把字节发出去了"——每个断言都覆盖
//! **请求方法 / 路径 / 请求头 / JSON 请求体**，再覆盖**响应解析**，
//! 另外覆盖**超时、5xx 重试（按 `RetryConfig`）、断路器状态流转**。
//!
//! 所有用例都不联外网：HTTP 走 `wiremock` 的 `127.0.0.1` 随机端口，
//! Syslog 走本机 UDP/TCP 回环套接字。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::time::Duration;

pub(crate) use agf_adapters::contract::VendorAdapter;

pub(crate) use agf_adapters::settings::StaticSecrets;

pub(crate) use agf_adapters::vendor::VendorAdapterImpl;
pub(crate) use agf_adapters::vendor::VendorSpec;

pub(crate) use agf_adapters::vendors::dingtalk::DingTalk;

pub(crate) use agf_adapters::vendors::edr::EdrIsolation;

pub(crate) use agf_adapters::vendors::email::Email;

pub(crate) use agf_adapters::vendors::feishu::Feishu;

pub(crate) use agf_adapters::vendors::jira::Jira;

pub(crate) use agf_adapters::vendors::servicenow::ServiceNow;

pub(crate) use agf_adapters::vendors::slack::Slack;

pub(crate) use agf_adapters::vendors::syslog::SyslogForwarder;

pub(crate) use agf_adapters::vendors::webhook::Webhook;

pub(crate) use agf_adapters::vendors::wecom::WeCom;

pub(crate) use agf_adapters::vendors::zentao::Zentao;

pub(crate) use agf_adapters::AdapterMessage;
pub(crate) use agf_adapters::AdapterMode;

pub(crate) use agf_adapters::contract::ConflictPolicy;
pub(crate) use agf_adapters::contract::LocalSnapshot;
pub(crate) use agf_adapters::contract::SyncRequest;

pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::CircuitBreakerConfig;
pub(crate) use agf_core::adapter::CircuitState;
pub(crate) use agf_core::adapter::PullRequest;
pub(crate) use agf_core::adapter::PushPayload;
pub(crate) use agf_core::adapter::RetryConfig;

pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainError;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde_json::Value;
pub(crate) use serde_json::json;

pub(crate) use tokio::io::AsyncReadExt;

pub(crate) use wiremock::matchers::any;
pub(crate) use wiremock::matchers::body_partial_json;
pub(crate) use wiremock::matchers::header;
pub(crate) use wiremock::matchers::method;
pub(crate) use wiremock::matchers::path;
pub(crate) use wiremock::matchers::query_param;

pub(crate) use wiremock::Mock;
pub(crate) use wiremock::MockServer;
pub(crate) use wiremock::ResponseTemplate;

#[allow(unused_imports)]
pub(crate) use isolate_message::*;
#[allow(unused_imports)]
pub(crate) use retry_once::*;
#[allow(unused_imports)]
pub(crate) use semantics_cross_cutting::*;
#[allow(unused_imports)]
pub(crate) use semantics_edr_notify::*;
#[allow(unused_imports)]
pub(crate) use semantics_push_pull::*;
#[allow(unused_imports)]
pub(crate) use semantics_sync::*;
#[allow(unused_imports)]
pub(crate) use wecom_posts_markdown_and_reads_errcode::*;

mod isolate_message;
mod retry_once;
mod semantics_cross_cutting;
mod semantics_edr_notify;
mod semantics_push_pull;
mod semantics_sync;
mod wecom_posts_markdown_and_reads_errcode;

// ---------------------------------------------------------------------------
// 工单类适配器的构造辅助（`semantics_push_pull` / `semantics_sync` 共用）
// ---------------------------------------------------------------------------

/// Jira 适配器（指向本地假服务端）。
pub(crate) async fn jira_at(server: &MockServer, timeout_secs: u64, retry_cfg: RetryConfig) -> VendorAdapterImpl<Jira> {
    adapter::<Jira>(
        &[("base_url", json!(server.uri())), ("project_key", json!("SEC"))],
        &[("api_token", "jira-token-abcdef"), ("user_email", "soc@example.invalid")],
        timeout_secs,
        retry_cfg,
        circuit(3, 30),
        false,
    )
    .await
}

/// ServiceNow 适配器（自建实例 + 明文 http 显式放行，仅测试内网假服务端）。
pub(crate) async fn servicenow_at(
    server: &MockServer,
    timeout_secs: u64,
    retry_cfg: RetryConfig,
) -> VendorAdapterImpl<ServiceNow> {
    adapter::<ServiceNow>(
        &[("instance_url", json!(server.uri())), ("allow_custom_host", json!(true)), ("insecure_http", json!(true))],
        &[("api_token", "sn-token-abcdef")],
        timeout_secs,
        retry_cfg,
        circuit(3, 30),
        false,
    )
    .await
}

/// 禅道适配器（指向本地假服务端）。
pub(crate) async fn zentao_at(
    server: &MockServer,
    timeout_secs: u64,
    retry_cfg: RetryConfig,
) -> VendorAdapterImpl<Zentao> {
    adapter::<Zentao>(
        &[("base_url", json!(server.uri())), ("product_id", json!(7))],
        &[("api_token", "zentao-token-abcdef")],
        timeout_secs,
        retry_cfg,
        circuit(3, 30),
        false,
    )
    .await
}

/// 回写载荷（显式固定幂等键，便于断言请求头）。
pub(crate) fn push_payload(entity: &str, entity_id: &str, body: Value) -> PushPayload {
    PushPayload {
        entity: entity.to_string(),
        entity_id: entity_id.to_string(),
        body,
        idempotency_key: Some("idem-fixed-1".to_string()),
    }
}

/// 本地案件快照（`updated_at` + 回写状态）。
pub(crate) fn local_snapshot(remote_id: &str, updated_at: &str, state: Value) -> LocalSnapshot {
    LocalSnapshot::new(remote_id, state).with_updated_at(Timestamp::parse_rfc3339(updated_at).expect("合法时间戳"))
}
