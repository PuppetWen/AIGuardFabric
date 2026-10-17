#![forbid(unsafe_code)]
// 测试代码允许 panic/unwrap/expect：workspace lints 对生产代码 `deny`，
// 这里按项目惯例（见 `agf-alicloud/src/lib.rs`）在 `cfg(test)` 下放行（断言失败就该 panic）。
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
//! # agf-adapters — AIGuardFabric 外部系统适配器
//!
//! **一厂商一模块**地落地 `docs/adapter-spec.md` 的统一适配器契约：
//! 通知类（飞书 / 钉钉 / 企业微信 / 邮件 / Webhook / Slack）、工单类（Jira / ServiceNow / 禅道）、
//! 安全平台类（Syslog 转发 / EDR 隔离 / SCIM 身份停用），共 **12 个适配器**。
//!
//! ## 三条不可协商的约束（对齐 spec §2.6）
//!
//! 1. **未配置即降级，不是错误**：`init()` 永远返回 `Ok(())`，未配置时模式为
//!    [`AdapterMode::Unconfigured`]，`send()` 返回明确的配置错误（**绝不假装成功**）；
//! 2. **Mock 模式零网络**：`AGF_MOCK_MODE=1` 或 `config.mock=true` 时全部适配器返回
//!    **确定性** Mock 回执（`remote_id` 由内容哈希派生），不触达任何外部系统；
//! 3. **熔断 + 重试统一包装**：所有真实调用都经 `agf_core::adapter::invoke_with_policy`
//!    （指数退避 + 半开探测），厂商模块无法绕过——见 [`vendor::VendorAdapterImpl::invoke`]。
//!
//! ## 降级行为总表（`AGF_MOCK_MODE` 与配置状态组合）
//!
//! | 模式 | 触发条件 | `send()` | `push()/pull()/sync()` | 健康状态 |
//! |---|---|---|---|---|
//! | `Mocked` | `AGF_MOCK_MODE=1` 或 `config.mock=true` | 确定性 Mock 回执（`mocked=true`） | 已登记语义 ⇒ 确定性降级结果（`mocked=true` + warnings）；未登记/脚手架 ⇒ 如实报错 | `Degraded`（message 含 `AGF_MOCK_MODE`） |
//! | `Unconfigured` | 配置存在但缺凭据 / 必需设置 | `Config` 错误，列出缺项，**不建连不发包** | `Config` 错误 | `Unconfigured` |
//! | `Live`（该语义已登记） | 配置齐全且未开 Mock | 真实 HTTP/UDP/TCP/**SMTP** 往返；5xx/超时按 `RetryConfig` 重试，4xx 不重试 | 真实往返 + 增量去重（`pull`）+ 冲突裁决与决策日志（`sync`） | 按熔断态 `Available`/`Degraded`/`Unavailable` |
//! | `Live`（该语义 `Unsupported`） | 适配器协议不支持该语义 | —— | `Validation` + **不适用原因**（不可重试；**不是** `NotImplemented` 占位） | 同上 |
//! | 已关闭 | `close()` 之后 | `PreconditionFailed` | `PreconditionFailed` | 仍可查（幂等 `close()` 恒 `Ok`） |
//!
//! ## 模块导览
//!
//! - [`contract`]：统一契约（[`contract::VendorAdapter`]）、载荷/回执/元信息、
//!   **四条语义（`send`/`push`/`pull`/`sync`）的契约与能力登记**（[`contract::semantics`]）；
//! - [`settings`]：配置与凭据解析（`SecretLookup` 三级优先级，凭据只以 `SecretString` 承载）；
//! - [`vendor`]：约定实现（[`vendor::VendorSpec`] → [`vendor::VendorAdapterImpl`]）；
//! - [`http`]：真实 HTTP 传输层（超时、状态码分类、响应体截断、id 提取）；
//! - [`registry`]：注册表（查找 / 路由 / 启停 / **失败保持旧配置**的热替换）；
//! - [`health`]：三档健康状态（可用 / 降级 / 不可用 + 最近错误 + 连续失败数）；
//! - [`transport`]：厂商请求编码载体与 URL 脱敏；
//! - [`vendors`]：12 个厂商模块（每个含确定性 Mock 与真实传输实现）+ 按语义拆分的
//!   `itsm_push`/`itsm_pull`/`device_semantics`/`notify_semantics` + [`vendors::capability_matrix`]；
//! - [`mock_mode`]：`AGF_MOCK_MODE` 解析（纯函数，便于离线单测）。
//!
//! ## 与 `agf_core::adapter::Adapter` 的关系
//!
//! 每个适配器**同时**实现 [`contract::VendorAdapter`]（本 crate 的调度面，含 `push`/`pull`/`sync`
//! 三条有类型入参/出参的语义方法）与 `agf_core::adapter::Adapter`
//! （平台契约，`init/health/sync/push/pull/self_check/shutdown`，方向/资源由 `PullRequest` 承载），
//! 因此既能被运行时统一调度，也能被控制台"接入管理"页按统一描述符渲染。
//!
//! ## 真实实现现状（**如实登记**）
//!
//! 12 个适配器**全部具备 `send` 真实传输**（`descriptor().real_implementation == true`）：
//! 飞书 / 钉钉 / 企业微信 / Slack / 通用 Webhook / Jira / ServiceNow / 禅道走真实 HTTP 往返，
//! `email` 走**真实 SMTP 发送**（`lettre` 0.11，真实会话 `EHLO`/`STARTTLS`/`AUTH`/`DATA`），
//! Syslog 转发走真实 UDP/TCP 发包，EDR 隔离指令走真实 HTTP POST，SCIM 身份停用走 HTTP PATCH。
//!
//! `push` / `pull` / `sync` **只在协议支持处实现**，其余**如实登记为 `Unsupported` + 原因**
//! （不是 `NotImplemented` 占位；有单测逐条守住）：
//!
//! | 适配器 | push | pull | sync |
//! |---|---|---|---|
//! | `jira` / `servicenow` / `zentao` | ✅ 工单状态/评论回写 | ✅ 按 `updated_at`/`since` 增量拉取 | ✅ 拉取 + 比对 + 回写（冲突策略可配） |
//! | `edr-isolation` | ✅ 隔离状态回写（受 dry-run 保护） | ✅ 主机清单 / 设备事件增量拉取 | ✅ 本地资产 ↔ EDR 主机对账 |
//! | `iam-scim` | ⛔ 仅案件审批入口可写 | ⛔ 不复制身份目录 | ⛔ 无读取对账 |
//! | `slack` | ✅ `chat.update` / `chat.delete`（需 `bot_token`） | ⛔ 无对账语义（原因见能力矩阵） | ⛔ 同上 |
//! | `feishu` / `dingtalk` / `wecom` / `webhook` / `email` / `syslog-forwarder` | ⛔ 通道只有单向投递 | ⛔ 无读取接口 | ⛔ 无对账语义 |
//!
//! 完整矩阵（含每条 `Unsupported` 的原因与测试证据）由
//! [`vendors::capability_matrix::capability_table_markdown`] 渲染，见 `crates/agf-adapters/CAPABILITY-MATRIX.md`。
//! `email` 另有一条能力边界：SMTP 的 TLS 信任锚是**编译内置的 webpki 根证书集**，
//! 不支持内网自签/私有 CA（无 `smtp_ca_pem`，且**刻意不提供**"跳过证书校验"开关）。

/// 本 crate 版本（编译期取自 `Cargo.toml`，与各适配器 `metadata().version` 一致）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod contract;
pub mod health;
pub mod http;
pub mod mock_mode;
pub mod registry;
pub mod settings;
pub mod transport;
pub mod vendor;
pub mod vendors;

#[cfg(test)]
mod test_support;

pub use contract::{AdapterCategory, AdapterMessage, AdapterMetadata, AdapterReceipt, MessageKind, VendorAdapter};
pub use contract::{
    ConflictPolicy, LocalSnapshot, PullPage, PushOutcome, SETTING_CONFLICT_POLICY, Semantic, SemanticCapability,
    SemanticProfile, SemanticSupport, SyncRequest,
};
pub use health::{AdapterHealthRecord, HealthStatus};
pub use http::HttpResponse;
pub use mock_mode::{MOCK_MODE_ENV, mock_mode_from_env, parse_mock_mode};
pub use registry::{AdapterHandle, AdapterRegistry, BroadcastOutcome, FailureNote, InitReport, SubscriptionRule};
pub use settings::{AdapterMode, AdapterSettings, EnvSecrets, NoSecrets, SecretLookup, StaticSecrets};
pub use transport::{VendorRequest, deterministic_token, redact_url};
pub use vendor::{VendorAdapterImpl, VendorSpec};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_version_is_wired() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn builtin_roster_is_exposed_at_crate_root() {
        assert_eq!(vendors::BUILTIN_NAMES.len(), 12);
        let mut registry = AdapterRegistry::mock_only(agf_core::ids::TenantId::default_tenant())
            .unwrap_or_else(|e| panic!("内置注册不得失败: {e}"));
        assert_eq!(registry.len(), 12);
        assert!(registry.register_builtin().is_err(), "重复注册必须报错");
        // 全部适配器在 Mock 模式下都能给出健康记录
        let records = registry.health_all().await;
        assert_eq!(records.len(), 12);
        assert!(records.iter().all(|r| r.mocked));
    }

    #[test]
    fn reexported_types_are_usable() {
        let msg: AdapterMessage = AdapterMessage::notification("标题", "摘要");
        assert!(msg.meets_severity(None));
        assert!(parse_mock_mode("1"));
        assert!(!MOCK_MODE_ENV.is_empty());
        assert!(redact_url("https://x/y?token=abcdef1234567890").contains("token="));
        assert_eq!(deterministic_token("a", "b"), deterministic_token("a", "b"));
    }
}
