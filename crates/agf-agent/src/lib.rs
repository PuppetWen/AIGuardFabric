#![forbid(unsafe_code)]
// 测试代码允许 panic/unwrap/expect：workspace lints 对生产代码 `deny`，
// 这里按项目惯例（见 `agf-alicloud/src/lib.rs`）在 `cfg(test)` 下放行（断言失败就该 panic）。
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
//! # agf-agent — AIGuardFabric 终端 Agent：AI 资产与凭据采集器
//!
//! 单二进制、**主动出网、零入向端口**：采集本终端的 AI Agent / IDE 插件 / MCP 配置 /
//! 工具与 Skill / 模型端点 / 硬编码密钥 / 进程与监听端口，按
//! **注册 → 快照 → 增量 → 心跳** 的协议上行到 `agf-ingest`。
//!
//! ## 采集项与平台支持（**如实登记**）
//!
//! | 采集项 | 模块 | Windows | Linux / macOS |
//! |---|---|---|---|
//! | 环境变量硬编码密钥 | [`collector::env_secrets`] | ✅ 真实现（临时目录样本 + 进程环境实测） | ✅ 共用实现；Linux 容器已验，macOS 真机待验 |
//! | MCP 配置解析 | [`collector::mcp_config`] | ✅ 真实现（Cursor / Claude Desktop / VS Code / Windsurf / Continue） | ✅ 标准库目录采集与解析；Linux 容器已验，macOS 真机待验收 |
//! | IDE / Agent 插件目录 | [`collector::ide_plugins`] | ✅ 真实现（插件目录名 + `package.json` 指纹 + 宿主目录） | ✅ 共用实现；Linux 容器已验，macOS 真机待验 |
//! | 工具与 Skill | [`collector::skills`] | ✅ 真实现（`SKILL.md` / commands / rules） | ✅ 共用实现；Linux 容器已验，macOS 真机待验 |
//! | 模型端点 | [`collector::model_endpoints`] | ✅ 真实现（配置 + 环境变量） | ✅ 共用实现；Linux 容器已验，macOS 真机待验 |
//! | 进程 | [`collector::processes`] | ✅ 真实现（`sysinfo`，仅上报命中 AI 特征的进程） | ✅ 共用实现；Linux 容器已验，macOS 真机待验 |
//! | 监听端口 | [`collector::ports`] | ✅ 真实现（`netstat -ano`） | Linux 读 `/proc/net`；macOS 仍为接口 |
//!
//! 判定"平台支持级别"的唯一来源是 [`platform::collector_roster`]。Windows 与 Linux 容器均已测试；
//! macOS 七类采集已接线；监听端口依赖本机 `lsof`，真机权限与输出仍需验收。
//!
//! ## 上报协议（serde JSON，[`payload`]）
//!
//! | 载荷 | 结构 | 幂等键 |
//! |---|---|---|
//! | 注册 | [`payload::Envelope`] + 身份字段 | `(agent_id, kind, 载荷)` 的 SHA-256 |
//! | 快照 | [`payload::SnapshotPayload`]（内含 `agf_core::agent::AgentReport` + 终端特有事实） | 同上 |
//! | 心跳 | [`payload::HeartbeatPayload`]（运行时长 / 队列深度 / 采集器状态） | 同上 |
//! | 增量 | [`payload::DiffPayload`]（新增 / 变化 / 移除 / 新凭据命中，超限截断） | 同上 |
//!
//! 快照的 `report` 字段就是服务端 `agf-ingest::decode_agent_report` 与
//! `agf-asset::discovery::DiscoveryBatch::from_agent_report` 消费的类型，**协议天然对齐**。
//!
//! ## 降级行为总表
//!
//! | 情况 | 行为 |
//! |---|---|
//! | `AGF_MOCK_MODE=1` | 客户端**零网络**，只把投递记录进内存（[`client::AgentClient::recorded_deliveries`]）；Mock 回执确定性 |
//! | 未配置 `AGF_AGENT_SERVER_URL` | 不假装成功：载荷入本地队列，回执 `queued = true` 且 `note` 说明原因 |
//! | 真实 HTTP/TLS 上行 | 已接线；配置错误明确拒绝，传输错误保留本地队列并重试 |
//! | 单个采集器失败 | 只记 [`payload::CollectorStatus::error`]，其余采集项照常上报 |
//! | 目录/文件缺失 | 空结果（不是错误）；平台不支持才是 `NotImplemented` |
//! | 队列超容量 | 淘汰最旧条目并累计 `evicted_total`（[`queue`]） |
//! | 显式自更新 | 可信签名、HTTPS 下载、原子安装及持久回滚；真实设备五项验证条件见 [`selfupdate`] |
//!
//! ## 模块导览
//!
//! - [`identity`]：agent id / 租户 / 主机画像 / 幂等键（含本地状态文件）；
//! - [`payload`]：三种上报载荷 + diff 计算（纯函数）；
//! - [`collector`]：七个采集器（一模块一采集面）；
//! - [`queue`]：本地积压队列（上限 / 淘汰 / 落盘续传）；
//! - [`client`]：注册 / 心跳 / 上报 / 退避重试 / 补传；
//! - [`platform`]：平台能力矩阵（真实现 vs 仅接口）；
//! - [`selfupdate`]：验签、HTTPS 下载、显式外部 helper 安装/回滚及本地可复测恢复。

/// 本 crate 版本（编译期取自 `Cargo.toml`，即采集器上报的 `agent_version`）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Mock 模式环境变量名（复用 `agf-core` 常量，避免口径漂移）。
pub const MOCK_MODE_ENV: &str = agf_core::constants::ENV_MOCK_MODE;

/// 判断当前进程是否处于 Mock 模式（`1` / `true` / `yes` / `on`，大小写不敏感）。
#[must_use]
pub fn mock_mode_from_env() -> bool {
    std::env::var(MOCK_MODE_ENV)
        .is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

pub mod audit_anchor;
pub mod client;
pub mod collector;
pub mod identity;
pub mod payload;
pub mod platform;
pub mod process_hook;
pub mod queue;
pub mod selfupdate;

pub use client::{
    AgentClient, AgentTransport, ClientConfig, ClientMode, DeliveryOutcome, EndpointPaths, HttpTransportNotImplemented,
    MockTransport, RecordedDelivery, TlsConfig, TlsEndpoint, TlsErrorKind, TlsHealth, TlsMaterial, TlsMode,
    TlsResponse, TlsTransport, redact_endpoint,
};
pub use collector::{CollectContext, CollectionSnapshot, CollectorOutcome, collect_all};
pub use identity::{AGENT_VERSION, AgentIdentity};
pub use payload::{
    CollectionExtras, DiffPayload, Envelope, HeartbeatPayload, PayloadKind, SnapshotPayload, compute_diff,
};
pub use platform::{CollectorDescriptor, HostPlatform, SupportLevel, collector_roster};
pub use queue::{FlushStats, LocalQueue, QueueConfig, QueueEntry, QueueStats};
pub use selfupdate::{ReleaseAsset, ReleaseManifest, UpdatePlan, parse_version, plan_update, verify_checksum};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_mock_mode_helper() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(MOCK_MODE_ENV, "AGF_MOCK_MODE");
        // 环境变量只读：仅断言函数可用且不 panic（edition 2024 下 set_var 需要 unsafe，测试不写环境）
        let _ = mock_mode_from_env();
    }

    #[tokio::test]
    async fn public_api_is_wired_end_to_end() {
        let identity = AgentIdentity::generate().with_agent_id("api-1");
        let dir = tempfile::tempdir().expect("临时目录");
        let ctx = CollectContext::for_current_user().with_home(dir.path()).without_system_probes();
        let snapshot = collect_all(&identity, &ctx);
        assert_eq!(snapshot.payload.report.collector_id, "api-1");
        assert_eq!(snapshot.statuses.len(), 7);

        let diff = compute_diff(None, &snapshot.payload.report);
        assert!(!diff.base_fingerprint.is_empty());

        let mut client = AgentClient::new(identity, ClientConfig::mock());
        let outcome = client
            .send_snapshot(snapshot.payload.report.clone(), snapshot.payload.extras.clone())
            .await
            .expect("Mock 上报");
        assert!(outcome.mocked);
        assert_eq!(client.recorded_deliveries().len(), 1);

        let roster = collector_roster();
        assert_eq!(roster.len(), 7);
        assert_eq!(HostPlatform::Windows.todo_anchor(), None);
        assert!(verify_checksum(b"x", &selfupdate::sha256_hex(b"x")));
        assert!(parse_version("1.0.0").is_ok());
    }
}
