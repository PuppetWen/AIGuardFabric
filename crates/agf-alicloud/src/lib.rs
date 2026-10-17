#![forbid(unsafe_code)]
// 测试代码允许 panic/unwrap/expect：workspace lints 对生产代码 `deny`，
// 这里按项目惯例在 `cfg(test)` 下放行（断言失败就该 panic）。
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
//! # agf-alicloud — AIGuardFabric 阿里云适配器：AgentTeams + 五底座服务（§5）
//!
//! 本 crate 实现 §5.2 表列出的**六个服务**的统一适配：
//! CMS（云监控）、APIG（AI 网关）、MSE（微服务引擎）、Privatelink（私网链接）、
//! SchedulerX3（分布式任务调度）、AgentTeams（多智能体治理平台）。
//!
//! ## 三条不可协商的约束
//!
//! 1. **无凭据 / Mock 模式下绝不发起真实 HTTP**。
//!    所有真实调用都必须先经过 [`http::RpcClient::live`] 这道闸门；
//!    `live` 在 [`AdapterMode::Mocked`] 或缺少 AK/SK 时返回错误，
//!    因此不存在"忘了判断 mock 就打网络"的路径。
//! 2. **未配置 = 降级，不是错误**。`init` 永远返回 `Ok(())`，
//!    未配置时 [`Adapter::health`] 返回 [`HealthState::Unconfigured`]，
//!    由 `Mock*Adapter`（[`mock`] 模块）接管，平台永远可启动。
//! 3. **Mock 与真实实现接口签名完全一致**。每个服务定义 `*Api` trait，
//!    真实适配器与 `Mock*Adapter` 同时实现它；差异只体现在
//!    `AdapterMode` 字段上（`live()` 会拒绝 Mock 模式），
//!    因此测试无需网络即可覆盖全部 `sync` / `push` / `pull` 语义。
//!
//! ## 降级行为表（六个服务，`AdapterDescriptor::degradation` 的实现依据）
//!
//! | 服务 | 适配器注册名 | 未配置 / 断网时的降级行为 | Mock 实现位置 |
//! |---|---|---|---|
//! | CMS | `alicloud-cms` | 不上报自定义事件与指标；告警订阅回退为 ingest 侧本地轮询；不影响主流程与已入库数据 | `crate::mock::MockCmsAdapter` |
//! | APIG | `alicloud-apig` | 不下发限流 / Token 配额 / 内容安全 / 模型路由策略，agf-aigw 继续用本地策略兜底并记告警；访问日志改用本地采集 | `crate::mock::MockApigAdapter` |
//! | MSE | `alicloud-mse` | 停止 Nacos 服务清单同步与配置热更新，资产发现回退为网段扫描 + 终端上报；已有资产标记 `stale` 但**不删除** | `crate::mock::MockMseAdapter` |
//! | Privatelink | `alicloud-privatelink` | 私网探测不可用，连通性判定降级为"未知"而非"不通"；采集器继续缓存本地数据并在恢复后补传 | `crate::mock::MockPrivatelinkAdapter` |
//! | SchedulerX3 | `alicloud-schedulerx3` | 全部云任务回退本地 tokio-cron（[`ScheduleBackend::fallback`]）；无云环境零配置可用 | `crate::mock::MockSchedulerX3Adapter` |
//! | AgentTeams | `alicloud-agentteams` | 台账只读：停止双向同步与配额下发，平台侧配置继续生效（**平台为准**）；审计事件缺失由网关侧流量审计补位 | `crate::mock::MockAgentTeamsAdapter` |
//!
//! ## 模块导览
//!
//! - [`signer`]：阿里云 RPC 风格（HMAC-SHA1）与 V3 风格（ACS3-HMAC-SHA256）签名；
//! - [`credential`]：凭据解析（RAM Role / STS / AssumeRole / 长期 AK 风险登记）；
//! - [`endpoint`]：公网 + PrivateLink 私网 endpoint 解析与地域映射；
//! - [`http`]：RPC 客户端（构建 → 签名 → 发送 → 解析 → 错误映射），Mock 模式下闸门关闭；
//! - [`cms`] / [`apig`] / [`mse`] / [`privatelink`] / [`schedulerx3`] / [`agentteams`]：六服务适配器；
//! - [`mock`]：六服务 + AgentTeams 的确定性 Mock 实现；
//! - [`selfcheck`]：云环境自检（连通性 / 最小权限 / 配额余量）与 Markdown 报表；
//! - [`registry`]：按配置构建全部适配器并输出控制台描述符；
//! - [`deadletter`]：离线缓存 + 死信队列 + 恢复重放。
//!
//! 实现进度见 `docs/roadmap.md` 里程碑 M8；尚未落地的部分（V3 与真实 STS 的联网校验）
//! 统一登记在 `docs/pending-verification.md`，代码中以 `TODO(pending-verification):` 标注。

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Mock 模式环境变量名（健康信息里会显式回显它，便于排障）。
pub const MOCK_MODE_ENV: &str = "AGF_MOCK_MODE";

/// 判断当前进程是否处于 Mock 模式。
///
/// 接受 `1` / `true` / `yes` / `on`（大小写不敏感）。
#[must_use]
pub fn mock_mode_from_env() -> bool {
    std::env::var(MOCK_MODE_ENV).is_ok_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        matches!(v.as_str(), "1" | "true" | "yes" | "on")
    })
}

/// 适配器运行模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterMode {
    /// 未配置（无凭据且未显式开启 Mock）。
    Unconfigured,
    /// Mock 模式（确定性 fixtures，**绝不发起网络请求**）。
    Mocked,
    /// 真实模式（需要凭据，走签名 HTTP）。
    Live,
}

impl AdapterMode {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unconfigured => "unconfigured",
            Self::Mocked => "mocked",
            Self::Live => "live",
        }
    }

    /// 是否 Mock。
    #[must_use]
    pub const fn is_mock(&self) -> bool {
        matches!(self, Self::Mocked)
    }

    /// 是否可发起真实调用。
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }
}

pub mod agentteams;
pub mod apig;
pub mod cms;
pub mod credential;
pub mod deadletter;
pub mod endpoint;
pub mod http;
pub mod mock;
pub mod mse;
pub mod openapi;
pub mod privatelink;
pub mod registry;
pub mod schedulerx3;
pub mod selfcheck;
pub mod signer;

#[cfg(test)]
mod test_support;
