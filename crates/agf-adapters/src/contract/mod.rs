//! 统一适配器契约（`agf-adapters` 侧的实现面）。
//!
//! 本模块定义 [`VendorAdapter`]：它是 `docs/adapter-spec.md` §1 的统一契约
//! （`agf_core::adapter::Adapter`）在本 crate 的**落地形态**，
//! 由 [`crate::vendor::VendorAdapterImpl`] 统一实现，具体厂商只需实现
//! [`VendorSpec`]（元信息 + 载荷编码 + 真实调用）。
//!
//! ## 与 `agf_core::adapter::Adapter` 的关系
//!
//! | 能力 | `agf_core::adapter::Adapter` | [`VendorAdapter`] |
//! |---|---|---|
//! | 元信息 / 描述符 | `descriptor()` | `metadata()` + `descriptor()` |
//! | 健康检查 | `health()` | `health_check()`（含最近错误与连续失败数） |
//! | 事件/通知发送 | `push()`（实体推送语义） | `send()`（事件/通知语义，本 crate 的主路径） |
//! | 关闭 | `shutdown()` | `close()`（幂等） |
//! | 配置热替换 | `init()` | `prepare()` + `commit()`（两段式，保证失败保持旧配置） |
//!
//! 两者**同时实现**：注册表按 [`VendorAdapter`] 调度，控制台/上层按
//! `agf_core::adapter::Adapter` 消费，签名差异由 [`crate::vendor`] 收敛。
//!
//! ## 未配置时的降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | `AGF_MOCK_MODE=1` 或 `config.mock=true` | `send()` 返回**确定性 Mock 回执**（`mocked=true`），绝不发起真实调用 |
//! | 配置存在但缺少必需凭据 | 模式为 `Unconfigured`；`send()` 返回 `Config` 错误（带缺项清单），**不建连、不假装成功** |
//! | 配置齐全且已实现真实传输 | 模式为 `Live`；`send()` 真实发包（HTTP/UDP/TCP），失败经熔断 + 重试后如实报错 |
//! | 配置齐全但真实传输未实现 | 模式为 `Live`；`send()` 返回 `NotImplemented`（**当前无内置适配器命中此档**：12 个适配器均已实现真实传输，该分支保留给新增适配器的脚手架阶段） |
//! | 配置存在但非法 | `init()` 返回 `DomainError::Config`，**旧配置保持不变** |
//!
//! ## 四条语义（`send` / `push` / `pull` / `sync`）
//!
//! | 语义 | 方向 | 入参 → 出参 | 远端对象 id |
//! |---|---|---|---|
//! | [`VendorAdapter::send`] | 平台 → 外部（单向投递） | [`AdapterMessage`] → [`AdapterReceipt`] | **产生** `remote_id` |
//! | [`VendorAdapter::push`] | 平台 → 外部（状态变更回写） | `PushPayload` → [`PushOutcome`] | **必须已存在**（取自 `send` 回执） |
//! | [`VendorAdapter::pull`] | 外部 → 平台（增量读取） | `PullRequest` → `PullResponse` | 逐条读取 |
//! | [`VendorAdapter::sync`] | 双向对账（`pull` + 比对 + `push`） | [`SyncRequest`] → `SyncOutcome` | 双方都有 |
//!
//! 完整契约、`Unsupported` 的判定标准与能力矩阵见 [`crate::contract::semantics`]；
//! **语义不适用**（如通知渠道没有读取接口）登记为 [`SemanticSupport::Unsupported`] 并给出原因，
//! 运行时返回不可重试的 `Validation`，**不留 `NotImplemented` 占位**。

pub(crate) use std::collections::BTreeMap;

pub(crate) use agf_core::adapter::AdapterCapability;
pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;
pub(crate) use agf_core::adapter::AdapterHealth;
pub(crate) use agf_core::adapter::PullRequest;
pub(crate) use agf_core::adapter::PullResponse;
pub(crate) use agf_core::adapter::PushPayload;
pub(crate) use agf_core::adapter::SyncOutcome;

pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use crate::health::AdapterHealthRecord;

pub(crate) use crate::settings::AdapterMode;
pub(crate) use crate::settings::AdapterSettings;
pub(crate) use crate::settings::SecretLookup;

pub(crate) use crate::transport::VendorRequest;

#[allow(unused_imports)]
pub use camel::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 适配器分类（决定 `AdapterDescriptor::category`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterCategory {
    /// 通知渠道（飞书 / 钉钉 / 企业微信 / 邮件 / Webhook / Slack）。
    Notification,
    /// 工单 / ITSM（Jira / ServiceNow / 禅道）。
    Itsm,
    /// 安全设备与平台（Syslog 转发 / EDR 隔离指令）。
    SecurityPlatform,
}

/// 载荷种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageKind {
    /// 通知（面向人的告警/升级路由）。
    Notification,
    /// 事件（面向系统的机读事件，如资产变更、策略下发）。
    Event,
}

/// 统一事件/通知载荷（[`VendorAdapter::send`] 的入参）。
///
/// 终端与服务端都只依赖本结构，厂商差异全部收敛在 [`VendorSpec::encode`]。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AdapterMessage {
    /// 种类。
    pub kind: MessageKind,
    /// 事件类型（点分命名，如 `ai.asset.discovered`、`notify.alert`）。
    pub event_type: String,
    /// 标题。
    pub title: String,
    /// 摘要（纯文本，厂商侧渲染用）。
    pub summary: String,
    /// 严重等级。
    pub severity: Severity,
    /// 关联资产（可选，用于路由标签与工单字段）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    /// 结构化载荷体（厂商侧按需透传）。
    #[serde(default)]
    pub body: serde_json::Value,
    /// 幂等键（远端据此去重；缺省由内容派生，见 [`AdapterMessage::derive_key`]）。
    pub idempotency_key: String,
    /// 发生时间。
    pub occurred_at: Timestamp,
    /// 标签（路由与厂商字段映射用）。
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// 适配器元信息（厂商 / 版本 / 能力清单 / 是否需要网络）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdapterMetadata {
    /// 注册名（kebab-case，如 `feishu`、`servicenow`）。
    pub name: String,
    /// 显示名。
    pub display_name: String,
    /// 厂商。
    pub vendor: String,
    /// 本 crate 中该适配器实现的版本（取自 `CARGO_PKG_VERSION`）。
    pub version: String,
    /// 分类。
    pub category: AdapterCategory,
    /// 能力清单。
    pub capabilities: Vec<AdapterCapability>,
    /// 是否需要网络（`requires_network`）。
    pub requires_network: bool,
    /// 必需凭据键。
    pub required_secrets: Vec<String>,
    /// 可选凭据键。
    pub optional_secrets: Vec<String>,
    /// endpoint 设置键（非敏感；Webhook 类适配器的 endpoint 本身是凭据，故为 `None`）。
    pub endpoint_key: Option<String>,
    /// **未配置时的降级行为**（`AdapterDescriptor::degradation` 的来源，非空）。
    pub degradation: String,
    /// Mock 实现位置（`AdapterDescriptor::mock_location` 的来源，非空）。
    pub mock_location: String,
    /// 文档锚点。
    pub doc_anchor: String,
    /// 是否已有真实传输实现（**如实登记**：11 个内置适配器**全部**为 `true`，含 `email` 的真实 SMTP 投递）。
    pub real_transport: bool,
    /// `push` / `pull` / `sync` 三条语义的能力声明（**如实登记**：不适用必须给原因）。
    ///
    /// 未显式声明时为 [`SemanticProfile::undeclared`]（不声称任何能力）；
    /// 能力矩阵（[`crate::vendors::capability_matrix`]）以本字段为唯一真源。
    pub semantics: SemanticProfile,
}

/// 适配器回执（`send` 的产出）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdapterReceipt {
    /// 适配器名。
    pub adapter: String,
    /// 是否被接受。
    pub accepted: bool,
    /// 是否 Mock。
    pub mocked: bool,
    /// 远端消息 id（Mock 下为确定性派生值）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,
    /// 实际尝试次数（含首次）。
    pub attempts: u32,
    /// 耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 来源（真实 endpoint / `mock://<name>`，排障用；凭据已脱敏）。
    pub origin: String,
    /// 完成时间。
    pub delivered_at: Timestamp,
}

/// 厂商适配器契约（`agf-adapters` 的对外统一面）。
///
/// `prepare` / `commit` 的两段式设计是"配置热替换失败保持旧配置"的实现基础：
/// `prepare` 只做**纯校验与构造**（不做 I/O、不改自身状态），
/// `commit` 是**不可失败**的落库动作。
#[async_trait]
pub trait VendorAdapter: Send + Sync {
    /// 注册名。
    fn name(&self) -> &str;

    /// 元信息。
    fn metadata(&self) -> AdapterMetadata;

    /// `agf-core` 契约描述符。
    fn descriptor(&self) -> AdapterDescriptor;

    /// 当前运行模式。
    fn mode(&self) -> AdapterMode;

    /// 构造候选配置（纯函数：失败即返回 Err，**不修改自身**）。
    ///
    /// # Errors
    /// 配置存在但非法（URL 非法、超时越界、凭据格式非法）时返回 `DomainError::Config`。
    fn prepare(&self, config: &AdapterConfig, lookup: &dyn SecretLookup) -> DomainResult<AdapterSettings>;

    /// 提交候选配置（不可失败）。
    fn commit(&mut self, settings: AdapterSettings);

    /// 强制进入 Mock 模式（`AGF_MOCK_MODE=1` / [`crate::registry::AdapterRegistry::mock_only`] 使用）。
    ///
    /// 语义：把"环境级 Mock"固化到适配器内部，后续 `commit` 也保持 Mock
    /// （**环境变量优先于 `config.mock`**，与 `docs/adapter-spec.md` §4.2 一致）。
    fn force_mock(&mut self);

    /// 初始化（`mock_env` 由调用方显式传入，保证测试可确定性地绕过环境变量）。
    ///
    /// # Errors
    /// 配置存在但非法时返回错误；**未配置不返回错误**（降级为 `Unconfigured`）。
    async fn init_with(
        &mut self,
        config: &AdapterConfig,
        lookup: &dyn SecretLookup,
        mock_env: bool,
    ) -> DomainResult<()>;

    /// 健康检查（含最近错误与连续失败数；网络失败映射为状态而非 `Err`）。
    ///
    /// # Errors
    /// 仅当探测本身无法执行时返回错误。
    async fn health_check(&self) -> DomainResult<AdapterHealthRecord>;

    /// 发送事件/通知（**单向投递**：通知 / 建单 / 隔离下发）。
    ///
    /// 本方法是**唯一创建远端对象**的入口：返回的 [`AdapterReceipt::remote_id`] 就是后续
    /// [`Self::push`] 定位对象所需的 `entity_id`（见 [`crate::contract::semantics`] 的不变式 1）。
    ///
    /// # Errors
    /// Mock 模式恒 `Ok`；未配置返回明确的 `Config`（列出缺项）；`Live` 模式真实发包后
    /// 如实返回上游错误（`Validation`/`DependencyUnavailable`/`Timeout` 等），**绝不假装成功**。
    async fn send(&mut self, msg: &AdapterMessage) -> DomainResult<AdapterReceipt>;

    /// 状态回写（平台 → 外部**已存在**的对象）。
    ///
    /// 语义：把案件/处置结果写回外部系统（工单状态与评论、群消息更新与撤回、
    /// EDR 隔离状态更新）。`payload.entity_id` **必须**是 [`Self::send`] 曾返回的
    /// `remote_id`；缺失一律 `Validation` 拒绝（绝不对模糊目标回写）。
    ///
    /// 未登记该语义（[`SemanticSupport::Unsupported`]）时返回**不可重试**的
    /// `Validation`（原因来自能力登记），不做任何网络 I/O。
    ///
    /// # Errors
    /// Mock 返回确定性回执；未配置返回 `Config`；不适用返回 `Validation`（带原因）；
    /// `Live` 返回上游错误（5xx/超时可重试、4xx 不重试）。
    async fn push(&self, payload: &PushPayload) -> DomainResult<PushOutcome>;

    /// 增量读取（外部 → 平台）。
    ///
    /// 语义：拉取外部对象的当前状态（工单/评论、设备事件与主机清单）。
    /// `req.cursor` 为空表示首轮全量，返回的 `next_cursor` 供下一轮使用；
    /// 同一实例内按 `resource` 去重（[`crate::vendor::IncrementalWindow`]），
    /// 上游分页边界重复返回的同一条目不会二次计入。
    ///
    /// # Errors
    /// 未登记该语义时返回不可重试的 `Validation`（带原因）；未配置返回 `Config`；`Live` 返回上游错误。
    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse>;

    /// 双向对账（`pull` → 与本地快照比对 → 需要时 `push`）。
    ///
    /// 冲突由 [`SyncRequest::conflict_policy`]（缺省取设置项
    /// [`SETTING_CONFLICT_POLICY`]，默认 [`ConflictPolicy::ExternalWins`]）裁决，
    /// 每条裁决写入 [`SyncOutcome::warnings`]（决策日志）并经 `tracing` 输出。
    ///
    /// # Errors
    /// 未登记 `sync` 语义时返回不可重试的 `Validation`（带原因）；未配置返回 `Config`；`Live` 返回上游错误。
    async fn sync(&self, req: &SyncRequest) -> DomainResult<SyncOutcome>;

    /// 三条语义的能力登记（能力矩阵与运行时判定共用的唯一真源）。
    fn semantics(&self) -> SemanticProfile {
        self.metadata().semantics
    }

    /// 关闭（幂等）。
    ///
    /// # Errors
    /// 关闭过程中的错误。
    async fn close(&mut self) -> DomainResult<()>;

    /// 该适配器是否订阅该载荷（路由用）。
    fn subscribes(&self, msg: &AdapterMessage) -> bool;

    /// 编码为厂商请求（排障与断言用；不做网络）。
    ///
    /// # Errors
    /// 载荷缺少厂商必需字段时返回 `DomainError::Validation`/`Config`。
    fn encode(&self, msg: &AdapterMessage) -> DomainResult<VendorRequest>;

    /// `agf-core::adapter::Adapter::health` 的桥接实现（默认由 `health_check` 转换）。
    ///
    /// # Errors
    /// 同 `health_check`。
    async fn health(&self) -> DomainResult<AdapterHealth> {
        let record = self.health_check().await?;
        Ok(record.to_core_health(self.metadata()))
    }
}

mod camel;
mod impl_adapter_category;
mod semantic_capability;
mod semantics;
mod sync_types;
#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use semantic_capability::*;
#[allow(unused_imports)]
pub use semantics::*;
#[allow(unused_imports)]
pub use sync_types::*;
