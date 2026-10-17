//! 防绕过与运行期自检（§4.3 防绕过）。
//!
//! # 三个不变量
//!
//! 1. **代理不可被被管 Agent 关闭**。运行时代理与被管 Agent 常在同一台机器上，
//!    因此"代理还活着吗"必须由**外部**观测：[`HeartbeatMonitor`] 接收被管端点/代理的
//!    心跳，连续丢失达阈值即产出 [`HeartbeatAlert`]，[`SelfCheck`] 据此判 FAIL。
//! 2. **策略签名校验**。见 [`crate::signature`]：`Enforce` 模式下未签名策略不装载，
//!    本模块把"是否存在未签名策略 / 是否处于 Warn 模式"暴露成自检项。
//! 3. **策略不能被静默绕过**。若"所有策略都是 dry-run""三个拦截点没配齐""黑名单为空"，
//!    表面看平台在运行，实际等于没有防护——[`SelfCheck`] 正是为发现这种状态而存在，
//!    其结论直接驱动控制台「运行时防护」页的红/黄/绿状态。
//!
//! # 与 `agf_core` 的关系
//!
//! 本模块不新增领域模型，只做**运行时观测**：心跳表、自检项、报告。
//! [`SelfCheck`] 的输入是运行时的共享引用（策略引擎、黑名单、审计链、配额、审批），
//! 因此可以在**完全离线**的环境下产出真实的"体检报告"（离线演示的核心卖点）。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Mutex;

pub(crate) use agf_core::enums::InterceptPoint;
pub(crate) use agf_core::enums::PolicyAction;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::audit::InterceptionAuditLog;

pub(crate) use crate::blocklist::Blocklist;

pub(crate) use crate::engine::EngineConfig;

pub(crate) use crate::policy::PolicyEngine;
pub(crate) use crate::policy::SignatureMode;

pub(crate) use crate::quota::QuotaService;

#[allow(unused_imports)]
pub use quick_report::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;

/// 单个自检项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardItem {
    /// 项名（稳定 key，前端 i18n 依赖）。
    pub key: String,
    /// 中文显示名。
    pub label: String,
    /// 是否通过。
    pub passed: bool,
    /// 严重程度（`fail` 项的必要性：`critical` 表示"等于没有防护"）。
    pub critical: bool,
    /// 结论说明（通过时说明证据，失败时说明原因与建议动作）。
    pub reason: String,
}

/// 运行期自检报告（控制台「运行时防护」页数据源）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardReport {
    /// 总体是否健康（无关键失败项）。
    pub healthy: bool,
    /// 全部自检项。
    pub items: Vec<GuardItem>,
    /// 通过项数。
    pub passed: usize,
    /// 失败项数（含非关键）。
    pub failed: usize,
    /// 关键失败项数。
    pub critical_failures: usize,
    /// 心跳告警。
    pub heartbeat_alerts: Vec<HeartbeatAlert>,
    /// 当前生效策略数。
    pub policy_count: usize,
    /// 当前黑名单规则数。
    pub blocklist_rule_count: usize,
    /// 拦截审计链累计条数。
    pub audit_entries: u64,
    /// 报告归属租户（[`SelfCheck`] 构造时给出；直接调 [`GuardReport::build`] 时为 `None`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<TenantId>,
    /// 生成时间。
    pub generated_at: Timestamp,
}

/// 被管端点（Agent 或代理实例）的心跳状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatState {
    /// 端点 id。
    pub endpoint_id: String,
    /// 端点类型（`agent` / `proxy`）。
    pub kind: String,
    /// 期望心跳间隔（秒）——由端点注册时声明。
    pub interval_secs: i64,
    /// 最近一次心跳时间。
    pub last_seen: Timestamp,
    /// 连续丢失次数。
    pub missed: u32,
    /// 是否已被判定为失联。
    pub alerted: bool,
}

/// 心跳丢失告警。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatAlert {
    /// 端点 id。
    pub endpoint_id: String,
    /// 端点类型。
    pub kind: String,
    /// 连续丢失次数。
    pub missed: u32,
    /// 最近一次心跳时间。
    pub last_seen: Timestamp,
    /// 静默时长（秒）。
    pub silence_secs: i64,
    /// 建议动作（中文，控制台直接展示）。
    pub suggestion: String,
}

/// 被管端点注册项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedEndpoint {
    /// 端点 id。
    pub endpoint_id: String,
    /// 端点类型。
    pub kind: String,
    /// 期望心跳间隔（秒）。
    pub interval_secs: i64,
    /// 达多少次丢失才告警（默认 3）。
    pub alert_after: u32,
}

/// 心跳监控器。
///
/// 语义：端点在 `last_seen + interval_secs` 之后未再次心跳，即记 1 次丢失；
/// 连续丢失达 `alert_after`（默认 **3**）次即产出告警。
///
/// **为什么是"连续丢失"而不是"超时即告警"**：网络抖动与 GC 停顿会让单次心跳偶然迟到，
/// 三次容忍在"及时发现问题"与"不误报"之间取了工程平衡（与 §4.3 的 N 次丢失要求一致）。
#[derive(Debug, Default)]
pub struct HeartbeatMonitor {
    /// 端点注册表与状态。
    endpoints: Mutex<BTreeMap<String, (ManagedEndpoint, HeartbeatState)>>,
    /// 已消费的告警端点（避免重复上报）。
    reported: Mutex<BTreeMap<String, Timestamp>>,
}

/// 运行期自检项 key 常量（前端 i18n 与告警规则依赖，**禁止随意变更**）。
pub mod keys {
    /// 策略签名校验状态。
    pub const POLICY_SIGNATURE: &str = "policy.signature";
    /// 是否存在未签名策略。
    pub const POLICY_UNSIGNED: &str = "policy.unsigned";
    /// 是否强制签名（非 Warn/Disabled）。
    pub const POLICY_SIGNATURE_MODE: &str = "policy.signature-mode";
    /// 策略签名是否使用开发默认密钥。
    pub const POLICY_DEV_KEY: &str = "policy.dev-key";
    /// 是否全部策略都是 dry-run。
    pub const POLICY_ALL_DRY_RUN: &str = "policy.all-dry-run";
    /// 三个拦截点是否都配置。
    pub const INTERCEPT_POINTS: &str = "intercept.points";
    /// 黑名单是否非空。
    pub const BLOCKLIST_NON_EMPTY: &str = "blocklist.non-empty";
    /// 是否至少有阻断类策略。
    pub const POLICY_HAS_BLOCKING: &str = "policy.has-blocking";
    /// 审计链是否校验通过。
    pub const AUDIT_CHAIN: &str = "audit.chain";
    /// 审计链是否完整（未发生缓冲滚出）。
    pub const AUDIT_COMPLETE: &str = "audit.complete";
    /// 配额服务是否处于降级。
    pub const QUOTA_DEGRADED: &str = "quota.degraded";
    /// 审批服务是否可用。
    pub const APPROVAL_AVAILABLE: &str = "approval.available";
    /// 被管端点心跳。
    pub const HEARTBEAT: &str = "guard.heartbeat";
    /// 是否存在被管端点。
    pub const HEARTBEAT_ENROLLED: &str = "guard.heartbeat-enrolled";
    /// 策略后端错误处理模式。
    pub const EVAL_ERROR_MODE: &str = "policy.eval-error-mode";
}

/// 运行期自检器。
///
/// 构造时只持有**共享引用**，因此可在任意时刻对运行中的引擎做"体检"。
#[derive(Debug)]
pub struct SelfCheck<'a> {
    /// 策略引擎。
    engine: &'a PolicyEngine,
    /// 黑名单。
    blocklist: &'a Blocklist,
    /// 拦截审计链。
    audit: &'a InterceptionAuditLog,
    /// 配额服务（可缺省）。
    quotas: Option<&'a QuotaService>,
    /// 审批存储（可缺省）。
    approvals: Option<&'a dyn crate::approval::ApprovalStore>,
    /// 心跳监控。
    heartbeats: Option<&'a HeartbeatMonitor>,
    /// 引擎配置（拦截点开关）。
    config: &'a EngineConfig,
    /// 租户。
    tenant_id: TenantId,
}

/// 便捷：拦截点中文名（控制台）。
#[must_use]
pub const fn intercept_point_label(point: InterceptPoint) -> &'static str {
    match point {
        InterceptPoint::McpProxy => "MCP 代理（stdio/SSE/HTTP）",
        InterceptPoint::AiGateway => "AI 网关南北向",
        InterceptPoint::ProcessHook => "eBPF/进程 Hook 东西向",
        InterceptPoint::Collector => "南向采集网关",
    }
}

mod impl_guard_item;
mod impl_unknown;
mod quick_report;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_2;
