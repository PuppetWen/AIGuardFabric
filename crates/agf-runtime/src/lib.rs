//! # agf-runtime — AIGuardFabric 运行时防御（§4.3）
//!
//! 本 crate 是平台的**在线拦截面**：MCP 代理（stdio/SSE/HTTP）、AI 网关南北向、
//! eBPF/进程 Hook 东西向三个拦截点共用同一套「策略引擎 + 配额 + 黑名单 + 审批 + 审计 + 自检」。
//!
//! ## 模块职责
//!
//! | 模块 | 职责 |
//! |---|---|
//! | [`policy`] | [`PolicyEngine`]：从 [`agf_core::policy::Policy`] 装载策略，按优先级评估出决策 |
//! | [`rego`] | Rego 后端（`regorus`）：编译 + 输入 JSON + 查询 `data.agf.*` 约定 |
//! | [`cel`] | CEL 后端（`cel-interpreter`）：表达式返回 map/字符串的约定 |
//! | [`signature`] | 策略签名（HMAC-SHA256 over `Policy::compute_hash`）与密钥轮换 |
//! | [`quota`] | 三级配额（租户 → Agent → 会话）强制，Redis 原子计数 + 内存兜底 |
//! | [`blocklist`] | 命令/域名/路径/工具/哈希黑名单，内置默认规则 + 热重载 |
//! | [`mcp_proxy`] | MCP 代理拦截逻辑、JSON-RPC 帧处理、会话状态机 |
//! | [`approval`] | 人工审批流程（TTL、单次消费、过期） |
//! | [`audit`] | 拦截审计记录（哈希链防篡改） |
//! | [`guard`] | 防绕过：心跳监控 + 运行期自检（控制台「运行时防护」页数据源） |
//! | [`engine`] | [`RuntimeEngine`] 编排器：对外唯一入口 |
//!
//! ## 评估与组合规则（**[`policy`] 中详述**）
//!
//! 1. 策略按 `priority` **升序**排序（数值小者先评估，deny 类应配高优先级即小数值）；
//! 2. 取第一条 `applies_to()` 成立**且**其条件命中的策略作为胜出者；
//! 3. `Deny` / `Isolate` **短路**：命中即定案，不再评估后续策略；
//! 4. 无策略命中 ⇒ 默认 `Allow`，原因固定为「无策略命中」；
//! 5. `dry_run` 策略照常产出 `PolicyDecision`，但 [`agf_core::policy::PolicyDecision::is_blocking`]
//!    为 `false`（只记录不拦截）。
//!
//! ## 降级行为
//!
//! 运行时防御是**在线路径**，任何外部依赖不可用时必须给出确定行为，禁止"静默放行"。
//!
//! | 依赖 / 能力 | 不可用时的行为 | 可配置 | 失败方向 |
//! |---|---|---|---|
//! | Redis（配额计数） | 该维度按 [`quota::FailMode`] 判定：`Deny` 维度**拒绝**（fail-closed），`Audit`/`Quota`/`Throttle`/`Degrade` 维度**放行并标记 `degraded`**（fail-open，避免计量依赖拖垮业务） | `QuotaService::with_fail_mode` | 按维度 |
//! | Redis 完全缺失 | 回退 [`quota::InMemoryQuotaStore`]（单进程近似计数，控制台标注 `degraded`） | `QuotaService::in_memory` | 可用 |
//! | PostgreSQL | 策略改由内存装载（[`PolicyEngine::from_policies`] / [`PolicyEngine::replace`]），审计落内存哈希链 | `RuntimeEngine::in_memory` | 可用（离线演示） |
//! | Rego 后端编译失败 | **装载期**即报 [`agf_core::error::DomainError::Parse`]（含策略名与源码行），坏策略不进入热路径 | 无 | fail-closed |
//! | CEL 后端编译/求值失败 | 求值期返回 [`agf_core::error::DomainError::Parse`]，由调用方决定放行或拒绝；[`engine::RuntimeEngine::evaluate`] 默认**拒绝**（fail-closed） | `PolicyEngine::with_eval_error_mode` | 可配置 |
//! | 策略签名缺失/非法 | `SignatureMode::Enforce`（生产默认）拒绝装载该策略；`SignatureMode::Warn`（开发）装载但在自检中记 **FAIL** | `PolicyEngine::with_signature_mode` | fail-closed |
//! | 审批服务不可用 | 视为**审批未通过**：请求被拒绝并提示"审批服务不可用"，绝不静默放行 | 无 | fail-closed |
//! | 心跳丢失 | 连续丢失达阈值即产出 `HeartbeatAlert`（默认 3 次），`SelfCheck` 记 **FAIL** 并建议挂起 Agent | `HeartbeatMonitor::with_alert_after` | 告警 |
//! | `agf-storage` 数据库审批表缺失 | 审批走内存实现（见 [`approval`] 的 TODO 锚点与迁移建议），行为一致但重启丢失 | `RuntimeEngine::in_memory` | 可用 |

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
// 测试代码允许 `panic!`（含测试支撑宏展开）：workspace lints 对非测试代码
// `deny(clippy::panic)`，这里按 crate 惯例放行测试分支。
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

pub mod approval;
pub mod audit;
pub mod blocklist;
pub mod cel;
pub mod engine;
pub mod guard;
pub mod mcp_proxy;
pub mod policy;
pub mod quota;
pub mod rego;
pub mod signature;

/// 测试支撑（仅 `cfg(test)` 编译；跨模块共用样例数据与断言宏）。
#[cfg(test)]
pub(crate) mod testkit;

pub use approval::{ApprovalError, ApprovalRecord, ApprovalStore, Decision, InMemoryApprovalStore};
pub use audit::{InterceptionAuditLog, InterceptionRecord, InterceptionVerdict};
pub use blocklist::{Blocklist, BlocklistStats, RuleAction, RuleHit, RuleKind, RuleRule};
pub use engine::{EngineConfig, RuntimeEngine};
pub use guard::{GuardItem, GuardReport, HeartbeatAlert, HeartbeatMonitor, HeartbeatState, ManagedEndpoint, SelfCheck};
pub use mcp_proxy::{InterceptOutcome, JsonRpcFrame, JsonRpcParseError, McpProxy, McpProxySession, SessionStats};
pub use policy::{EvalErrorMode, PolicyEngine, PolicyMatch, SignatureMode};
pub use quota::{
    FailMode, InMemoryQuotaStore, QuotaCheckOutcome, QuotaService, QuotaSnapshot, QuotaStore, QuotaStoreError,
    RedisQuotaStore, SnapshotEntry,
};
pub use signature::{PolicySignatureState, PolicySigner, sign_policy, verify_policy};

/// 运行时拦截点枚举别名（便于上层少写一层路径）。
pub use agf_core::enums::{InterceptPoint, PolicyAction};

/// crate 版本（编译期取自 Cargo 包版本）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 无策略命中时的默认放行原因（**契约字符串**，API 与前端断言依赖，禁止随意变更）。
pub const NO_POLICY_MATCHED_REASON: &str = "无策略命中";

/// 默认策略包名（Rego 契约）。
pub const REGO_PACKAGE: &str = "agf";

/// 默认策略包路径前缀（Rego 契约：`data.agf.*`）。
pub const REGO_PACKAGE_PATH: &str = "data.agf";
