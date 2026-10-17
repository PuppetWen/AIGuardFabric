//! 演示数据灌库：`data/seed/*.json`（合成数据集）→ [`ApiStore`]。
//!
//! ## 为什么需要
//!
//! [`ApiStore`] 是纯内存真相源（见 [`crate::store`] 模块文档），进程启动时是空的，
//! 因此控制台列表页长期表现为"接口 200 但 `total=0`"。本模块把 `data/seed/` 下的合成数据集
//! 按领域模型映射后灌入，并额外合成少量**运行时对象**（扫描任务 / 红队战役 / 报表 / 配额），
//! 让演示环境"一开机就有数据"。
//!
//! ## 数据来源
//!
//! | 文件 | 数据集键 | 落库路径 | 条数 |
//! |---|---|---|---|
//! | `assets.json` | `assets` | [`ApiStore::asset_upsert`] | 8 |
//! | `findings.json` | `findings` | [`ApiStore::finding_insert`] | 6 |
//! | `policies.json` | `policies` | [`ApiStore::policy_upsert`] | 3 |
//! | `alerts.json` | `alerts` | [`ApiStore::alert_upsert_dedup`] | 4 |
//! | `cases.json` | `cases` | [`ApiStore::case_create`] | 2 |
//! | `redteam-cases.json` | `redteam_cases` | **无对应存储面**（仅解析校验 + 跨表引用检查） | 3 |
//!
//! 文件清单以 `data/seed/index.json` 为准；本模块**不信任**其中的 `count` 字段，只以实际
//! `items` 数组为准，两者不一致时记 `warn` 并计入 [`SeedReport::warnings`]。
//!
//! `redteam_cases` 数据集没有对应的内存表：红队用例库的正规来源是 `redteam/*.yaml`
//! （[`CaseLibrary`]，由 [`crate::state::AppState`] 装配）。该数据集仍然被解析，
//! 用于**校验** `policy_id` 等跨表引用是否指向本次灌入的策略；条数如实记入
//! [`DatasetReport::skipped`] 并在 `note` 中说明，不伪造存储面。
//!
//! ## 由真实组件产出的数据（不是 hand-written 记录）
//!
//! 除 fixtures 之外，本模块**驱动项目里的真实组件**产出控制台"接口通但恒为空"的几类数据。
//! 每条产出的来源与落库路径如下（本模块只负责"驱动 + 如实计数"，不复制被驱动组件的逻辑）：
//!
//! | 产出 | 真实来源（谁产出的） | 落库路径 | 对外端点 |
//! |---|---|---|---|
//! | 运行时拦截审计 | [`RuntimeEngine`] 自身：`intercept_mcp_request`（MCP 代理点）/ `evaluate` + `record_decision`（进程 Hook 与 AI 网关点） | 引擎内存**哈希链**（不复制进 [`ApiStore`]） | `GET /runtime/events`、`GET /runtime/intercept-points` |
//! | 模型计量记录 | `agf_aigw::Meter::record`（token/费用走 `meter::breakdown` 微元整数运算；调用形态由 `agf_aigw::MockProvider` 这一真实 provider 实现合成——无 Key 时网关的既定降级路径也是它） | [`crate::state::AppState::meter`] | `GET /models/usage`、`GET /models/usage/aggregate` |
//! | 剧本执行轨迹 | `agf_correlate::playbook::PlaybookEngine::run`（`parse_playbooks_yaml` 解析 → `validate` → `run`，注入 `MockActionExecutor`/`MockNotifySink`/`MockApprovalGate`） | [`ApiStore::soar_run_insert`] | `GET /cases/{id}/soar-runs` |
//! | MCP 工具清单 | fixtures 资产的 `attributes.tools`（`agf_core::mcp::ToolTraits::infer` 推断能力/风险） | [`ApiStore::asset_upsert`] | `GET /mcp-servers/{id}/tools` |
//! | 模型路由策略 | **演示记录**：`agf-aigw` 只有运行时选路（`ModelRouter`），没有策略实体，故由本模块合成并落 [`ApiStore::route_policy_upsert`] | [`ApiStore::route_policy_upsert`] | `GET /models/route-policies` |
//!
//! 三处**刻意不做**的事：
//!
//! 1. **不手写审计条目**：`/runtime/events` 的每一行都由引擎自己的拦截入口产生（含哈希链）；
//! 2. **不手写剧本轨迹**：`/cases/{id}/soar-runs` 的每一步都来自 `PlaybookEngine::run` 的
//!    `StepTrace`，本模块只补 `id`/`started_at` 两个引擎没有的字段（如实标注）；
//! 3. **不伪造端点**：台账里只有 1 个 `ModelEndpoint` 资产，因此路由策略的
//!    `fallback_endpoint_ids` 一律为空，不编造未登记的端点 id。
//!
//! ## 不灌入的数据集（刻意留空，不是"忘了接数据源"）
//!
//! - **API Key**（`GET /api/v1/api-keys`）：API Key 是**凭据**，演示环境不预置任何凭据——
//!   预置等于把可用的长期凭据写进交付物。`ApiStore::api_keys` 在灌库阶段恒为空；
//!   需要 Key 时由管理员通过 `POST /api/v1/api-keys` 现场签发。
//!
//! ## 开关与目录
//!
//! | 项 | 环境变量 | 取值 / 默认 |
//! |---|---|---|
//! | 总开关 | `AGF_SEED_FIXTURES` | `1` / `true` / `yes` / `on` 为开，**默认关闭**（生产安全） |
//! | 数据集目录 | `AGF_SEED_DIR` | 容器 `/app/data/seed`（compose 注入），本机回退 `<项目根>/data/seed` |
//!
//! 关闭时本模块**完全不执行**，[`ApiStore`] 保持为空（与历史行为一致）。
//!
//! ## 降级行为（铁律）
//!
//! 目录不存在、单个数据集文件缺失、JSON 解析失败、条目字段缺失、枚举取值无法映射、
//! 跨表引用解析不到目标 —— 一律只 `warn!` 并跳过该条/该数据集，计入
//! [`DatasetReport::errors`]（解析/写入失败）或 [`DatasetReport::skipped`]（幂等命中/数据集缺失），
//! **绝不 panic、绝不让进程崩溃、绝不让服务起不来**。本函数仅在内存后端锁中毒
//! （[`DomainError::Internal`]）时返回 `Err`；调用方（[`crate::state::AppState::build`]）
//! 对该 `Err` 也只降级告警，不影响启动。
//!
//! ## 幂等性
//!
//! 所有业务键（`ast-agent-0001`、`fnd-0001`……）经 [`deterministic_id`] 映射为**确定性 UUID**，
//! 引用同一份 fixtures 的两次灌库产生完全相同的 ID；写入前先按确定性 ID / 名称 / 去重键判重
//! （走 [`ApiStore`] 既有读写能力），因此重复调用不产生重复数据，第二次调用
//! [`DatasetReport::inserted`] 恒为 0。
//!
//! 例外：告警与案件的 UUID 由 [`ApiStore`] 内部 `Id::new()`（UUID v7）生成 —— store 未提供
//! "注入 id"的写入路径。这两类实体按 `dedup_key` / 标题判重保证幂等，跨表引用按运行时返回的
//! ID 解析（见 [`CrossRefs`]），其绝对值跨进程不稳定，已在文档与测试中如实标注。
//!
//! ## 合成运行时对象（仅为演示）
//!
//! 命名空间用独立前缀 `aiguardfabric.seed.runtime`，与 fixtures 派生的 ID 不冲突：
//! 扫描任务 2 个（1 个终态 `succeeded`、1 个 `running`）、红队战役 1 个（真实用例库
//! [`CaseLibrary`] + [`CampaignRunner`] + [`RedteamSimulator`] 离线模拟目标，含逐用例结果与
//! Markdown 报告）、报表 2 份（Markdown / JSON 各 1）、配额 4 条（[`ApiStore::quota_ensure_defaults`]）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agf_aigw::wire::ChatRequest;
use agf_aigw::{Meter, MockProvider};
use agf_core::asset::Asset;
use agf_core::config::QuotaDefaults;
use agf_core::enums::{
    AlertState, AssetKind, CaseState, DataClass, DiscoverySource, EvidenceLevel, InterceptPoint, LifecycleState,
    LlmProvider, PolicyAction, Protocol, RiskDomain, Severity,
};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId, deterministic_id};
use agf_core::model::{ModelEndpoint, ModelPricing};
use agf_core::policy::{Policy, PolicyContext, PolicyLanguage, StructuredCondition};
use agf_core::redteam::RedteamResult;
use agf_core::report::{ReportFormat, ReportKind};
use agf_core::risk::{Evidence, Finding, FindingState};
use agf_core::time::{TimeRange, Timestamp};
use agf_correlate::playbook::{
    MockActionExecutor, MockApprovalGate, MockNotifySink, PlaybookEngine, RunContext, TriggerInput,
    parse_playbooks_yaml,
};
use agf_runtime::engine::RuntimeEngine;
use agf_scan::redteam::{CampaignRunner, CaseLibrary, RedteamSimulator, render_markdown};
use futures::FutureExt;
use serde_json::Value;
use tracing::{info, warn};

use crate::store::{ApiStore, ModelRoutePolicy, ScanJob, ScanJobState, SoarRunRecord};

// ===========================================================================
// 常量：开关、目录、数据集与命名空间
// ===========================================================================

/// 总开关环境变量名。
pub const ENV_ENABLED: &str = "AGF_SEED_FIXTURES";
/// 数据集目录环境变量名。
pub const ENV_DIR: &str = "AGF_SEED_DIR";

/// 确定性 ID 命名空间：演示资产。
pub(super) const NS_ASSET: &str = "aiguardfabric.seed.asset";
/// 确定性 ID 命名空间：演示风险发现。
pub(super) const NS_FINDING: &str = "aiguardfabric.seed.finding";
/// 确定性 ID 命名空间：演示策略。
pub(super) const NS_POLICY: &str = "aiguardfabric.seed.policy";
/// 确定性 ID 命名空间：**合成运行时对象**（扫描/战役/报表）。
pub(super) const NS_RUNTIME: &str = "aiguardfabric.seed.runtime";

/// 数据集：资产。
pub(super) const DS_ASSETS: &str = "assets";
/// 数据集：风险发现。
pub(super) const DS_FINDINGS: &str = "findings";
/// 数据集：策略。
pub(super) const DS_POLICIES: &str = "policies";
/// 数据集：告警。
pub(super) const DS_ALERTS: &str = "alerts";
/// 数据集：案件。
pub(super) const DS_CASES: &str = "cases";
/// 数据集：红队用例（无存储面，仅校验）。
pub(super) const DS_REDTEAM_CASES: &str = "redteam_cases";
/// 数据集：扫描任务（合成）。
pub(super) const DS_SCANS: &str = "scans";
/// 数据集：红队战役（合成）。
pub(super) const DS_CAMPAIGNS: &str = "redteam_campaigns";
/// 数据集：报表（合成）。
pub(super) const DS_REPORTS: &str = "reports";
/// 数据集：配额（合成/默认值）。
pub(super) const DS_QUOTAS: &str = "quotas";
/// 数据集：模型路由策略（合成/演示记录）。
pub(super) const DS_ROUTE_POLICIES: &str = "route_policies";
/// 数据集：模型计量记录（由 `agf_aigw::Meter` 真实计价产出）。
pub(super) const DS_MODEL_USAGE: &str = "model_usage";
/// 数据集：案件剧本执行轨迹（由 `agf_correlate::playbook::PlaybookEngine` 真实执行产出）。
pub(super) const DS_SOAR_RUNS: &str = "soar_runs";
/// 数据集：运行时拦截审计（由 [`RuntimeEngine`] 自身产出）。
pub(super) const DS_RUNTIME_EVENTS: &str = "runtime_events";

/// 数据集键（对外）：模型计量记录（[`crate::state::AppState::build`] 的启动日志用）。
pub const DATASET_MODEL_USAGE: &str = DS_MODEL_USAGE;
/// 数据集键（对外）：运行时拦截审计（同上）。
pub const DATASET_RUNTIME_EVENTS: &str = DS_RUNTIME_EVENTS;

/// 合成运行时对象的来源说明（无 fixtures 文件）。
pub(super) const SYNTHETIC_SOURCE: &str = "(合成运行时对象，无 fixtures 文件)";

/// 演示战役名。
pub(super) const CAMPAIGN_NAME: &str = "演示-红队巡航（合成）";
/// 演示战役/报表的发起人标识。
pub(super) const DEMO_ACTOR: &str = "demo-seed";

pub use entry::*;
pub use model_usage::*;
pub use report::*;
pub use runtime::*;

use alerts::*;
use assets::*;
use cases::*;
use findings::*;
use policies::*;
use quotas_route_policies::*;
use scan_campaign_report::*;
use soar_runs::*;
use support::*;

// ===========================================================================
// 测试
// ===========================================================================

mod alerts;
mod assets;
mod cases;
mod entry;
mod findings;
mod model_usage;
mod policies;
mod quotas_route_policies;
mod report;
mod runtime;
mod scan_campaign_report;
mod soar_runs;
mod support;
#[cfg(test)]
mod tests_a;
#[cfg(test)]
mod tests_b;
