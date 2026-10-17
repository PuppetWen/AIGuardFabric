//! 控制台补齐的两个存储实体：模型路由策略与剧本执行记录。

use super::*;

/// 模型路由策略（控制台 `ModelRoutePolicy`，见 `apps/web/src/types/domain.ts`）。
///
/// 租户配置持久保存；网关在下一次请求读取策略并执行选路、降级和日预算。
/// 历史预算字段名误写为 USD，实际执行一直按微元记账；按原数值兼容读取，不做汇率换算。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelRoutePolicy {
    /// 单调版本，旧记录缺失时从 0 开始迁移。
    #[serde(default)]
    pub version: u64,
    /// 策略 id（灌库时取确定性 UUID）。
    pub id: Id,
    /// 租户（隔离锚点；对外投影时**不输出**）。
    pub tenant_id: TenantId,
    /// 策略名。
    pub name: String,
    /// 主端点 id（指向 `ModelEndpoint` 资产的 id）。
    pub primary_endpoint_id: String,
    /// 降级端点 id 列表（台账里没有登记为 fallback 的端点时为空，**不伪造**）。
    pub fallback_endpoint_ids: Vec<String>,
    /// 选路策略（前端词表：`priority`/`weighted`/`cost-first`/`latency-first`）。
    pub strategy: String,
    /// 权重表（端点 id → 权重；`weighted` 策略使用）。
    pub weights: BTreeMap<String, f64>,
    /// 日预算（CNY 元；0 = 不限）。
    #[serde(alias = "budget_usd_per_day")]
    pub budget_cny_per_day: f64,
    /// 是否启用。
    pub enabled: bool,
}

/// 案件剧本执行记录（控制台 `SoarRun`）。
///
/// `run` 是 [`agf_correlate::playbook::PlaybookEngine::run`] **真实执行**产出的轨迹对象
/// （逐步 `StepTrace`、结论 `RunOutcome`、`dry_run` 标记），**不是**手写的运行记录；
/// 写入方是 [`crate::seed`]（演示灌库，`AGF_SEED_FIXTURES=1`）。
///
/// `id` / `started_at` 由写入方补充：引擎的 `PlaybookRun` 只带 `finished_at`，没有"运行 id"
/// 与"开始时间"字段（不想为演示给引擎加字段），因此这两个值由调用方如实记录（开始时间即调用
/// `run` 之前的墙钟时刻），并在 `routes/console_ops.rs` 的投影里如实说明。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SoarRunRecord {
    /// 运行 id（灌库时取确定性 UUID）。
    pub id: Id,
    /// 租户（隔离锚点；对外投影时**不输出**）。
    pub tenant_id: TenantId,
    /// 关联案件 id。
    pub case_id: Id,
    /// 运行开始时间（调用引擎之前的墙钟时刻）。
    pub started_at: Timestamp,
    /// 引擎真实产出的执行轨迹。
    pub run: agf_correlate::playbook::PlaybookRun,
}
