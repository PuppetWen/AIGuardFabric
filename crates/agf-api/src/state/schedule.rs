//! 报表周期调度登记表 `ScheduleStore`（自 `state.rs` 拆出）。

use super::*;

/// 报表周期调度登记表（`GET`/`POST /api/v1/reports/schedules`）。
///
/// ## 数据来源与降级
///
/// - 记录保存在**本进程内存**（与 [`crate::store`] 的其它实体同口径：`TODO(api-persistence)`；
///   `agf-storage` 尚无 `report_schedules` 仓储），重启即清空；
/// - **首次访问某租户时写入 2 条演示调度**（幂等）：仓库里没有任何调度 fixtures，
///   空表会让「周期报表」永远空白，故按任务约定灌入演示登记（字段都是真实可用值：
///   `cron` / 窗口 / 类型 / 格式 / 启用位），调用方可用 `POST` 覆盖或新增；
/// - `cron` **只登记不执行**：`agf-server` 进程里没有调度器（`apps/scheduler` 未装配进来），
///   因此 `last_generated_at` 恒为 `None`，绝不谎报"已按周期生成"。见
///   `TODO(api-report-schedule-runner)`；
/// - `channel_ids` / `recipients` 留空：`ApiStore` 没有通知渠道表，编造收件人比留空更糟。
#[derive(Debug, Default)]
pub struct ScheduleStore {
    inner: std::sync::Mutex<BTreeMap<(TenantId, Id), ReportSchedule>>,
}

/// 演示调度登记 `(id 种子, 名称, 类型, 格式, cron, 窗口秒)`。
const DEMO_SCHEDULES: [(&str, &str, ReportKind, ReportFormat, &str, i64); 2] = [
    ("demo-weekly-posture", "每周安全态势（演示）", ReportKind::Posture, ReportFormat::Markdown, "0 8 * * 1", 604_800),
    ("demo-daily-findings", "每日风险发现（演示）", ReportKind::Findings, ReportFormat::Markdown, "0 9 * * *", 86_400),
];

/// 调度 id 命名空间（确定性 id，重复灌库不产生重复行）。
const NS_REPORT_SCHEDULE: &str = "aiguardfabric.api.report_schedule";

impl ScheduleStore {
    /// 空登记表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 写入/覆盖一条调度（按 `(租户, id)`）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn upsert(&self, schedule: &ReportSchedule) -> DomainResult<Id> {
        self.inner
            .lock()
            .map_err(|e| DomainError::Internal(format!("调度登记表锁中毒: {e}")))?
            .insert((schedule.tenant_id, schedule.id), schedule.clone());
        Ok(schedule.id)
    }

    /// 读取一条调度（租户隔离）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn get(&self, tenant: TenantId, id: Id) -> DomainResult<Option<ReportSchedule>> {
        Ok(self
            .inner
            .lock()
            .map_err(|e| DomainError::Internal(format!("调度登记表锁中毒: {e}")))?
            .get(&(tenant, id))
            .cloned())
    }

    /// 列出该租户全部调度（按名称排序，输出顺序确定）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn list(&self, tenant: TenantId) -> DomainResult<Vec<ReportSchedule>> {
        let mut items: Vec<ReportSchedule> = self
            .inner
            .lock()
            .map_err(|e| DomainError::Internal(format!("调度登记表锁中毒: {e}")))?
            .iter()
            .filter(|((t, _), _)| *t == tenant)
            .map(|(_, s)| s.clone())
            .collect();
        items.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(items)
    }

    /// 首次访问时灌入演示调度，返回**本次新增**条数（已存在则 0，幂等）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn ensure_demo(&self, tenant: TenantId, now: Timestamp) -> DomainResult<usize> {
        let mut added = 0_usize;
        for (seed, name, kind, format, cron, window_secs) in DEMO_SCHEDULES {
            let id = agf_core::ids::deterministic_id(NS_REPORT_SCHEDULE, &format!("{tenant}:{seed}"));
            if self.get(tenant, id)?.is_some() {
                continue;
            }
            let schedule = ReportSchedule {
                id,
                tenant_id: tenant,
                name: name.to_string(),
                kind,
                format,
                cron: cron.to_string(),
                window_secs,
                channel_ids: Vec::new(),
                recipients: Vec::new(),
                enabled: true,
                last_generated_at: None,
                created_at: now,
            };
            self.upsert(&schedule)?;
            added = added.saturating_add(1);
        }
        Ok(added)
    }
}
