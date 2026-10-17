//! 写后持久化的值类型：写意图载荷（`AlertWrite` / `PgWrite`）、队列计数（`WriteStats` /
//! `WriteQueue`）与报告（`HydrationReport` / `PersistenceReport`）。

use super::*;

/// 单条告警去重 upsert 的写意图载荷。
#[derive(Debug, Clone)]
pub struct AlertWrite {
    /// 租户。
    pub tenant: TenantId,
    /// 内存层的告警 id（用于建立重映射表）。
    pub memory_id: Id,
    /// 去重键。
    pub dedup_key: String,
    /// 标题。
    pub title: String,
    /// 描述。
    pub description: String,
    /// 严重等级。
    pub severity: Severity,
    /// 风险域。
    pub domain: Option<RiskDomain>,
    /// 关联资产。
    pub asset_ids: Vec<Id>,
    /// 关联发现。
    pub finding_ids: Vec<Id>,
    /// SLA 截止。
    pub sla_due_at: Option<Timestamp>,
}

/// 写意图：内存层**已经**改完，这里只描述"还要把同样的改动落到 PG"。
#[derive(Debug, Clone)]
pub enum PgWrite {
    /// 资产 upsert（仓储按 `fingerprint` 幂等）。
    AssetUpsert {
        /// 资产（`Box` 以压小枚举体积）。
        asset: Box<Asset>,
    },
    /// 资产生命周期流转。
    AssetLifecycle {
        /// 租户。
        tenant: TenantId,
        /// 资产 id。
        id: Id,
        /// 目标状态。
        state: LifecycleState,
    },
    /// 资产变更台账。
    AssetChange {
        /// 变更记录。
        change: Box<AssetChange>,
    },
    /// 每日快照。
    AssetSnapshot {
        /// 租户。
        tenant: TenantId,
        /// 快照日期（`YYYY-MM-DD`）。
        date: String,
        /// 资产。
        asset: Box<Asset>,
    },
    /// 发现插入（含证据明细）。
    FindingInsert {
        /// 发现。
        finding: Box<Finding>,
    },
    /// 发现状态与注记更新。
    FindingSetState {
        /// 租户。
        tenant: TenantId,
        /// 发现 id。
        id: Id,
        /// 新状态。
        state: FindingState,
        /// 复核注记。
        verify_note: Option<String>,
        /// 证据等级。
        evidence_level: Option<EvidenceLevel>,
    },
    /// 策略 upsert（仓储按名称）。
    PolicyUpsert {
        /// 策略。
        policy: Box<Policy>,
    },
    /// 告警按去重键 upsert。
    AlertDedup {
        /// 载荷。
        write: Box<AlertWrite>,
    },
    /// 告警状态/指派更新。
    AlertSetState {
        /// 租户。
        tenant: TenantId,
        /// 内存层告警 id（经重映射表解析为 PG 行 id）。
        id: Id,
        /// 新状态。
        state: AlertState,
        /// 指派给。
        assignee: Option<String>,
    },
    /// 案件新建。
    CaseCreate {
        /// 案件。
        case: Box<Case>,
    },
    /// 案件状态流转。
    CaseSetState {
        /// 租户。
        tenant: TenantId,
        /// 内存层案件 id（经重映射表解析）。
        id: Id,
        /// 新状态。
        state: CaseState,
        /// 决议说明。
        resolution: Option<String>,
    },
    /// 案件时间线事件。
    CaseAddEvent {
        /// 事件。
        event: Box<CaseEvent>,
    },
    /// API Key 签发（**只落指纹/前缀/scope/租户**，明文永不入库）。
    ApiKeyInsert {
        /// Key 记录（`Box` 以压小枚举体积）。
        key: Box<ApiKey>,
    },
    /// API Key 吊销。
    ApiKeyRevoke {
        /// 租户。
        tenant: TenantId,
        /// Key id。
        id: Id,
    },
}

impl PgWrite {
    /// 写意图标签（日志与最近错误用）。
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::AssetUpsert { .. } => "asset.upsert",
            Self::AssetLifecycle { .. } => "asset.lifecycle",
            Self::AssetChange { .. } => "asset.change",
            Self::AssetSnapshot { .. } => "asset.snapshot",
            Self::FindingInsert { .. } => "finding.insert",
            Self::FindingSetState { .. } => "finding.set-state",
            Self::PolicyUpsert { .. } => "policy.upsert",
            Self::AlertDedup { .. } => "alert.dedup",
            Self::AlertSetState { .. } => "alert.set-state",
            Self::CaseCreate { .. } => "case.create",
            Self::CaseSetState { .. } => "case.set-state",
            Self::CaseAddEvent { .. } => "case.add-event",
            Self::ApiKeyInsert { .. } => "api-key.insert",
            Self::ApiKeyRevoke { .. } => "api-key.revoke",
        }
    }

    /// 租户（重映射表与事务上下文的键）。
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        match self {
            Self::AssetUpsert { asset } => asset.tenant_id,
            Self::AssetLifecycle { tenant, .. }
            | Self::AssetSnapshot { tenant, .. }
            | Self::FindingSetState { tenant, .. }
            | Self::AlertSetState { tenant, .. }
            | Self::CaseSetState { tenant, .. }
            | Self::ApiKeyRevoke { tenant, .. } => *tenant,
            Self::AssetChange { change } => change.tenant_id,
            Self::FindingInsert { finding } => finding.tenant_id,
            Self::PolicyUpsert { policy } => policy.tenant_id,
            Self::AlertDedup { write } => write.tenant,
            Self::CaseCreate { case } => case.tenant_id,
            Self::CaseAddEvent { event } => event.tenant_id,
            Self::ApiKeyInsert { key } => key.tenant_id,
        }
    }
}

/// 写入队列的原子计数（无锁，可在同步写方法里直接调用）。
#[derive(Debug, Default)]
pub struct WriteStats {
    /// 成功入队条数。
    queued: AtomicU64,
    /// 成功落库条数。
    pub(super) applied: AtomicU64,
    /// 执行失败条数。
    failed: AtomicU64,
    /// 因队列满被丢弃条数。
    dropped: AtomicU64,
    /// 发生 id 重映射的次数（告警/案件）。
    pub(super) id_remapped: AtomicU64,
    /// 当前在队条数。
    pub(super) depth: AtomicUsize,
    /// 最近错误（有界）。
    pub(super) recent_errors: Mutex<VecDeque<String>>,
}

impl WriteStats {
    /// 追加一条最近错误（有界，最多 [`MAX_RECENT_ERRORS`] 条）。
    fn push_error(&self, message: String) {
        if let Ok(mut errors) = self.recent_errors.lock() {
            if errors.len() >= MAX_RECENT_ERRORS {
                errors.pop_front();
            }
            errors.push_back(message);
        }
    }

    /// 记一次落库失败（计数 + 最近错误）。
    pub(super) fn record_failure(&self, intent: &str, error: &DomainError) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        self.push_error(format!("{intent}: {error}"));
    }

    /// 记一次丢弃（计数 + 采样日志 + 最近错误）。
    fn record_drop(&self, capacity: usize) {
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped % DROP_LOG_INTERVAL == 1 {
            let message = format!("写后队列已满（上限 {capacity} 条）：累计丢弃 {dropped} 条写意图，PG 将缺少这些改动");
            self.push_error(message);
            warn!(dropped, capacity, "写后持久化队列达到上限，正在丢弃写意图（内存仍为权威副本）");
        }
    }

    /// 快照 `(queued, applied, failed, dropped, id_remapped, depth)`。
    #[must_use]
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64, usize) {
        (
            self.queued.load(Ordering::Relaxed),
            self.applied.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
            self.id_remapped.load(Ordering::Relaxed),
            self.depth.load(Ordering::Relaxed),
        )
    }
}

/// 写入队列：`UnboundedSender` + **显式深度上限**（超限丢弃并计数）。
///
/// # 为什么用无界通道 + 自带上限
///
/// 写方法是**同步**的，不能在请求线程上 `.await` 一次 `send`（有界通道在满时会挂起发送方，
/// 等于把 PG 的背压变成对控制台请求的阻塞）。这里用无界通道保证 `enqueue` 恒为瞬时操作，
/// 深度上限由 [`WriteStats::depth`] 计数在**入队前**判定：超过上限即丢弃，请求照常返回。
#[derive(Debug)]
pub struct WriteQueue {
    sender: UnboundedSender<PgWrite>,
    pub(super) stats: Arc<WriteStats>,
    capacity: usize,
}

impl WriteQueue {
    /// 构造独立队列（**无消费者**）：测试与自检用，返回接收端以便驱动。
    #[must_use]
    pub fn detached(capacity: usize) -> (Arc<Self>, UnboundedReceiver<PgWrite>) {
        let (sender, receiver) = unbounded_channel();
        let queue = Arc::new(Self { sender, stats: Arc::new(WriteStats::default()), capacity: capacity.max(1) });
        (queue, receiver)
    }

    /// 入队一条写意图；队列满时**丢弃并计数**（返回 `false` 表示被丢弃）。
    pub fn enqueue(&self, intent: PgWrite) -> bool {
        let depth = self.stats.depth.load(Ordering::Relaxed);
        if depth >= self.capacity {
            self.stats.record_drop(self.capacity);
            return false;
        }
        if self.sender.send(intent).is_err() {
            // 消费端已退出（进程关闭中）：与丢弃同口径记账，绝不 panic。
            self.stats.record_drop(self.capacity);
            return false;
        }
        self.stats.queued.fetch_add(1, Ordering::Relaxed);
        self.stats.depth.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// 队列上限。
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// 统计句柄。
    #[must_use]
    pub fn stats(&self) -> &Arc<WriteStats> {
        &self.stats
    }
}

/// 水合结果（启动时从 PG 读进内存的量）。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HydrationReport {
    /// 各资源水合成功条数。
    pub loaded: BTreeMap<String, usize>,
    /// 被跳过的面（原因写在值里）。
    pub skipped: Vec<String>,
    /// 水合错误（如实记录，不 panic、不阻断启动）。
    pub errors: Vec<String>,
    /// 是否**推迟到后台任务**水合（当前运行时不是 multi-thread 时为 true）。
    pub deferred: bool,
}

impl HydrationReport {
    /// 推迟水合（后台任务完成前内存缓存可能是空的）。
    #[must_use]
    pub fn deferred() -> Self {
        Self { loaded: BTreeMap::new(), skipped: Vec::new(), errors: Vec::new(), deferred: true }
    }

    /// 水合条数合计。
    #[must_use]
    pub fn total_loaded(&self) -> usize {
        self.loaded.values().sum()
    }
}

/// 持久化报告（`/readyz` 的 notes、日志、测试断言共用）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistenceReport {
    /// 已落 PG 的资源。
    pub durable: Vec<String>,
    /// 仅内存（无仓储）的资源。
    pub memory_only: Vec<String>,
    /// 启动水合结果。
    pub hydrate: HydrationReport,
    /// 成功入队条数。
    pub queued: u64,
    /// 成功落库条数。
    pub applied: u64,
    /// 落库失败条数。
    pub failed: u64,
    /// 队列满丢弃条数。
    pub dropped: u64,
    /// 发生 id 重映射的次数。
    pub id_remapped: u64,
    /// 当前在队条数。
    pub pending: usize,
    /// 队列上限。
    pub queue_capacity: usize,
    /// 最近错误。
    pub recent_errors: Vec<String>,
}

impl PersistenceReport {
    /// 一致性口径（一句话，供 `/readyz` 的 notes 直接使用）。
    #[must_use]
    pub fn consistency_line() -> String {
        "持久化口径：PostgreSQL 为持久层、内存为读缓存；写入为写后**最终一致**（非事务性双写，\
         存在「内存已改、PG 未落」的窗口，进程在该窗口内被杀会丢该次改动）——TODO(api-persistence-tx)"
            .to_string()
    }

    /// 面向 `/readyz` 的 notes（启动期快照）。
    ///
    /// **边界**：`AppState::notes` 是构建期快照（`routes/**` 只读 `state.notes`，本轮不改
    /// 路由层），因此这里的 `queued/applied/failed/dropped` 是**启动瞬间**的值；
    /// 运行期计数请读 [`PersistenceBridge::report`] 或日志（丢弃与失败都会打 `warn`）。
    #[must_use]
    pub fn notes(&self) -> Vec<String> {
        let mut lines = vec![
            Self::consistency_line(),
            format!("已落 PostgreSQL 的资源（写后持久化）：{}", self.durable.join(", ")),
            format!("无对应仓储、仍仅内存（重启即丢）：{}", self.memory_only.join(", ")),
        ];
        if self.hydrate.deferred {
            lines.push(
                "启动水合已推迟到后台任务（当前运行时不是 multi-thread）：后台完成前内存缓存可能为空，\
                 PG 中的数据不受影响"
                    .to_string(),
            );
        } else {
            let loaded: Vec<String> = self.hydrate.loaded.iter().map(|(k, v)| format!("{k}={v}")).collect();
            lines.push(format!(
                "启动水合完成：{}（合计 {} 条；水合只把 PG 读进内存缓存，不产生写回）",
                if loaded.is_empty() { "无".to_string() } else { loaded.join(" ") },
                self.hydrate.total_loaded()
            ));
        }
        for skipped in &self.hydrate.skipped {
            lines.push(format!("水合跳过：{skipped}"));
        }
        for error in &self.hydrate.errors {
            lines.push(format!("水合错误：{error}"));
        }
        lines.push(format!(
            "写后队列：上限 {} 条，累计入队 {} / 落库 {} / 失败 {} / 丢弃 {}（id 重映射 {} 次）；\
             这一段是**启动期快照**，运行期实时计数请读 PersistenceBridge::report() 或 warn 日志\
             （丢弃与失败都会打 warn）",
            self.queue_capacity, self.queued, self.applied, self.failed, self.dropped, self.id_remapped
        ));
        for error in &self.recent_errors {
            lines.push(format!("写后持久化最近错误：{error}"));
        }
        lines
    }
}
