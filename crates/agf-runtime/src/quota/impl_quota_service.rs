//! 由 `quota.rs` 拆分：`QuotaService` 的实现（纯搬移，逻辑不变）。
use super::*;

impl QuotaService {
    /// 由配额集与存储构造。
    #[must_use]
    pub fn new(quotas: Vec<Quota>, store: std::sync::Arc<dyn QuotaStore>) -> Self {
        Self { quotas, store, fail_modes: BTreeMap::new() }
    }

    /// 全内存构造（离线演示 / 测试）。
    #[must_use]
    pub fn in_memory(quotas: Vec<Quota>) -> Self {
        Self::new(quotas, std::sync::Arc::new(InMemoryQuotaStore::new()))
    }

    /// 由 Redis 存储构造。
    #[must_use]
    pub fn with_redis(quotas: Vec<Quota>, redis: std::sync::Arc<RedisStore>) -> Self {
        Self::new(quotas, std::sync::Arc::new(RedisQuotaStore::new(redis)))
    }

    /// 覆盖某维度的失败方向。
    #[must_use]
    pub fn with_fail_mode(mut self, dimension: QuotaDimension, mode: FailMode) -> Self {
        self.fail_modes.insert(dimension, mode);
        self
    }

    /// 替换配额集（热重载）。
    pub fn replace_quotas(&mut self, quotas: Vec<Quota>) {
        self.quotas = quotas;
    }

    /// 生效配额。
    #[must_use]
    pub fn quotas(&self) -> &[Quota] {
        &self.quotas
    }

    /// 计数存储（自检用）。
    #[must_use]
    pub fn store(&self) -> &std::sync::Arc<dyn QuotaStore> {
        &self.store
    }

    /// 某维度当前的失败方向。
    #[must_use]
    pub fn fail_mode(&self, quota: &Quota) -> FailMode {
        self.fail_modes.get(&quota.dimension).copied().unwrap_or_else(|| FailMode::for_action(quota.on_exceed))
    }

    /// 三级检查 + 消费（**先判定、后消费**）。
    ///
    /// 流程：
    /// 1. 对每条生效配额 `peek` 当前用量（只读），交给 [`check_quotas`] 做三级判定；
    /// 2. 判定不通过 ⇒ **立即返回，不消费任何维度**——被拒的请求不该占用任何额度，
    ///    否则一次会话级拒绝会白白吃掉租户/Agent 的额度，把限额提前耗尽；
    /// 3. 判定通过 ⇒ 逐维度 `check_and_consume` 原子消费。若两步之间被并发请求顶到上限，
    ///    该维度仍会因硬上限拒绝（fail-closed），并向调用方报出该维度超限。
    ///
    /// # Errors
    /// 永不返回 `Err`：存储不可达被降级为"放行 + `degraded`"或"拒绝 + 原因"
    /// （见 [`FailMode`]）。保留 `Result` 是为了将来接入"配额定义非法"等硬错误。
    pub async fn check(
        &self,
        tenant: TenantId,
        agent: Option<Id>,
        session: &str,
        consumption: &QuotaConsumption,
    ) -> DomainResult<QuotaCheckOutcome> {
        let mut observations: Vec<(Quota, i64)> = Vec::new();
        let mut degraded = false;
        let mut degradation_reason: Option<String> = None;

        // 1) 只读预检
        for quota in self.quotas.iter().filter(|q| q.enabled && q.tenant_id == tenant) {
            let Some(key) = Self::quota_key(quota, agent, session) else {
                continue; // Agent 级配额但本次调用没有 Agent 身份 ⇒ 跳过
            };
            match self.store.peek(&key).await {
                Ok(used) => observations.push((quota.clone(), used)),
                Err(e) => {
                    degraded = true;
                    let mode = self.fail_mode(quota);
                    if mode == FailMode::FailClosed {
                        return Ok(hard_fail(
                            quota,
                            mode,
                            format!("读取配额用量失败（fail-closed）：{e}"),
                            &mut degraded,
                        ));
                    }
                    degradation_reason.get_or_insert_with(|| format!("读取配额用量失败（fail-open 放行）：{e}"));
                    observations.push((quota.clone(), 0));
                }
            }
        }

        let check = check_quotas(&observations, consumption);
        if !check.allowed {
            // 2) 判定不通过：不消费任何维度（被拒请求不占额度）
            return Ok(QuotaCheckOutcome { check, degraded, reason: degradation_reason });
        }

        // 3) 判定通过：逐维度原子消费
        for quota in self.quotas.iter().filter(|q| q.enabled && q.tenant_id == tenant) {
            let Some(key) = Self::quota_key(quota, agent, session) else { continue };
            let amount = consumption.value(quota.dimension);
            if amount <= 0 {
                continue;
            }
            match self.store.check_and_consume(&key, quota.limit, amount, window_secs(quota)).await {
                Ok(outcome) if outcome.allowed => {}
                Ok(outcome) => {
                    // 预检与消费之间被并发请求顶到上限：以该维度超限收口（fail-closed）
                    let mut exceeded = QuotaCheck::pass();
                    exceeded.allowed = false;
                    exceeded.exceeded_quota_id = Some(quota.id);
                    exceeded.dimension = Some(quota.dimension);
                    exceeded.scope = Some(quota.scope);
                    exceeded.used = outcome.used.saturating_add(amount);
                    exceeded.limit = quota.limit;
                    exceeded.action = quota.on_exceed;
                    exceeded.retry_after_secs = quota.window.seconds();
                    degraded = true;
                    degradation_reason
                        .get_or_insert_with(|| "配额消费时被并发请求顶到上限（已按超限拒绝）".to_string());
                    return Ok(QuotaCheckOutcome { check: exceeded, degraded, reason: degradation_reason });
                }
                Err(e) => {
                    degraded = true;
                    let mode = self.fail_mode(quota);
                    if mode == FailMode::FailClosed {
                        return Ok(hard_fail(quota, mode, format!("配额计数失败（fail-closed）：{e}"), &mut degraded));
                    }
                    degradation_reason.get_or_insert_with(|| format!("配额计数失败（fail-open 放行）：{e}"));
                }
            }
        }

        Ok(QuotaCheckOutcome { check, degraded, reason: degradation_reason })
    }

    /// 只读预检（不消费）。用于"先看能不能过"的 UI 预演与告警。
    ///
    /// # Errors
    /// 同 [`QuotaService::check`]（不返回硬错误）。
    pub async fn check_only(
        &self,
        tenant: TenantId,
        agent: Option<Id>,
        session: &str,
        consumption: &QuotaConsumption,
    ) -> DomainResult<QuotaCheckOutcome> {
        let mut observations: Vec<(Quota, i64)> = Vec::new();
        let mut degraded = false;
        let mut reason: Option<String> = None;
        for quota in self.quotas.iter().filter(|q| q.enabled && q.tenant_id == tenant) {
            let Some(key) = Self::quota_key(quota, agent, session) else { continue };
            match self.store.peek(&key).await {
                Ok(used) => observations.push((quota.clone(), used)),
                Err(e) => {
                    degraded = true;
                    reason.get_or_insert_with(|| format!("读取配额用量失败：{e}"));
                }
            }
        }
        Ok(QuotaCheckOutcome { check: check_quotas(&observations, consumption), degraded, reason })
    }

    /// 请求完成：归还并发额度并累加后置用量。
    ///
    /// - `consumption.concurrency` 从计数中**释放**（不是累加）；
    /// - `tokens` / `cost_micro` / `requests` 若在 [`QuotaService::check`] 时未计入
    ///   （例如 token 数要等模型返回才知道），在此**累加**。
    ///
    /// 为避免重复计量，本方法的约定是：**`check` 只消费 `requests` 与 `concurrency`，
    /// token/金额由此处补记**。若调用方在 `check` 里已经传了 tokens，则应只在
    /// `complete` 中传 `concurrency`，避免把同一笔 token 记两次。
    ///
    /// # Errors
    /// 存储不可达时返回 [`DomainError::DependencyUnavailable`]（由调用方决定是否降级；
    /// 归还失败不影响请求结果，只影响后续并发判定，因此调用方通常只记日志）。
    pub async fn complete(
        &self,
        tenant: TenantId,
        agent: Option<Id>,
        session: &str,
        consumption: &QuotaConsumption,
    ) -> DomainResult<()> {
        let mut errors: Vec<String> = Vec::new();
        for quota in self.quotas.iter().filter(|q| q.enabled && q.tenant_id == tenant) {
            let Some(key) = Self::quota_key(quota, agent, session) else { continue };
            match quota.dimension {
                // 并发：释放
                QuotaDimension::Concurrency => {
                    let amount = consumption.concurrency.max(0);
                    if amount > 0 {
                        if let Err(e) = self.store.release(&key, amount).await {
                            errors.push(format!("{}: {e}", quota.name));
                        }
                    }
                }
                // 其它维度：补记
                _ => {
                    let amount = consumption.value(quota.dimension);
                    if amount > 0 {
                        // 补记不参与"是否放行"判定，故 limit 传 0（不限量）。
                        if let Err(e) = self.store.check_and_consume(&key, 0, amount, window_secs(quota)).await {
                            errors.push(format!("{}: {e}", quota.name));
                        }
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(DomainError::DependencyUnavailable {
                dependency: "quota-store".to_string(),
                cause: format!("配额结算部分失败：{}", errors.join("；")),
            })
        }
    }

    /// 控制台快照（逐条配额的 used/limit/ratio）。
    ///
    /// # Errors
    /// 永不返回硬错误；读取失败的条目 `used = -1` 且 `degraded = true`。
    pub async fn snapshot(&self, tenant: TenantId, agent: Option<Id>, session: &str) -> DomainResult<QuotaSnapshot> {
        let mut snapshot = QuotaSnapshot {
            entries: Vec::new(),
            degraded: self.store.is_degraded(),
            at: agf_core::time::Timestamp::now(),
        };
        for quota in self.quotas.iter().filter(|q| q.enabled && q.tenant_id == tenant) {
            let Some(key) = Self::quota_key(quota, agent, session) else { continue };
            let (used, degraded) = match self.store.peek(&key).await {
                Ok(v) => (v, false),
                Err(_) => (-1, true),
            };
            if degraded {
                snapshot.degraded = true;
            }
            #[allow(clippy::cast_precision_loss)]
            let ratio = if used < 0 || quota.limit <= 0 { -1.0_f32 } else { (used as f32) / (quota.limit as f32) };
            snapshot.entries.push(SnapshotEntry {
                quota_id: quota.id,
                name: quota.name.clone(),
                scope: quota.scope,
                target: key.target.clone().unwrap_or_default(),
                dimension: quota.dimension,
                window: quota.window,
                used,
                limit: quota.limit,
                ratio,
                on_exceed: quota.on_exceed,
                soft_breached: used >= 0 && quota.is_soft_breached(used),
                degraded,
            });
        }
        Ok(snapshot)
    }

    /// 计算某配额的三级作用域落点。
    ///
    /// 返回 `None` 表示该配额在本次调用中不适用（Agent 级配额但无 Agent 身份）。
    ///
    /// `scope` / `dimension` / `bucket` 三者与 [`agf_storage::RedisStore::quota`]
    /// 的键布局一一对应；`target` 为 Agent id 或会话 id（租户级为 `None`）。
    /// 配额显式绑定了 `target_id` 时以它为准（可用于"把某条租户级配额限定到某个 Agent"）。
    pub(crate) fn quota_key(quota: &Quota, agent: Option<Id>, session: &str) -> Option<QuotaKey> {
        let target = quota.target_id.map(|t| t.to_string()).or_else(|| match quota.scope {
            QuotaScope::Tenant => None,
            QuotaScope::Agent => agent.map(|a| a.to_string()),
            QuotaScope::Session => Some(session.to_string()),
        });
        // Agent 级配额必须落到具体 Agent；无 Agent 身份时该配额不适用。
        if quota.target_id.is_none() && quota.scope == QuotaScope::Agent && target.is_none() {
            return None;
        }
        Some(QuotaKey {
            tenant: quota.tenant_id,
            scope: quota.scope.as_str().to_string(),
            dimension: quota.dimension.as_str().to_string(),
            bucket: quota.window.bucket_key(agf_core::time::Timestamp::now()),
            target,
        })
    }
}
