//! 由 `guard.rs` 拆分：`GuardItem`/`GuardReport`/`HeartbeatMonitor`/`HeartbeatState`/`ManagedEndpoint` 的实现（纯搬移，逻辑不变）。
use super::*;

impl GuardItem {
    /// 通过项。
    #[must_use]
    pub fn pass(key: &str, label: &str, reason: impl Into<String>) -> Self {
        Self { key: key.to_string(), label: label.to_string(), passed: true, critical: false, reason: reason.into() }
    }

    /// 关键失败项（导致总体 `healthy = false`）。
    #[must_use]
    pub fn fail(key: &str, label: &str, reason: impl Into<String>) -> Self {
        Self { key: key.to_string(), label: label.to_string(), passed: false, critical: true, reason: reason.into() }
    }

    /// 非关键失败项（告警但不影响"是否在防护"的判定）。
    #[must_use]
    pub fn warn(key: &str, label: &str, reason: impl Into<String>) -> Self {
        Self { key: key.to_string(), label: label.to_string(), passed: false, critical: false, reason: reason.into() }
    }
}

impl GuardReport {
    /// 由自检项组装。
    #[must_use]
    pub fn build(
        items: Vec<GuardItem>,
        heartbeat_alerts: Vec<HeartbeatAlert>,
        policy_count: usize,
        blocklist_rule_count: usize,
        audit_entries: u64,
    ) -> Self {
        let passed = items.iter().filter(|i| i.passed).count();
        let failed = items.len() - passed;
        let critical_failures = items.iter().filter(|i| !i.passed && i.critical).count();
        Self {
            healthy: critical_failures == 0,
            items,
            passed,
            failed,
            critical_failures,
            heartbeat_alerts,
            policy_count,
            blocklist_rule_count,
            audit_entries,
            tenant_id: None,
            generated_at: Timestamp::now(),
        }
    }

    /// 单行摘要（日志与告警用）。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "运行时防护自检：{}/{} 通过（关键失败 {}），策略 {} 条，黑名单 {} 条，审计 {} 条，心跳告警 {} 个",
            self.passed,
            self.items.len(),
            self.critical_failures,
            self.policy_count,
            self.blocklist_rule_count,
            self.audit_entries,
            self.heartbeat_alerts.len()
        )
    }

    /// 未通过项（控制台红色卡片）。
    #[must_use]
    pub fn failures(&self) -> Vec<&GuardItem> {
        self.items.iter().filter(|i| !i.passed).collect()
    }

    /// 按 key 取项。
    #[must_use]
    pub fn item(&self, key: &str) -> Option<&GuardItem> {
        self.items.iter().find(|i| i.key == key)
    }
}

impl HeartbeatState {
    /// 距上次心跳经过的秒数。
    #[must_use]
    pub fn silence_secs(&self, now: Timestamp) -> i64 {
        now.since_secs(&self.last_seen)
    }

    /// 是否存活（未达告警阈值）。
    #[must_use]
    pub const fn is_alive(&self) -> bool {
        !self.alerted
    }
}

impl ManagedEndpoint {
    /// 构造（默认 3 次丢失告警）。
    #[must_use]
    pub fn new(endpoint_id: impl Into<String>, kind: impl Into<String>, interval_secs: i64) -> Self {
        Self { endpoint_id: endpoint_id.into(), kind: kind.into(), interval_secs, alert_after: 3 }
    }

    /// 自定义告警阈值。
    #[must_use]
    pub const fn with_alert_after(mut self, n: u32) -> Self {
        self.alert_after = n;
        self
    }
}

impl HeartbeatMonitor {
    /// 新建空监控器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册被管端点（重复注册会重置其心跳时间）。
    pub fn register(&self, endpoint: ManagedEndpoint) {
        let now = Timestamp::now();
        let id = endpoint.endpoint_id.clone();
        let state = HeartbeatState {
            endpoint_id: id.clone(),
            kind: endpoint.kind.clone(),
            interval_secs: endpoint.interval_secs,
            last_seen: now,
            missed: 0,
            alerted: false,
        };
        if let Ok(mut guard) = self.endpoints.lock() {
            guard.insert(id.clone(), (endpoint, state));
        }
        if let Ok(mut reported) = self.reported.lock() {
            reported.remove(&id);
        }
    }

    /// 记录一次心跳（清除丢失计数与告警标记）。
    ///
    /// 返回 `false` 表示端点未注册（调用方应据 `false` 提示"未纳管端点"——
    /// 这本身就是一种绕过信号）。
    pub fn record_beat(&self, endpoint_id: &str) -> bool {
        self.record_beat_at(endpoint_id, Timestamp::now())
    }

    /// 指定时间记录心跳（测试用，避免依赖真实时钟）。
    pub fn record_beat_at(&self, endpoint_id: &str, at: Timestamp) -> bool {
        let Ok(mut guard) = self.endpoints.lock() else { return false };
        let Some((_, state)) = guard.get_mut(endpoint_id) else { return false };
        state.last_seen = at;
        state.missed = 0;
        state.alerted = false;
        drop(guard);
        if let Ok(mut reported) = self.reported.lock() {
            reported.remove(endpoint_id);
        }
        true
    }

    /// 推进一次"丢失检测"（由调度器按 interval 调用；也可在读取报告前调用一次）。
    ///
    /// 返回本轮新增的告警。
    pub fn tick(&self, now: Timestamp) -> Vec<HeartbeatAlert> {
        let Ok(mut guard) = self.endpoints.lock() else { return Vec::new() };
        let mut fresh: Vec<HeartbeatAlert> = Vec::new();
        for (endpoint, state) in guard.values_mut() {
            if now.since_secs(&state.last_seen) < endpoint.interval_secs {
                continue;
            }
            state.missed = state.missed.saturating_add(1);
            if state.missed >= endpoint.alert_after && !state.alerted {
                state.alerted = true;
                fresh.push(HeartbeatAlert {
                    endpoint_id: state.endpoint_id.clone(),
                    kind: state.kind.clone(),
                    missed: state.missed,
                    last_seen: state.last_seen,
                    silence_secs: now.since_secs(&state.last_seen),
                    suggestion: format!(
                        "「{}」连续 {} 次心跳丢失（静默 {} 秒），建议立即核查代理进程是否被结束，\
                         必要时挂起该 Agent 并回收其凭据",
                        state.endpoint_id,
                        state.missed,
                        now.since_secs(&state.last_seen)
                    ),
                });
            }
        }
        drop(guard);
        if let Ok(mut reported) = self.reported.lock() {
            for alert in &fresh {
                reported.insert(alert.endpoint_id.clone(), now);
            }
        }
        fresh
    }

    /// 当前全部告警（不做状态推进，只读取已达阈值的端点；按端点 id 稳定排序）。
    #[must_use]
    pub fn alerts(&self) -> Vec<HeartbeatAlert> {
        let now = Timestamp::now();
        let Ok(guard) = self.endpoints.lock() else { return Vec::new() };
        let mut alerts: Vec<HeartbeatAlert> = guard
            .values()
            .filter(|(_, state)| state.alerted)
            .map(|(_, state)| HeartbeatAlert {
                endpoint_id: state.endpoint_id.clone(),
                kind: state.kind.clone(),
                missed: state.missed,
                last_seen: state.last_seen,
                silence_secs: now.since_secs(&state.last_seen),
                suggestion: format!(
                    "「{}」连续 {} 次心跳丢失，建议核查代理进程并考虑挂起该 Agent",
                    state.endpoint_id, state.missed
                ),
            })
            .collect();
        alerts.sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));
        alerts
    }

    /// 端点是否存活（未达告警阈值）。
    #[must_use]
    pub fn is_alive(&self, endpoint_id: &str) -> bool {
        self.endpoints.lock().ok().and_then(|g| g.get(endpoint_id).map(|(_, s)| s.is_alive())).unwrap_or(false)
    }

    /// 端点状态快照。
    #[must_use]
    pub fn state(&self, endpoint_id: &str) -> Option<HeartbeatState> {
        self.endpoints.lock().ok().and_then(|g| g.get(endpoint_id).map(|(_, s)| s.clone()))
    }

    /// 全部端点状态。
    #[must_use]
    pub fn states(&self) -> Vec<HeartbeatState> {
        self.endpoints.lock().map(|g| g.values().map(|(_, s)| s.clone()).collect()).unwrap_or_default()
    }

    /// 端点数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.endpoints.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// 是否未注册任何端点。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 存活端点数。
    #[must_use]
    pub fn alive_count(&self) -> usize {
        self.states().iter().filter(|s| s.is_alive()).count()
    }
}
