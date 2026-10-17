//! 由 `audit.rs` 拆分：`impl_InterceptionVerdict`/`impl_InterceptionRecord` 等 5 项（纯搬移，逻辑不变）。
use super::*;

impl InterceptionVerdict {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::ForwardedRedacted => "forwarded-redacted",
            Self::Blocked => "blocked",
            Self::Throttled => "throttled",
            Self::Degraded => "degraded",
            Self::PendingApproval => "pending-approval",
            Self::Isolated => "isolated",
            Self::CircuitBroken => "circuit-broken",
            Self::Audited => "audited",
        }
    }

    /// 中文简述（控制台）。
    #[must_use]
    pub const fn display_zh(&self) -> &'static str {
        match self {
            Self::Forwarded => "已放行",
            Self::ForwardedRedacted => "脱敏放行",
            Self::Blocked => "已阻断",
            Self::Throttled => "已限流",
            Self::Degraded => "已降级",
            Self::PendingApproval => "待审批（拒绝）",
            Self::Isolated => "已隔离",
            Self::CircuitBroken => "已熔断",
            Self::Audited => "仅审计",
        }
    }

    /// 是否拦下了请求。
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self, Self::Blocked | Self::PendingApproval | Self::Isolated | Self::CircuitBroken | Self::Throttled)
    }

    /// 由策略动作推导处置结果（`dry_run` 一律降级为 [`Self::Audited`]）。
    #[must_use]
    pub const fn from_action(action: PolicyAction, dry_run: bool) -> Self {
        if dry_run {
            return Self::Audited;
        }
        match action {
            PolicyAction::Allow => Self::Forwarded,
            PolicyAction::Deny => Self::Blocked,
            PolicyAction::Audit => Self::Audited,
            PolicyAction::Quota | PolicyAction::Throttle => Self::Throttled,
            PolicyAction::Redact => Self::ForwardedRedacted,
            PolicyAction::Degrade => Self::Degraded,
            PolicyAction::CircuitBreak => Self::CircuitBroken,
            PolicyAction::Isolate => Self::Isolated,
            PolicyAction::Approval => Self::PendingApproval,
        }
    }
}

impl InterceptionRecord {
    /// 计算规范化载荷哈希（**不可变字段**参与；`entry_hash` 自身不参与）。
    ///
    /// `latency_micros` **仅当 > 0 时**并入摘要素材，理由有两条，缺一不可：
    ///
    /// - **向后兼容**：v0 记录没有该字段，反序列化后为 `0`；若无条件并入，重算出的哈希
    ///   与升级前逐字节不同，[`Self::verify`] 会把一条**合法的老记录**误报为"疑似被篡改"，
    ///   进而让 [`InterceptionAuditLog::verify`] 与 `guard` 自检（`audit.chain`）集体误报；
    /// - **不放弃保护**：新记录只要测到了耗时（> 0）就并入哈希，改这条记录的时间同样会被
    ///   链校验发现。
    ///
    /// 因此"耗时 = 0"是唯一的哈希豁免值，这也正好等于"没有测量值"的语义。
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let mut canonical = serde_json::json!({
            "sequence": self.sequence,
            "tenant_id": self.tenant_id.to_string(),
            "session_id": self.session_id,
            "agent_id": self.agent_id.map(|v| v.to_string()),
            "intercept_point": self.intercept_point.as_str(),
            "tool_name": self.tool_name,
            "target": self.target,
            "policy_id": self.policy_id.map(|v| v.to_string()),
            "policy_name": self.policy_name,
            "blocklist_rules": self.blocklist_rules,
            "action": self.action.as_str(),
            "verdict": self.verdict.as_str(),
            "reason": self.reason,
            "request_excerpt": self.request_excerpt,
            "response_excerpt": self.response_excerpt,
            "enforced": self.enforced,
            "severity": self.severity.map(|s| s.as_str()),
            "approval_id": self.approval_id.map(|v| v.to_string()),
            "at": self.at.to_rfc3339(),
            "prev_hash": self.prev_hash,
        });
        if self.latency_micros > 0 {
            if let Some(object) = canonical.as_object_mut() {
                object.insert("latency_micros".to_string(), serde_json::Value::from(self.latency_micros));
            }
        }
        agf_core::secret::content_hash(&serde_json::to_string(&canonical).unwrap_or_default())
    }

    /// 依据当前字段重算 `entry_hash`。
    pub fn seal(&mut self) {
        self.entry_hash = self.compute_hash();
    }

    /// 本条记录的哈希是否自洽。
    #[must_use]
    pub fn verify(&self) -> bool {
        self.compute_hash() == self.entry_hash
    }

    /// 控制台摘要行（一行文本）。
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "#{} {} {} {} → {}（{}）",
            self.sequence,
            self.at.to_rfc3339(),
            self.intercept_point.as_str(),
            self.tool_name.as_deref().unwrap_or("-"),
            self.verdict.as_str(),
            self.reason
        )
    }

    /// 构造一条记录的骨架（`entry_hash` 由 [`InterceptionAuditLog::append`] 填充）。
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        session_id: &str,
        intercept_point: agf_core::enums::InterceptPoint,
        verdict: InterceptionVerdict,
        reason: &str,
    ) -> Self {
        Self {
            id: Id::new(),
            sequence: 0,
            tenant_id,
            session_id: session_id.to_string(),
            agent_id: None,
            intercept_point,
            tool_name: None,
            target: None,
            policy_id: None,
            policy_name: None,
            blocklist_rules: Vec::new(),
            action: PolicyAction::Allow,
            verdict,
            reason: reason.to_string(),
            request_excerpt: String::new(),
            response_excerpt: None,
            enforced: true,
            severity: None,
            approval_id: None,
            latency_micros: 0,
            prev_hash: GENESIS_HASH.to_string(),
            entry_hash: String::new(),
            at: Timestamp::now(),
        }
    }

    /// 由策略决策填充字段（`dry_run` 时 `enforced = false` 且处置降级为"仅审计"）。
    #[must_use]
    pub fn with_decision(mut self, decision: &PolicyDecision) -> Self {
        self.action = decision.action;
        self.policy_id = decision.policy_id;
        self.policy_name = decision.policy_name.clone();
        self.reason = decision.reason.clone();
        self.enforced = !decision.dry_run;
        self.verdict = if decision.dry_run {
            InterceptionVerdict::Audited
        } else if decision.redact && matches!(decision.action, PolicyAction::Allow) {
            InterceptionVerdict::ForwardedRedacted
        } else {
            InterceptionVerdict::from_action(decision.action, decision.dry_run)
        };
        self
    }

    /// 设置工具名。
    #[must_use]
    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.tool_name = Some(tool.into());
        self
    }

    /// 设置目标。
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// 设置请求摘要（调用方**必须**先脱敏）。
    #[must_use]
    pub fn with_excerpt(mut self, excerpt: impl Into<String>) -> Self {
        self.request_excerpt = excerpt.into();
        self
    }

    /// 设置响应摘要。
    #[must_use]
    pub fn with_response(mut self, excerpt: impl Into<String>) -> Self {
        self.response_excerpt = Some(excerpt.into());
        self
    }

    /// 设置"进入拦截处理 → 出决策"的耗时（微秒；**必须**是真实测量值，
    /// 未测量时保持 0 —— 0 会在 `/runtime/intercept-points` 的 p95 里如实体现为"无样本值"）。
    ///
    /// 典型用法：拦截入口处 `let started = std::time::Instant::now();`，
    /// 出决策写审计时 `.with_latency_micros(elapsed_micros(started))`。
    #[must_use]
    pub const fn with_latency_micros(mut self, latency_micros: u64) -> Self {
        self.latency_micros = latency_micros;
        self
    }
}

/// 已耗时（微秒，**向上取整**，饱和到 `u64`）。
///
/// 全 crate 共用的唯一计时口径：`Instant::now()` → 本函数，避免各处各写一份
/// （`policy.rs` 的 `eval_micros`、`mcp_proxy` 的拦截耗时同源）。
///
/// 为什么**向上取整**而不是截断：廉价路径（例如"MCP 非工具调用直接放行"）常常不足 1 微秒，
/// 按纳秒截断会得到 `0`——那样 `latency_micros == 0` 会同时意味着"未测量"和"非常快"，
/// p95 的样本口径与哈希豁免规则（0 是唯一豁免值）都会失去清晰语义。
/// 取整后：**任何真实发生过的耗时都 ≥ 1µs，`0` 唯一表示"未测量"**。
#[must_use]
pub(crate) fn elapsed_micros(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos().div_ceil(1_000)).unwrap_or(u64::MAX)
}

impl InterceptionChainReport {
    /// 问题摘要（单行，便于日志与告警）。
    #[must_use]
    pub fn summary(&self) -> String {
        if self.passed {
            format!("拦截审计链校验通过（{} 条）", self.checked)
        } else {
            format!(
                "拦截审计链校验失败（{} 条中 {} 处异常）：{}",
                self.checked,
                self.violations.len(),
                self.violations.iter().map(|v| format!("#{} {}", v.sequence, v.kind)).collect::<Vec<_>>().join(", ")
            )
        }
    }
}

impl ChainState {
    /// 初始状态（创世哈希）。
    pub(crate) fn new() -> Self {
        Self { entries: VecDeque::new(), total: 0, tail_hash: GENESIS_HASH.to_string(), truncated: false }
    }
}
