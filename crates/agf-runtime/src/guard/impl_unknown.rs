//! 由 `guard.rs` 拆分：`unknown` 的实现（纯搬移，逻辑不变）。
use super::*;

impl<'a> SelfCheck<'a> {
    /// 构造自检器（最小集合）。
    #[must_use]
    pub const fn new(
        engine: &'a PolicyEngine,
        blocklist: &'a Blocklist,
        audit: &'a InterceptionAuditLog,
        config: &'a EngineConfig,
        tenant_id: TenantId,
    ) -> Self {
        Self { engine, blocklist, audit, quotas: None, approvals: None, heartbeats: None, config, tenant_id }
    }

    /// 附加配额服务。
    #[must_use]
    pub const fn with_quotas(mut self, quotas: &'a QuotaService) -> Self {
        self.quotas = Some(quotas);
        self
    }

    /// 附加审批存储。
    #[must_use]
    pub fn with_approvals(mut self, approvals: &'a dyn crate::approval::ApprovalStore) -> Self {
        self.approvals = Some(approvals);
        self
    }

    /// 附加心跳监控。
    #[must_use]
    pub const fn with_heartbeats(mut self, heartbeats: &'a HeartbeatMonitor) -> Self {
        self.heartbeats = Some(heartbeats);
        self
    }

    /// 执行全部自检。
    #[must_use]
    pub fn run(&self) -> GuardReport {
        let mut report = self.run_inner();
        // 报告归属租户（多租户控制台按此路由；自检结论本身是租户无关的）
        report.tenant_id = Some(self.tenant_id);
        report
    }

    /// 自检主体。
    pub(crate) fn run_inner(&self) -> GuardReport {
        let mut items: Vec<GuardItem> = vec![
            self.check_signature_mode(),
            self.check_unsigned_policies(),
            self.check_signature_state(),
            self.check_dev_key(),
            self.check_all_dry_run(),
            self.check_has_blocking(),
            self.check_intercept_points(),
            self.check_blocklist(),
            self.check_audit_chain(),
            self.check_audit_complete(),
            self.check_eval_error_mode(),
        ];
        if let Some(q) = self.quotas {
            items.push(Self::check_quota(q));
        }
        if let Some(a) = self.approvals {
            items.push(Self::check_approval(a));
        }
        if let Some(h) = self.heartbeats {
            items.push(Self::check_heartbeat_enrolled(h));
            items.push(Self::check_heartbeat_alive(h));
        }
        let alerts = self.heartbeats.map(HeartbeatMonitor::alerts).unwrap_or_default();
        GuardReport::build(items, alerts, self.engine.len(), self.blocklist.len(), self.audit.total())
    }

    /// 项：签名模式必须是 Enforce。
    pub(crate) fn check_signature_mode(&self) -> GuardItem {
        match self.engine.signature_mode() {
            SignatureMode::Enforce => {
                GuardItem::pass(keys::POLICY_SIGNATURE_MODE, "策略签名强制校验", "签名模式为 enforce（生产默认）")
            }
            SignatureMode::Warn => GuardItem::fail(
                keys::POLICY_SIGNATURE_MODE,
                "策略签名强制校验",
                "签名模式为 warn：未签名/被篡改的策略仍会生效，生产环境必须改为 enforce",
            ),
            SignatureMode::Disabled => GuardItem::fail(
                keys::POLICY_SIGNATURE_MODE,
                "策略签名强制校验",
                "签名校验被完全关闭：被管 Agent 可直接改写本地策略绕过管控，仅可用于离线演示",
            ),
        }
    }

    /// 项：不存在未签名/签名非法的策略。
    pub(crate) fn check_unsigned_policies(&self) -> GuardItem {
        let rejected = self.engine.rejected().len();
        let warnings = self.engine.signature_warnings().len();
        if rejected == 0 && warnings == 0 {
            return GuardItem::pass(keys::POLICY_UNSIGNED, "无未签名策略", "全部生效策略签名有效");
        }
        GuardItem::fail(
            keys::POLICY_UNSIGNED,
            "无未签名策略",
            format!(
                "{rejected} 条策略因签名问题被拒绝装载，{warnings} 条签名告警；\
                 请重新签名下发（原因：{}）",
                self.engine
                    .rejected()
                    .first()
                    .map(|(n, r)| format!("{n}: {r}"))
                    .or_else(|| self.engine.signature_warnings().first().cloned())
                    .unwrap_or_else(|| "-".to_string())
            ),
        )
    }

    /// 项：已配置签名密钥且能校验生效策略。
    pub(crate) fn check_signature_state(&self) -> GuardItem {
        if self.engine.signer().is_none() {
            return GuardItem::fail(
                keys::POLICY_SIGNATURE,
                "策略签名密钥已配置",
                "引擎未配置策略签名密钥，Enforce 模式下所有策略都会被拒绝装载",
            );
        }
        GuardItem::pass(keys::POLICY_SIGNATURE, "策略签名密钥已配置", "已配置主密钥并可校验策略签名")
    }

    /// 项：签名密钥不是开发默认值。
    pub(crate) fn check_dev_key(&self) -> GuardItem {
        match self.engine.signer() {
            Some(s) if s.is_dev_key() => GuardItem::fail(
                keys::POLICY_DEV_KEY,
                "签名密钥已轮换",
                "当前使用开发默认签名密钥（dev-default）：任何拿到源码的人都能伪造策略签名",
            ),
            Some(_) => GuardItem::pass(keys::POLICY_DEV_KEY, "签名密钥已轮换", "签名密钥标识非开发默认值"),
            None => GuardItem::warn(keys::POLICY_DEV_KEY, "签名密钥已轮换", "未配置签名密钥，无法判定"),
        }
    }

    /// 项：不是"全部策略都 dry-run"。
    pub(crate) fn check_all_dry_run(&self) -> GuardItem {
        if self.engine.is_empty() {
            return GuardItem::warn(
                keys::POLICY_ALL_DRY_RUN,
                "存在非 dry-run 策略",
                "策略表为空：拦截完全依赖黑名单兜底，建议至少下发一条阻断策略",
            );
        }
        if self.engine.all_dry_run() {
            return GuardItem::fail(
                keys::POLICY_ALL_DRY_RUN,
                "存在非 dry-run 策略",
                format!("{} 条策略全部为 dry-run：只记录不拦截，等于没有策略防护", self.engine.len()),
            );
        }
        GuardItem::pass(
            keys::POLICY_ALL_DRY_RUN,
            "存在非 dry-run 策略",
            format!("{} 条策略中至少一条为实际拦截", self.engine.len()),
        )
    }

    /// 项：至少有一条会产生拦截效果的策略。
    pub(crate) fn check_has_blocking(&self) -> GuardItem {
        let blocking = self
            .engine
            .policies()
            .iter()
            .filter(|p| {
                !p.dry_run
                    && matches!(
                        p.action,
                        PolicyAction::Deny
                            | PolicyAction::Isolate
                            | PolicyAction::CircuitBreak
                            | PolicyAction::Approval
                    )
            })
            .count();
        if blocking > 0 {
            return GuardItem::pass(
                keys::POLICY_HAS_BLOCKING,
                "存在阻断类策略",
                format!("{blocking} 条策略会产生阻断/隔离/审批效果"),
            );
        }
        GuardItem::warn(
            keys::POLICY_HAS_BLOCKING,
            "存在阻断类策略",
            "没有任何非 dry-run 的阻断类策略：放行/审计/脱敏策略不会阻止危险调用",
        )
    }

    /// 项：三个拦截点（MCP 代理 / AI 网关 / 进程 Hook）都配置了策略。
    pub(crate) fn check_intercept_points(&self) -> GuardItem {
        let required = self.config.required_intercept_points();
        let configured = self.engine.configured_intercept_points();
        let missing: Vec<&str> =
            required.iter().filter(|p| !configured.contains(p)).map(InterceptPoint::as_str).collect();
        if missing.is_empty() {
            return GuardItem::pass(
                keys::INTERCEPT_POINTS,
                "三个拦截点均已配置",
                format!(
                    "已覆盖全部 {} 个拦截点：{}",
                    required.len(),
                    required.iter().map(InterceptPoint::as_str).collect::<Vec<_>>().join(", ")
                ),
            );
        }
        GuardItem::fail(
            keys::INTERCEPT_POINTS,
            "三个拦截点均已配置",
            format!(
                "以下拦截点没有任何策略覆盖：{}（未覆盖的拦截点等于不设防）；\
                 请在策略中声明 intercept_points",
                missing.join(", ")
            ),
        )
    }

    /// 项：黑名单非空。
    pub(crate) fn check_blocklist(&self) -> GuardItem {
        if self.blocklist.is_empty() {
            return GuardItem::fail(
                keys::BLOCKLIST_NON_EMPTY,
                "黑名单非空",
                "黑名单为空：平台级最低防线失效，危险命令/高危域名不再被兜底拦截",
            );
        }
        GuardItem::pass(
            keys::BLOCKLIST_NON_EMPTY,
            "黑名单非空",
            format!(
                "已加载 {} 条规则（命令 {} / 域名 {} / 路径 {} / 工具 {} / 哈希 {}），累计求值 {} 次",
                self.blocklist.len(),
                self.blocklist.stats().by_kind.get("command").copied().unwrap_or(0),
                self.blocklist.stats().by_kind.get("domain").copied().unwrap_or(0),
                self.blocklist.stats().by_kind.get("path").copied().unwrap_or(0),
                self.blocklist.stats().by_kind.get("tool").copied().unwrap_or(0),
                self.blocklist.stats().by_kind.get("hash").copied().unwrap_or(0),
                self.blocklist.stats().evaluations,
            ),
        )
    }

    /// 项：拦截审计链校验通过。
    pub(crate) fn check_audit_chain(&self) -> GuardItem {
        let report = self.audit.verify();
        if report.passed {
            return GuardItem::pass(
                keys::AUDIT_CHAIN,
                "审计哈希链完整",
                format!("{} 条记录校验通过，链尾 {}", report.checked, report.tail_hash.as_deref().unwrap_or("-")),
            );
        }
        GuardItem::fail(
            keys::AUDIT_CHAIN,
            "审计哈希链完整",
            format!("审计链校验失败（疑似被篡改）：{}", report.summary()),
        )
    }

    /// 项：审计链未被截断（缓冲未滚出）。
    pub(crate) fn check_audit_complete(&self) -> GuardItem {
        if self.audit.is_truncated() {
            return GuardItem::warn(
                keys::AUDIT_COMPLETE,
                "审计记录未滚出缓冲",
                format!(
                    "内存审计缓冲已滚出（累计 {} 条，仅保留最近 {} 条）：\
                     请接入持久化存储，否则早期证据会丢失",
                    self.audit.total(),
                    self.audit.len()
                ),
            );
        }
        GuardItem::pass(
            keys::AUDIT_COMPLETE,
            "审计记录未滚出缓冲",
            format!("累计 {} 条记录全部在缓冲内，链完整可校验", self.audit.total()),
        )
    }

    /// 项：后端求值失败是 fail-closed。
    pub(crate) fn check_eval_error_mode(&self) -> GuardItem {
        match self.engine.eval_error_mode() {
            crate::policy::EvalErrorMode::FailClosed => GuardItem::pass(
                keys::EVAL_ERROR_MODE,
                "策略求值失败时拒绝请求",
                "fail-closed（默认）：策略不可判定时宁可少服务不可放过",
            ),
            crate::policy::EvalErrorMode::FailOpen => GuardItem::warn(
                keys::EVAL_ERROR_MODE,
                "策略求值失败时拒绝请求",
                "fail-open：策略求值出错时请求会被放行，仅建议灰度期使用",
            ),
        }
    }

    /// 项：配额服务未降级。
    pub(crate) fn check_quota(quotas: &QuotaService) -> GuardItem {
        if quotas.store().is_degraded() {
            return GuardItem::warn(
                keys::QUOTA_DEGRADED,
                "配额服务未降级",
                "配额计数存储处于降级状态：Deny 维度会 fail-closed 拒绝，计量维度会放行但计数不准",
            );
        }
        GuardItem::pass(
            keys::QUOTA_DEGRADED,
            "配额服务未降级",
            format!("已加载 {} 条配额，计数存储可用", quotas.quotas().len()),
        )
    }

    /// 项：审批服务可用。
    pub(crate) fn check_approval(approvals: &dyn crate::approval::ApprovalStore) -> GuardItem {
        if approvals.is_available() {
            return GuardItem::pass(
                keys::APPROVAL_AVAILABLE,
                "审批服务可用",
                "审批存储可用，待审批调用会被拒绝而非放行",
            );
        }
        GuardItem::fail(
            keys::APPROVAL_AVAILABLE,
            "审批服务可用",
            "审批存储不可用：要求人工审批的调用会被 fail-closed 拒绝，业务可能中断",
        )
    }

    /// 项：已纳管端点。
    pub(crate) fn check_heartbeat_enrolled(heartbeats: &HeartbeatMonitor) -> GuardItem {
        if heartbeats.is_empty() {
            return GuardItem::warn(
                keys::HEARTBEAT_ENROLLED,
                "已纳管 Agent/代理端点",
                "没有任何端点注册心跳：无法发现「代理被结束」这类绕过行为",
            );
        }
        GuardItem::pass(
            keys::HEARTBEAT_ENROLLED,
            "已纳管 Agent/代理端点",
            format!("已纳管 {} 个端点（存活 {}）", heartbeats.len(), heartbeats.alive_count()),
        )
    }

    /// 项：全部端点心跳正常。
    pub(crate) fn check_heartbeat_alive(heartbeats: &HeartbeatMonitor) -> GuardItem {
        let alerts = heartbeats.alerts();
        if alerts.is_empty() {
            return GuardItem::pass(
                keys::HEARTBEAT,
                "被管端点心跳正常",
                format!("{} 个端点全部心跳正常", heartbeats.len()),
            );
        }
        GuardItem::fail(
            keys::HEARTBEAT,
            "被管端点心跳正常",
            format!(
                "{} 个端点心跳丢失达阈值：{}；建议核查代理进程是否被结束",
                alerts.len(),
                alerts
                    .iter()
                    .map(|a| format!("{}（丢失 {} 次）", a.endpoint_id, a.missed))
                    .collect::<Vec<_>>()
                    .join("、")
            ),
        )
    }
}
