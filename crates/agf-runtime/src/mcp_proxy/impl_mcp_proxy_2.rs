//! 由 `mcp_proxy.rs` 拆分：`impl_McpProxy`/`base_record` 等 5 项（纯搬移，逻辑不变）。
use super::*;

impl McpProxy {
    /// 创建审批单，返回 `(id, 控制台链接)`。
    ///
    /// 审批存储不可用时**按"未通过"处理**（fail-closed），返回
    /// [`DomainError::DependencyUnavailable`]，绝不静默放行。
    pub(crate) async fn create_approval(
        &self,
        session: &McpProxySession,
        frame: &JsonRpcFrame,
        decision: &PolicyDecision,
    ) -> DomainResult<(Id, String)> {
        let Some(store) = &self.approvals else {
            return Err(DomainError::DependencyUnavailable {
                dependency: "approval-store".to_string(),
                cause: "策略要求人工审批，但未配置审批存储（按未通过处理）".to_string(),
            });
        };
        let targets = frame.extract_targets();
        let target = frame.tool_name().unwrap_or("unknown").to_string();
        let excerpt = truncate(
            &targets
                .command
                .clone()
                .or_else(|| targets.domain.clone())
                .or_else(|| targets.path.clone())
                .unwrap_or_else(|| frame.arguments().to_string()),
            256,
        );
        let (excerpt, _) = self.redact_text_payload(&excerpt);
        let mut record = crate::approval::build_request(
            session.tenant_id,
            session.session_id(),
            session.agent_id,
            session.intercept_point(),
            &target,
            decision.action.as_str(),
            &decision.reason,
            &excerpt,
            crate::approval::DEFAULT_TTL_SECS,
        );
        record.policy_id = decision.policy_id;
        record.policy_name = decision.policy_name.clone();
        let link = record.console_link();
        match store.create(record).await {
            Ok(created) => Ok((created.request.id, link)),
            Err(e) => Err(e.into()),
        }
    }
    /// 写审计（决策路径）。
    ///
    /// `latency_micros` 由调用方用 [`elapsed_micros`] 从**拦截入口**计时得出
    /// （本函数内部再取 `Instant::now()` 只能测到"构造记录"这一段，不是决策耗时）。
    pub(crate) fn record(
        &self,
        session: &McpProxySession,
        frame: &JsonRpcFrame,
        decision: &PolicyDecision,
        hit: Option<&RuleHit>,
        verdict: InterceptionVerdict,
        latency_micros: u64,
    ) {
        let targets = frame.extract_targets();
        let target = targets
            .command
            .clone()
            .or_else(|| targets.domain.clone())
            .or_else(|| targets.path.clone())
            .unwrap_or_else(|| frame.method_name().to_string());
        let excerpt = truncate(&frame.arguments().to_string(), 512);
        let (excerpt, _) = self.redact_text_payload(&excerpt);
        let (target, _) = self.redact_text_payload(&target);
        let mut record = base_record(session)
            .with_decision(decision)
            .with_latency_micros(latency_micros)
            .with_target(target)
            .with_excerpt(excerpt);
        record.tool_name = frame.tool_name().map(str::to_owned);
        record.verdict = verdict;
        if let Some(h) = hit {
            record.blocklist_rules.push(h.rule_id.clone());
            record.severity = Some(h.severity);
        }
        let _ = self.audit.append(record);
    }
    /// 写审计（自定义处置与摘要，出站脱敏路径使用）。
    ///
    /// `latency_micros` 口径同 [`Self::record`]。
    pub(crate) fn record_with_verdict(
        &self,
        session: &McpProxySession,
        decision: &PolicyDecision,
        verdict: InterceptionVerdict,
        request_excerpt: Option<String>,
        response_excerpt: Option<String>,
        latency_micros: u64,
    ) {
        let mut record = base_record(session).with_decision(decision).with_latency_micros(latency_micros);
        record.verdict = verdict;
        if let Some(r) = request_excerpt {
            record.request_excerpt = self.redact_text_payload(&r).0;
        }
        if let Some(r) = response_excerpt {
            record.response_excerpt = Some(self.redact_text_payload(&r).0);
        }
        let _ = self.audit.append(record);
    }
    /// 构造 [`McpInvocation`] 审计条目（`agf_core::mcp` 模型，供落库）。
    #[must_use]
    pub fn invocation_of(
        &self,
        session: &McpProxySession,
        frame: &JsonRpcFrame,
        decision: &PolicyDecision,
        latency_ms: u64,
    ) -> McpInvocation {
        McpInvocation {
            id: Id::new(),
            tenant_id: session.tenant_id,
            session_id: session.session_id().to_string(),
            agent_id: session.agent_id,
            mcp_server_id: session.mcp_server_id(),
            tool_name: frame.tool_name().unwrap_or("unknown").to_string(),
            arguments: frame.arguments(),
            result_excerpt: None,
            action: decision.action,
            policy_id: decision.policy_id,
            blocked: decision.is_blocking(),
            latency_ms,
            at: Timestamp::now(),
        }
    }
}

/// 构造审计记录骨架（填充会话与拦截点）。
pub(crate) fn base_record(session: &McpProxySession) -> InterceptionRecord {
    let mut record = InterceptionRecord::new(
        session.tenant_id,
        session.session_id(),
        session.intercept_point(),
        InterceptionVerdict::Forwarded,
        "",
    );
    record.agent_id = session.agent_id;
    record
}

/// 截断文本（按字符数，避免在多字节字符中间切断）。
pub(crate) fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push('…');
    out
}

/// 便捷：构造一个只做黑名单与策略判定的代理（测试与离线演示）。
#[must_use]
pub fn offline_proxy(engine: PolicyEngine, blocklist: Blocklist) -> McpProxy {
    McpProxy::new(engine, blocklist, std::sync::Arc::new(InterceptionAuditLog::new()))
}

/// 便捷：默认签名器（开发用）。
#[must_use]
pub fn dev_signer() -> PolicySigner {
    PolicySigner::dev_default()
}
