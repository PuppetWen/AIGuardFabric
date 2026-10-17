//! 由 `mcp_proxy.rs` 拆分：`McpProxy` 的实现（纯搬移，逻辑不变）。
use super::*;

impl McpProxy {
    /// 构造代理（最小集合：策略 + 黑名单 + 审计）。
    #[must_use]
    pub fn new(engine: PolicyEngine, blocklist: Blocklist, audit: std::sync::Arc<InterceptionAuditLog>) -> Self {
        Self {
            engine,
            blocklist: Mutex::new(blocklist),
            quotas: None,
            approvals: None,
            audit,
            redaction_mode: RedactionMode::default(),
            max_frame_bytes: JsonRpcFrame::DEFAULT_MAX_BYTES,
            intercepted_total: AtomicU64::new(0),
        }
    }
    /// 设置配额服务。
    #[must_use]
    pub fn with_quotas(mut self, quotas: QuotaService) -> Self {
        self.quotas = Some(quotas);
        self
    }
    /// 设置审批存储。
    #[must_use]
    pub fn with_approvals(mut self, approvals: std::sync::Arc<dyn crate::approval::ApprovalStore>) -> Self {
        self.approvals = Some(approvals);
        self
    }
    /// 设置脱敏模式（默认 [`RedactionMode::CredentialsAndPii`]）。
    #[must_use]
    pub const fn with_redaction_mode(mut self, mode: RedactionMode) -> Self {
        self.redaction_mode = mode;
        self
    }
    /// 设置帧大小上限。
    #[must_use]
    pub const fn with_max_frame_bytes(mut self, max: usize) -> Self {
        self.max_frame_bytes = max;
        self
    }
    /// 策略引擎引用。
    #[must_use]
    pub const fn engine(&self) -> &PolicyEngine {
        &self.engine
    }
    /// 审计链引用。
    #[must_use]
    pub fn audit(&self) -> &std::sync::Arc<InterceptionAuditLog> {
        &self.audit
    }
    /// 累计拦截调用数（含放行）。
    #[must_use]
    pub fn intercepted_total(&self) -> u64 {
        self.intercepted_total.load(Ordering::Relaxed)
    }
    /// 黑名单规则数。
    pub async fn blocklist_len(&self) -> usize {
        self.blocklist.lock().await.len()
    }
    /// 对一段原始 JSON-RPC 文本做入站拦截（`raw` 为单帧）。
    ///
    /// # Errors
    /// 帧非法（超出大小上限、JSON 错误、非 JSON-RPC 2.0）。
    pub async fn intercept_request_raw(&self, session: &McpProxySession, raw: &str) -> DomainResult<InterceptOutcome> {
        let frame = JsonRpcFrame::parse_with_limit(raw, self.max_frame_bytes)?;
        self.intercept_request(session, &frame).await
    }
    /// 入站拦截（请求方向）。
    ///
    /// 顺序：
    /// 1. 非 `tools/call` ⇒ 直接转发（MCP 握手/列表类方法不做工具级管控）；
    /// 2. 黑名单（**先于策略**：平台级最低防线不受租户策略影响）；
    /// 3. 策略引擎求值（内含黑名单否决权）；
    /// 4. 人工审批（在配额之前：待审批不应消耗配额）；
    /// 5. 配额（仅当策略/黑名单未拦下）；
    /// 6. 脱敏（`needs_redaction`）；
    /// 7. 写审计。
    ///
    /// **耗时埋点**：本函数第一行取 `Instant::now()`，7 个写审计的分支全部用
    /// `elapsed_micros(started)` 落 [`InterceptionRecord::latency_micros`]——
    /// 口径是"进入拦截处理 → 出决策"（含黑名单/策略求值/配额检查/脱敏改写与审计记录构造），
    /// **不含**上层网关的字节流读写与真实转发耗时（本模块不承载转发，见模块文档）。
    ///
    /// # Errors
    /// 策略后端求值失败（fail-closed 模式）、审批服务不可用等硬错误。
    pub async fn intercept_request(
        &self,
        session: &McpProxySession,
        frame: &JsonRpcFrame,
    ) -> DomainResult<InterceptOutcome> {
        // p95 时延的计时起点（**必须在函数第一行**：非工具调用的直接放行也要有真实耗时）
        let started = Instant::now();
        self.intercepted_total.fetch_add(1, Ordering::Relaxed);
        let tool = frame.tool_name().map(str::to_string);
        session.note_call(tool.as_deref()).await;

        // 1) 非工具调用直接放行（但仍写审计，保留完整调用链）
        if !frame.is_tool_call() {
            let record = base_record(session)
                .with_latency_micros(elapsed_micros(started))
                .with_target(frame.method_name())
                .with_excerpt(truncate(frame.method_name(), 256));
            let _ = self.audit.append(record);
            return Ok(InterceptOutcome::Forward);
        }

        let targets = frame.extract_targets();
        let ctx = Self::build_context(session, frame, &targets);

        // 2) 黑名单
        let hit: Option<RuleHit> = {
            let mut bl = self.blocklist.lock().await;
            bl.evaluate(&ctx)?
        };
        if let Some(h) = hit.as_ref() {
            if h.is_blocking() {
                session.note_blocked().await;
                let decision = PolicyDecision {
                    action: PolicyAction::Deny,
                    policy_id: None,
                    policy_name: None,
                    reason: format!("命中黑名单规则 {}：{}", h.rule_id, h.reason),
                    redact: false,
                    dry_run: false,
                    quota_id: None,
                    degrade_endpoint_id: None,
                    eval_micros: 0,
                };
                self.record(session, frame, &decision, Some(h), InterceptionVerdict::Blocked, elapsed_micros(started));
                return Ok(InterceptOutcome::Blocked { decision: Box::new(decision) });
            }
        }

        // 3) 策略
        let (decision, needs_redaction) = self.engine.evaluate_for_redaction(&ctx, hit.as_ref())?;
        if decision.is_blocking() {
            session.note_blocked().await;
            let verdict = InterceptionVerdict::from_action(decision.action, false);
            self.record(session, frame, &decision, hit.as_ref(), verdict, elapsed_micros(started));
            return Ok(InterceptOutcome::Blocked { decision: Box::new(decision) });
        }

        // 4) 审批
        if decision.needs_approval() {
            session.note_approval().await;
            let (id, link) = self.create_approval(session, frame, &decision).await?;
            self.record(
                session,
                frame,
                &decision,
                hit.as_ref(),
                InterceptionVerdict::PendingApproval,
                elapsed_micros(started),
            );
            return Ok(InterceptOutcome::NeedsApproval { id, link });
        }

        // 5) 配额
        if let Some(quotas) = &self.quotas {
            let consumption = QuotaConsumption::one_request();
            let outcome = quotas.check(session.tenant_id, session.agent_id, session.session_id(), &consumption).await?;
            if !outcome.allowed() {
                let action = outcome.check.action;
                let retry = outcome.check.retry_after_secs.unwrap_or(0);
                let reason = outcome.reason.clone().unwrap_or_else(|| {
                    format!(
                        "配额超限：{} / {} 已用 {} 超过上限 {}",
                        outcome.check.scope.map_or("-", |s| s.as_str()),
                        outcome.check.dimension.map_or("-", |d| d.as_str()),
                        outcome.check.used,
                        outcome.check.limit
                    )
                });
                let quota_decision = PolicyDecision {
                    action,
                    policy_id: outcome.check.exceeded_quota_id,
                    policy_name: None,
                    reason: reason.clone(),
                    redact: false,
                    dry_run: false,
                    quota_id: outcome.check.exceeded_quota_id,
                    degrade_endpoint_id: None,
                    eval_micros: 0,
                };
                session.note_blocked().await;
                let verdict = if matches!(action, PolicyAction::Degrade) {
                    InterceptionVerdict::Degraded
                } else if matches!(action, PolicyAction::Throttle) {
                    InterceptionVerdict::Throttled
                } else {
                    InterceptionVerdict::Blocked
                };
                self.record(session, frame, &quota_decision, hit.as_ref(), verdict, elapsed_micros(started));
                return Ok(match action {
                    PolicyAction::Degrade => InterceptOutcome::Degraded { reason },
                    PolicyAction::Throttle => InterceptOutcome::Throttled { retry_after: retry },
                    // Deny / Isolate 等"从严"动作必须按**阻断**返回：
                    // 把 `deny` 降级成"限速放行"等于绕过配额，属安全语义错误。
                    _ => InterceptOutcome::Blocked { decision: Box::new(quota_decision) },
                });
            }
            // 成功消费：登记并发持有，供 `finish` 归还
            session.hold_concurrency().await;
        }

        // 6) 脱敏改写
        if needs_redaction {
            let (payload, redactions) = self.redact_frame(frame);
            session.note_redacted().await;
            self.record(
                session,
                frame,
                &decision,
                hit.as_ref(),
                InterceptionVerdict::ForwardedRedacted,
                elapsed_micros(started),
            );
            return Ok(InterceptOutcome::ForwardRedacted { payload, redactions });
        }

        // 7) 放行 + 审计
        let verdict = InterceptionVerdict::from_action(decision.action, decision.dry_run);
        self.record(session, frame, &decision, hit.as_ref(), verdict, elapsed_micros(started));
        if !decision.dry_run && matches!(decision.action, PolicyAction::Degrade) {
            return Ok(InterceptOutcome::Degraded { reason: decision.reason });
        }
        Ok(InterceptOutcome::Forward)
    }
    /// 出站拦截（响应方向）：模型/工具输出可能在返回给 Agent 前泄露凭据，
    /// 因此**默认对响应体执行凭据脱敏**（[`RedactionMode`] 为 `None` 时跳过）。
    ///
    /// **耗时埋点**：与 [`Self::intercept_request`] 同口径（"进入拦截处理 → 出决策"），
    /// 用于出站改写同样进入 `/runtime/intercept-points` 的 p95 样本集。
    ///
    /// # Errors
    /// 传入的不是响应帧。
    pub async fn intercept_response(
        &self,
        session: &McpProxySession,
        frame: &JsonRpcFrame,
    ) -> DomainResult<InterceptOutcome> {
        let started = Instant::now();
        if !frame.is_response() {
            return Err(DomainError::Validation("出站拦截只接受 JSON-RPC 响应帧".to_string()));
        }
        // 错误消息也可能包含密钥和原始请求，执行与正常结果相同的脱敏。
        let Some(result) = frame.error.clone().or_else(|| frame.result.clone()) else {
            return Ok(InterceptOutcome::Forward);
        };
        let mut map = RedactionMap::new();
        let redacted = redact_json(&result, self.redaction_mode, &mut map);
        if map.is_empty() && redacted == result {
            let record = base_record(session)
                .with_latency_micros(elapsed_micros(started))
                .with_response(truncate(&result.to_string(), 512));
            let _ = self.audit.append(record);
            return Ok(InterceptOutcome::Forward);
        }
        let count = map.len();
        let mut new_frame = frame.clone();
        if frame.error.is_some() {
            new_frame.error = Some(redacted.clone());
        } else {
            new_frame.result = Some(redacted.clone());
        }
        let payload = new_frame.to_line()?;
        session.note_redacted().await;
        let decision = PolicyDecision {
            action: PolicyAction::Redact,
            policy_id: None,
            policy_name: None,
            reason: format!("出站脱敏：替换 {count} 处敏感内容"),
            redact: true,
            dry_run: false,
            quota_id: None,
            degrade_endpoint_id: None,
            eval_micros: 0,
        };
        self.record_with_verdict(
            session,
            &decision,
            InterceptionVerdict::ForwardedRedacted,
            Some(truncate(&result.to_string(), 512)),
            Some(truncate(&redacted.to_string(), 512)),
            elapsed_micros(started),
        );
        Ok(InterceptOutcome::ForwardRedacted { payload, redactions: count })
    }
    /// 对一段原始响应文本做脱敏（便捷入口，内部做帧解析）。
    ///
    /// # Errors
    /// 帧非法。
    pub async fn intercept_response_raw(&self, session: &McpProxySession, raw: &str) -> DomainResult<InterceptOutcome> {
        let frame = JsonRpcFrame::parse_with_limit(raw, self.max_frame_bytes)?;
        self.intercept_response(session, &frame).await
    }
    /// 对纯文本做脱敏（用于非 JSON 的 SSE `data:` 负载、stdio 的日志流）。
    #[must_use]
    pub fn redact_text_payload(&self, text: &str) -> (String, usize) {
        let mut map = RedactionMap::new();
        let out: RedactOutcome = redact_text(text, self.redaction_mode, &mut map);
        (out.text, map.len())
    }
    /// 由帧构造 [`PolicyContext`]。
    ///
    /// 纯函数（不读 `self`）：上下文只取决于会话、帧与已抽取的目标，
    /// 这样它可以在不持有代理实例的场景（离线回放、单测）里直接复用。
    pub(crate) fn build_context(
        session: &McpProxySession,
        frame: &JsonRpcFrame,
        targets: &FrameTargets,
    ) -> PolicyContext {
        let args = frame.arguments();
        let payload_bytes = serde_json::to_vec(&args).map(|v| u64::try_from(v.len()).unwrap_or(u64::MAX)).unwrap_or(0);
        PolicyContext {
            tenant_id: session.tenant_id,
            session_id: session.session_id().to_string(),
            agent_id: session.agent_id,
            department: session.context.as_ref().and_then(|ctx| ctx.department.clone()),
            intercept_point: session.intercept_point(),
            tool_name: frame.tool_name().map(str::to_string),
            path: targets.path.clone(),
            domain: targets.domain.clone(),
            command: targets.command.clone(),
            payload: args,
            payload_bytes,
            risk_domains: session.context.as_ref().map(|ctx| ctx.risk_domains.clone()).unwrap_or_default(),
            max_severity: session.context.as_ref().and_then(|ctx| ctx.max_severity),
            data_class: session.context.as_ref().map_or(agf_core::enums::DataClass::Internal, |ctx| ctx.data_class),
            now: Timestamp::now(),
        }
    }
    /// 脱敏改写一整帧：对 `params.arguments` 递归脱敏后重新序列化。
    pub(crate) fn redact_frame(&self, frame: &JsonRpcFrame) -> (String, usize) {
        let mut map = RedactionMap::new();
        let args = frame.arguments();
        let redacted = redact_json(&args, self.redaction_mode, &mut map);
        let mut params = frame.params.clone().unwrap_or_else(|| serde_json::json!({}));
        if let Some(obj) = params.as_object_mut() {
            obj.insert("arguments".to_string(), redacted);
        }
        let new_frame = frame.clone().with_params(params);
        (new_frame.to_line().unwrap_or_default(), map.len())
    }
}
