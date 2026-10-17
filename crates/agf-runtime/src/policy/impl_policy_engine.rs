//! 由 `policy.rs` 拆分：`PolicyEngine` 的实现（纯搬移，逻辑不变）。
use super::*;

impl PolicyEngine {
    /// 求值主逻辑：返回 `(决策, 实际参与评估的策略条数)`。
    pub(crate) fn evaluate_inner(
        &self,
        ctx: &PolicyContext,
        hit: Option<&crate::blocklist::RuleHit>,
    ) -> DomainResult<(PolicyDecision, usize)> {
        let started = Instant::now();
        let hit_json = crate::blocklist::Blocklist::hit_json(&hit.cloned());
        let mut evaluated = 0_usize;

        for policy in &self.policies {
            if !policy.applies_to(ctx.agent_id.as_ref(), ctx.department.as_deref()) {
                continue;
            }
            // 未覆盖当前拦截点的策略不参与该点的评估（§4.3 三拦截点可分治）。
            if !policy.intercept_points.is_empty() && !policy.intercept_points.contains(&ctx.intercept_point) {
                continue;
            }
            evaluated += 1;
            let structured = matches!(policy.language, PolicyLanguage::Structured);
            let outcome = match policy.language {
                PolicyLanguage::Structured => Self::evaluate_structured(policy, ctx).map(|hit| StructuredOutcome {
                    hit,
                    action: None,
                    reason: None,
                    redact: false,
                }),
                PolicyLanguage::Rego => match RegoBackend::compile(policy)
                    .and_then(|b| b.evaluate(ctx, Some(&hit_json)))
                {
                    Ok(o) => Ok(StructuredOutcome { hit: o.hit, action: o.action, reason: o.reason, redact: o.redact }),
                    Err(e) => Err(e),
                },
                PolicyLanguage::Cel => match CelBackend::compile(policy).and_then(|b| b.evaluate(ctx, Some(&hit_json)))
                {
                    Ok(o) => Ok(StructuredOutcome { hit: o.hit, action: o.action, reason: o.reason, redact: o.redact }),
                    Err(e) => Err(e),
                },
            };
            let outcome = match outcome {
                Ok(o) => o,
                // `Structured` 的求值错误只可能是**配置错误**（如 `command_deny` 里的正则非法），
                // 必须原样抛给调用方去修策略，而不是被降级成 PolicyDenied/放行——
                // 否则排障时只能看到"被拒"，看不到真正的原因。
                // Rego/CEL 的**运行期**求值失败仍走 [`EvalErrorMode`]（见下）。
                Err(e) if structured => return Err(e),
                Err(e) => match self.eval_error_mode {
                    EvalErrorMode::FailClosed => {
                        return Err(DomainError::PolicyDenied {
                            policy: policy.name.clone(),
                            action: PolicyAction::Deny.as_str().to_string(),
                            reason: format!(
                                "策略求值失败且当前为 fail-closed（{}）：{e}",
                                self.eval_error_mode.as_str()
                            ),
                        });
                    }
                    EvalErrorMode::FailOpen => {
                        warn!(policy = %policy.name, error = %e, "策略求值失败，按 fail-open 放行");
                        continue;
                    }
                },
            };
            if !outcome.hit {
                continue;
            }
            let action = outcome.action.unwrap_or(policy.action);
            let reason = outcome.reason.clone().filter(|r| !r.trim().is_empty()).unwrap_or_else(|| {
                if policy.description.trim().is_empty() {
                    format!("命中策略「{}」", policy.name)
                } else {
                    policy.description.clone()
                }
            });
            let reason = match (self.hit_source, hit) {
                (HitSource::Annotate, Some(i)) if i.is_blocking() => {
                    format!("{reason}（黑名单 {}：{}）", i.rule_id, i.reason)
                }
                _ => reason,
            };
            let mut decision = PolicyDecision {
                action,
                policy_id: Some(policy.id),
                policy_name: Some(policy.name.clone()),
                reason,
                redact: outcome.redact || matches!(action, PolicyAction::Redact),
                dry_run: policy.dry_run,
                quota_id: policy.quota_id,
                degrade_endpoint_id: policy.degrade_endpoint_id,
                eval_micros: crate::audit::elapsed_micros(started),
            };
            // §4.3 动作：脱敏类动作隐含"需要脱敏"
            if matches!(action, PolicyAction::Redact) {
                decision.redact = true;
            }
            // 黑名单否决权：策略放行/仅审计时，黑名单的 Deny 命中仍会升级为阻断。
            // 例外：`HitSource::Off`（显式拆防线，自检 FAIL）与策略 dry-run
            // （"不拦截"是显式的运营意图，且 dry-run 会被审计记录）。
            if let Some(i) = hit {
                if i.is_blocking()
                    && !self.hit_source.is_unsafe()
                    && !policy.dry_run
                    && !matches!(decision.action, PolicyAction::Deny | PolicyAction::Isolate)
                {
                    decision.action = PolicyAction::Deny;
                    decision.reason = format!("{}；同时命中黑名单规则 {}：{}", decision.reason, i.rule_id, i.reason);
                }
            }
            debug!(
                policy = %policy.name,
                action = decision.action.as_str(),
                dry_run = policy.dry_run,
                "策略命中"
            );
            return Ok((decision, evaluated));
        }

        // 无策略命中时的黑名单参与：
        // - `PolicyFirst` / `FallbackDeny`：Deny 命中即兜底拒绝（保证空策略表下最低防线仍在）；
        // - `Annotate`：不拦，但把命中写进原因（决策仍为 Allow + dry_run，供"只看不拦"灰度使用）；
        // - `Off`：完全不参与（自检 FAIL 的危险取值）。
        if let Some(i) = hit {
            if i.is_blocking() && !self.hit_source.is_unsafe() {
                let decision = match self.hit_source {
                    HitSource::Annotate => PolicyDecision {
                        action: PolicyAction::Allow,
                        policy_id: None,
                        policy_name: None,
                        reason: format!(
                            "{}（{} 模式下仅注记：命中黑名单 {}：{}）",
                            crate::NO_POLICY_MATCHED_REASON,
                            self.hit_source.as_str(),
                            i.rule_id,
                            i.reason
                        ),
                        redact: false,
                        dry_run: true,
                        quota_id: None,
                        degrade_endpoint_id: None,
                        eval_micros: crate::audit::elapsed_micros(started),
                    },
                    _ => PolicyDecision {
                        action: PolicyAction::Deny,
                        policy_id: None,
                        policy_name: None,
                        reason: format!("命中黑名单规则 {}：{}", i.rule_id, i.reason),
                        redact: false,
                        dry_run: false,
                        quota_id: None,
                        degrade_endpoint_id: None,
                        eval_micros: crate::audit::elapsed_micros(started),
                    },
                };
                return Ok((decision, evaluated));
            }
        }

        // 无命中（默认放行）也要带上真实求值耗时：`eval_micros` 是"评估耗时"字段，
        // 放行路径不填会让 `/runtime/intercept-points` 的 p95 样本把放行决策记成 0µs
        // （`PolicyDecision::allow` 的默认值是 0，见 `agf_core::policy`）。
        let mut allow = PolicyDecision::allow(crate::NO_POLICY_MATCHED_REASON);
        allow.eval_micros = crate::audit::elapsed_micros(started);
        Ok((allow, evaluated))
    }
    /// 求值并返回命中详情（排障/审计用；不改变决策语义）。
    ///
    /// # Errors
    /// 同 [`Self::evaluate`]。
    pub fn evaluate_detailed(
        &self,
        ctx: &PolicyContext,
        hit: Option<&crate::blocklist::RuleHit>,
    ) -> DomainResult<(PolicyDecision, PolicyMatch)> {
        let (decision, evaluated) = self.evaluate_inner(ctx, hit)?;
        let detail = PolicyMatch {
            policy_id: decision.policy_id,
            policy_name: decision.policy_name.clone(),
            backend_reason: Some(decision.reason.clone()),
            backend_action: Some(decision.action),
            backend_redact: decision.redact,
            blocklist_hit: hit.is_some_and(crate::blocklist::RuleHit::is_blocking),
            evaluated,
        };
        Ok((decision, detail))
    }
    /// `Structured` 条件求值：声明过的条件**全部**命中才返回 `true`（AND 语义）。
    ///
    /// 三条关键语义（均有单测）：
    /// - **空条件集恒真** ⇒ 条件全空的策略在其作用域内全量命中；
    /// - 上下文缺少某条件所需字段 ⇒ 该条件不成立（不命中，不误拦）；
    /// - `require_approval` 单独声明（无其它条件）时**不**命中——它表达的是
    ///   "在其它条件成立的前提下要求审批"，而不是"所有请求都要审批"。
    ///
    /// # Errors
    /// 命令黑名单正则非法（配置错误；`StructuredCondition.command_deny` 中的 `re:` 模式）。
    pub(crate) fn evaluate_structured(policy: &Policy, ctx: &PolicyContext) -> DomainResult<bool> {
        let c: &StructuredCondition = &policy.structured;
        let mut declared = 0_usize;
        let mut matched = 0_usize;

        // 1) 工具白名单
        if !c.tool_allowlist.is_empty() {
            declared += 1;
            if ctx.tool_name.as_deref().is_some_and(|t| c.tool_allowlist.iter().any(|p| pattern_matches(p, t))) {
                matched += 1;
            }
        }
        // 2) 工具黑名单
        if !c.tool_denylist.is_empty() {
            declared += 1;
            if ctx.tool_name.as_deref().is_some_and(|t| c.tool_denylist.iter().any(|p| pattern_matches(p, t))) {
                matched += 1;
            }
        }
        // 3) 域名黑名单
        if !c.domain_denylist.is_empty() {
            declared += 1;
            if ctx.domain.as_deref().is_some_and(|d| c.domain_denylist.iter().any(|p| domain_matches(p, d))) {
                matched += 1;
            }
        }
        // 4) 域名白名单
        if !c.domain_allowlist.is_empty() {
            declared += 1;
            if ctx.domain.as_deref().is_some_and(|d| c.domain_allowlist.iter().any(|p| domain_matches(p, d))) {
                matched += 1;
            }
        }
        // 5) 路径黑名单
        if !c.path_denylist.is_empty() {
            declared += 1;
            if ctx.path.as_deref().is_some_and(|p| c.path_denylist.iter().any(|pat| path_matches_prefix(pat, p))) {
                matched += 1;
            }
        }
        // 6) 路径白名单
        if !c.path_allowlist.is_empty() {
            declared += 1;
            if ctx.path.as_deref().is_some_and(|p| c.path_allowlist.iter().any(|pat| path_matches_prefix(pat, p))) {
                matched += 1;
            }
        }
        // 7) 命令黑名单（复用 agf-core 的子串/正则实现）
        if !c.command_deny.is_empty() {
            declared += 1;
            if let Some(command) = ctx.command.as_deref() {
                for pattern in &c.command_deny {
                    let hit = command_matches_deny(pattern, command)
                        .map_err(|e| DomainError::Parse(format!("策略「{}」命令黑名单配置错误：{e}", policy.name)))?;
                    if hit {
                        matched += 1;
                        break;
                    }
                }
            }
        }
        // 8) 风险域交集
        if !c.domains.is_empty() {
            declared += 1;
            if ctx.risk_domains.iter().any(|d| c.domains.contains(d)) {
                matched += 1;
            }
        }
        // 9) 最低严重等级
        //
        // 用 [`Severity::weight`]（Info=1 … Critical=16）而不是枚举的派生 `Ord`：
        // `Severity` 的声明顺序是 `Info, Low, Medium, High, Critical`，派生 `Ord` 下
        // **Info 反而最大**，直接比较会让"min_severity"变成"只看 Info"的反直觉语义。
        if let Some(min) = c.min_severity {
            declared += 1;
            if ctx.max_severity.is_some_and(|actual| actual.weight() >= min.weight()) {
                matched += 1;
            }
        }
        // 10) 载荷大小上限（**超过**上限即命中；用于"大载荷审批/降级"）
        if let Some(max) = c.max_payload_bytes {
            declared += 1;
            if ctx.payload_bytes > max {
                matched += 1;
            }
        }
        // 11) 人工审批：作为"门控修饰"而非独立条件——只有其它条件也成立时才生效
        if c.require_approval && declared == 0 {
            return Ok(false);
        }

        if declared == 0 {
            // 空条件集：作用域内全量命中（见模块文档第 3 条）
            return Ok(true);
        }
        Ok(matched == declared)
    }
    /// 依据 `priority`（升序）+ `id`（升序）重排。
    pub(crate) fn resort(&mut self) {
        self.policies.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
    }
}
