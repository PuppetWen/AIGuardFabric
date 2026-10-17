//! 由 `playbook.rs` 拆分：`PlaybookEngine` 的实现（纯搬移，逻辑不变）。
use super::*;

impl PlaybookEngine {
    /// 构造（无任何注入实现：只能执行条件步骤）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 注入动作执行器。
    #[must_use]
    pub fn with_action_executor(mut self, executor: Box<dyn ActionExecutor>) -> Self {
        self.action_executor = Some(executor);
        self
    }

    /// 注入通知点。
    #[must_use]
    pub fn with_notifier(mut self, notifier: Box<dyn NotifySink>) -> Self {
        self.notifier = Some(notifier);
        self
    }

    /// 注入审批门（**不注入即拒绝**）。
    #[must_use]
    pub fn with_approval(mut self, gate: Box<dyn ApprovalGate>) -> Self {
        self.approval = Some(gate);
        self
    }

    /// 设置单步最大尝试次数。
    #[must_use]
    pub const fn with_step_max_attempts(mut self, attempts: u32) -> Self {
        self.step_max_attempts = attempts;
        self
    }

    /// 开启空转模式。
    #[must_use]
    pub const fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    /// 静态校验剧本（不含触发判定）。
    ///
    /// # Errors
    /// 剧本自身非法、步骤形态为空、条件表达式无法编译、声明超时之和超过剧本超时时返回错误。
    pub fn validate(&mut self, playbook: &Playbook) -> Result<(), PlaybookError> {
        self.validate_with_timeout_limit(playbook, 3600)
    }

    /// Durable orchestration can validate longer waits without holding a synchronous request.
    pub fn validate_with_timeout_limit(&mut self, playbook: &Playbook, max_secs: i64) -> Result<(), PlaybookError> {
        if !(1..=max_secs).contains(&playbook.timeout_secs) || playbook.steps.len() > 100 {
            return Err(PlaybookError::Invalid(format!("剧本超时须为 1–{max_secs} 秒，最多 100 步")));
        }
        playbook.validate().map_err(|errs| PlaybookError::Invalid(errs.join("；")))?;
        let mut declared = 0i64;
        for (index, step) in playbook.steps.iter().enumerate() {
            let kind = derive_step_kind(step);
            if kind == StepKind::Empty {
                return Err(PlaybookError::Invalid(format!(
                    "剧本 {} 第 {} 步「{}」既没有动作/通知，也没有 condition/wait_secs/require_approval",
                    playbook.key,
                    index + 1,
                    step.name
                )));
            }
            if let StepKind::Condition { expression } = &kind {
                self.compiled.get_or_compile(expression)?;
            }
            if let StepKind::Wait { secs } = kind {
                if secs < 0 {
                    return Err(PlaybookError::Invalid(format!(
                        "剧本 {} 第 {} 步等待时长为负",
                        playbook.key,
                        index + 1
                    )));
                }
                declared = declared.saturating_add(secs);
            }
            if let Some(step_timeout) = step.timeout_secs {
                if step_timeout <= 0 {
                    return Err(PlaybookError::Invalid(format!(
                        "剧本 {} 第 {} 步超时必须为正",
                        playbook.key,
                        index + 1
                    )));
                }
                declared = declared.saturating_add(step_timeout);
            }
        }
        if playbook.timeout_secs > 0 && declared > playbook.timeout_secs {
            return Err(PlaybookError::Invalid(format!(
                "剧本 {} 声明的步骤时长合计 {declared}s 超过剧本超时 {}s",
                playbook.key, playbook.timeout_secs
            )));
        }
        // 预热全部条件编译，保证 `run` 阶段不再出现编译错误。
        for step in &playbook.steps {
            if let StepKind::Condition { expression } = derive_step_kind(step) {
                let _ = self.compiled.get_or_compile(&expression)?;
            }
        }
        Ok(())
    }

    /// 每步的派生形态（供接口预览/前端展示）。
    #[must_use]
    pub fn step_kinds(playbook: &Playbook) -> Vec<StepKind> {
        playbook.steps.iter().map(derive_step_kind).collect()
    }

    /// 该剧本是否需要人工审批。
    ///
    /// [`Playbook::needs_human_approval`]（`agf-core`）只看剧本的 `require_approval` 字段与
    /// 步骤 `action` 中的不可逆动作，**不识别** `params.require_approval`；而本 crate 的步骤
    /// 派生器 [`derive_step_kind`] 恰恰用 `params.require_approval` 表示审批步骤。
    /// 因此审批需求必须在引擎侧再叠一层，否则"用 params 声明审批"的剧本会被静默放行。
    #[must_use]
    pub fn needs_human_approval(playbook: &Playbook) -> bool {
        playbook.needs_human_approval()
            || playbook.steps.iter().any(|step| matches!(derive_step_kind(step), StepKind::Approval))
    }

    /// 求值 CEL 条件（未声明引用/缺键 → [`PlaybookEngine::default_condition`]，默认 false）。
    ///
    /// # Errors
    /// 表达式编译失败、返回值不是布尔、或求值出现非"引用缺失"类错误时返回错误。
    pub fn evaluate_condition(&mut self, expression: &str, ctx: &RunContext) -> Result<bool, PlaybookError> {
        let input = ctx.to_cel_input();
        let program = self.compiled.get_or_compile(expression)?;
        let mut cel = Context::default();
        let value =
            cel_interpreter::to_value(input).map_err(|e| PlaybookError::Condition(format!("上下文注入失败：{e}")))?;
        cel.add_variable_from_value("input", value.clone());
        cel.add_variable_from_value("ctx", value);
        match program.execute(&cel) {
            Ok(Value::Bool(b)) => Ok(b),
            Ok(other) => {
                Err(PlaybookError::Condition(format!("表达式「{expression}」必须返回布尔值，实际为 {other:?}")))
            }
            Err(e) => {
                let text = e.to_string();
                let lower = text.to_ascii_lowercase();
                if lower.contains("undeclared reference") || lower.contains("no such key") {
                    Ok(self.default_condition)
                } else {
                    Err(PlaybookError::Condition(format!("表达式「{expression}」求值失败：{text}")))
                }
            }
        }
    }

    /// 执行剧本（确定性：严格按声明顺序）。
    ///
    /// # Errors
    /// 剧本非法、条件求值失败、或缺少必要注入实现时返回错误。
    /// **注意**：步骤执行失败不报错，而是记入 [`PlaybookRun::trace`] 并按 `continue_on_error` 决定是否继续。
    pub async fn run(
        &mut self,
        playbook: &Playbook,
        trigger: &TriggerInput,
        ctx: &RunContext,
        now: Timestamp,
    ) -> Result<PlaybookRun, PlaybookError> {
        self.validate(playbook)?;
        if ctx.tenant_id.as_uuid().is_nil() {
            return Err(PlaybookError::Invalid("租户 id 非法（nil）".to_string()));
        }
        let mut run = PlaybookRun {
            playbook_key: playbook.key.clone(),
            playbook_version: playbook.version,
            tenant_id: ctx.tenant_id,
            case_id: ctx.case_id,
            outcome: RunOutcome::NotStarted,
            trace: Vec::new(),
            reason: None,
            dry_run: self.dry_run,
            finished_at: now,
        };
        if !playbook.enabled {
            run.reason = Some("剧本已禁用".to_string());
            return Ok(run);
        }
        if !trigger.matches(playbook) {
            run.reason = Some("触发条件不匹配".to_string());
            return Ok(run);
        }
        // 剧本级审批门：只要剧本**需要人工审批**（声明 `require_approval`、含不可逆动作，
        // 或含审批形态的步骤，见 [`PlaybookEngine::needs_human_approval`]），就必须在**启动前**
        // 拿到批准——缺审批门即拒绝，绝不进入"跑到一半才发现没人审批"的中间态。
        //
        // 空转（dry-run）不执行任何动作、也不做依赖检查，因此不走审批门。
        if !self.dry_run && Self::needs_human_approval(playbook) {
            let gate_result = match self.approval.as_ref() {
                None => Err("未注入审批门，按最保守策略拒绝".to_string()),
                Some(gate) => gate.approve(ctx, &format!("剧本 {} 需要人工审批", playbook.key)).await,
            };
            match gate_result {
                Ok(true) => {}
                Ok(false) => {
                    run.outcome = RunOutcome::NotStarted;
                    run.reason = Some("人工审批被拒".to_string());
                    run.trace.push(StepTrace {
                        index: 0,
                        name: "剧本审批门".to_string(),
                        kind: "approval".to_string(),
                        outcome: StepOutcome::Failed,
                        attempts: 1,
                        error: Some("人工审批被拒".to_string()),
                        note: "未开始执行".to_string(),
                        automated: true,
                    });
                    return Ok(run);
                }
                Err(reason) => {
                    run.outcome = RunOutcome::NotStarted;
                    run.reason = Some(format!("审批门不可用：{reason}"));
                    run.trace.push(StepTrace {
                        index: 0,
                        name: "剧本审批门".to_string(),
                        kind: "approval".to_string(),
                        outcome: StepOutcome::Failed,
                        attempts: 1,
                        error: Some(reason),
                        note: "未开始执行".to_string(),
                        automated: true,
                    });
                    return Ok(run);
                }
            }
        }
        run.outcome = RunOutcome::Completed;
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(playbook.timeout_secs.max(1) as u64);
        for (index, step) in playbook.steps.iter().enumerate() {
            let kind = derive_step_kind(step);
            let mut trace = StepTrace {
                index,
                name: step.name.clone(),
                kind: kind.as_str().to_string(),
                outcome: StepOutcome::Succeeded,
                attempts: 0,
                error: None,
                note: String::new(),
                automated: true,
            };
            // Step arguments previously never reached the executor (all steps saw only case metadata).
            let mut step_context = ctx.clone();
            if let Some(params) = step.params.as_object() {
                for (key, value) in params {
                    step_context
                        .params
                        .insert(key.clone(), value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string()));
                }
            }
            let step_deadline = step
                .timeout_secs
                .map(|secs| tokio::time::Instant::now() + std::time::Duration::from_secs(secs.max(1) as u64))
                .unwrap_or(deadline)
                .min(deadline);
            let execution = tokio::time::timeout_at(step_deadline, self.run_step(&kind, &step_context))
                .await
                .unwrap_or_else(|_| StepExecution::Aborted {
                    attempts: 1,
                    reason: "步骤或剧本执行超时；已完成的步骤不会自动撤销，请核对处置记录".into(),
                });
            match execution {
                StepExecution::Succeeded { attempts, note } => {
                    trace.attempts = attempts;
                    trace.note = note;
                }
                StepExecution::Skipped { attempts, note } => {
                    trace.outcome = StepOutcome::Skipped;
                    trace.attempts = attempts;
                    trace.note = note;
                }
                StepExecution::Failed { attempts, error } => {
                    trace.outcome = StepOutcome::Failed;
                    trace.attempts = attempts;
                    trace.note = format!("第 {} 步失败", index + 1);
                    trace.error = Some(error);
                }
                StepExecution::Aborted { attempts, reason } => {
                    trace.outcome = StepOutcome::Failed;
                    trace.attempts = attempts;
                    trace.note = "已中止剧本".to_string();
                    trace.error = Some(reason.clone());
                    run.trace.push(trace);
                    run.outcome = RunOutcome::Aborted;
                    run.reason = Some(reason);
                    return Ok(run);
                }
            }
            let failed = trace.outcome == StepOutcome::Failed;
            let cont = step.continue_on_error;
            run.trace.push(trace);
            if failed && !cont {
                run.outcome = RunOutcome::Aborted;
                run.reason = Some(format!("第 {} 步「{}」失败且未允许继续", index + 1, step.name));
                return Ok(run);
            }
        }
        Ok(run)
    }

    /// 执行单步（含重试）。
    ///
    /// 成功/跳过也带回 `attempts`：重试后成功的那一步必须如实报告"尝试了 N 次"
    /// （否则轨迹会把"第 3 次才成功"谎报成一次成功）。
    pub(crate) async fn run_step(&mut self, kind: &StepKind, ctx: &RunContext) -> StepExecution {
        match kind {
            StepKind::Condition { expression } => match self.evaluate_condition(expression, ctx) {
                Ok(true) => StepExecution::Succeeded { attempts: 1, note: format!("条件成立：{expression}") },
                Ok(false) => StepExecution::Skipped { attempts: 1, note: format!("条件不成立：{expression}") },
                Err(e) => StepExecution::Failed { attempts: 1, error: e.to_string() },
            },
            StepKind::Notify { channel } => {
                if self.dry_run {
                    return StepExecution::Succeeded { attempts: 1, note: format!("dry-run：跳过通知 {channel}") };
                }
                let Some(notifier) = self.notifier.as_ref() else {
                    return StepExecution::Failed {
                        attempts: 1, error: format!("未注入通知实现，无法通知 {channel}")
                    };
                };
                let note = format!("{} 案件 {:?} 等级 {}", ctx.severity.as_str(), ctx.case_id, ctx.domain);
                retry(self.step_max_attempts, || notifier.notify(channel, ctx, &note)).await
            }
            StepKind::Action { action } => {
                if self.dry_run {
                    return StepExecution::Succeeded {
                        attempts: 1,
                        note: format!("dry-run：跳过动作 {}", action.as_str()),
                    };
                }
                let Some(executor) = self.action_executor.as_ref() else {
                    return StepExecution::Failed {
                        attempts: 1,
                        error: format!("未注入动作执行器，无法执行 {}", action.as_str()),
                    };
                };
                let action = *action;
                retry(self.step_max_attempts, || executor.execute(action, ctx)).await
            }
            StepKind::Wait { secs } => {
                if self.dry_run {
                    return StepExecution::Succeeded { attempts: 1, note: format!("dry-run：跳过等待 {secs}s") };
                }
                let Some(executor) = self.action_executor.as_ref() else {
                    return StepExecution::Failed {
                        attempts: 1,
                        error: format!("未注入动作执行器，无法挂起等待 {secs}s"),
                    };
                };
                let secs = *secs;
                match executor.wait(secs, ctx).await {
                    Ok(WaitOutcome::Completed) => {
                        StepExecution::Succeeded { attempts: 1, note: format!("等待 {secs}s 结束") }
                    }
                    Ok(WaitOutcome::Aborted) => {
                        StepExecution::Aborted { attempts: 1, reason: format!("等待 {secs}s 被中止") }
                    }
                    Ok(WaitOutcome::TimedOut) => {
                        StepExecution::Aborted { attempts: 1, reason: format!("等待 {secs}s 超时") }
                    }
                    Err(e) => StepExecution::Failed { attempts: 1, error: e },
                }
            }
            StepKind::Approval => {
                // 空转不执行任何动作，也就不存在"需要人放行"的动作 ⇒ 跳过审批依赖。
                if self.dry_run {
                    return StepExecution::Succeeded { attempts: 1, note: "dry-run：跳过人工审批".to_string() };
                }
                let reason = "步骤要求人工审批".to_string();
                let result = match self.approval.as_ref() {
                    None => Err("未注入审批门，按最保守策略拒绝".to_string()),
                    Some(gate) => gate.approve(ctx, &reason).await,
                };
                match result {
                    Ok(true) => StepExecution::Succeeded { attempts: 1, note: "人工审批通过".to_string() },
                    Ok(false) => StepExecution::Aborted { attempts: 1, reason: "人工审批被拒".to_string() },
                    Err(e) => StepExecution::Aborted { attempts: 1, reason: format!("审批门不可用：{e}") },
                }
            }
            StepKind::Empty => StepExecution::Failed {
                attempts: 1,
                error: "空步骤（配置错误，应由 validate 拦截）".to_string(),
            },
        }
    }
}
