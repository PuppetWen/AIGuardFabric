//! 由 `playbook.rs` 拆分：`CompiledConditions`/`MockActionExecutor`/`MockApprovalGate`/`MockNotifySink`/`PlaybookEngine` 的实现（纯搬移，逻辑不变）。
use super::*;

impl Default for MockActionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl MockActionExecutor {
    /// 构造（恒成功、等待完成）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            fail_first: 0,
            wait_outcome: WaitOutcome::Completed,
            state: std::sync::Mutex::new(MockActionState::default()),
        }
    }

    /// 前 `times` 次动作调用失败。
    #[must_use]
    pub const fn failing_first(mut self, times: u32) -> Self {
        self.fail_first = times;
        self
    }

    /// 设置等待结论。
    #[must_use]
    pub const fn with_wait_outcome(mut self, outcome: WaitOutcome) -> Self {
        self.wait_outcome = outcome;
        self
    }

    /// 调用记录 `(动作名, 租户)`。
    #[must_use]
    pub fn calls(&self) -> Vec<(String, String)> {
        self.state.lock().map(|s| s.calls.clone()).unwrap_or_default()
    }

    /// 等待记录（秒）。
    #[must_use]
    pub fn waits(&self) -> Vec<i64> {
        self.state.lock().map(|s| s.waits.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl ActionExecutor for MockActionExecutor {
    async fn execute(&self, action: ContainmentAction, ctx: &RunContext) -> Result<String, String> {
        let mut state = self.state.lock().map_err(|_| "mock 执行器锁中毒".to_string())?;
        state.calls.push((action.as_str().to_string(), ctx.tenant_id.to_string()));
        if state.failures < self.fail_first {
            state.failures = state.failures.saturating_add(1);
            return Err(format!("mock 执行 {} 失败", action.as_str()));
        }
        Ok(format!("已执行 {}", action.as_str()))
    }

    async fn wait(&self, secs: i64, _ctx: &RunContext) -> Result<WaitOutcome, String> {
        let mut state = self.state.lock().map_err(|_| "mock 执行器锁中毒".to_string())?;
        state.waits.push(secs);
        Ok(self.wait_outcome)
    }
}

impl MockNotifySink {
    /// 构造。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 通知记录 `(渠道, 标题)`。
    #[must_use]
    pub fn calls(&self) -> Vec<(String, String)> {
        self.state.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl NotifySink for MockNotifySink {
    async fn notify(&self, channel: &str, _ctx: &RunContext, note: &str) -> Result<String, String> {
        self.state.lock().map_err(|_| "mock 通知锁中毒".to_string())?.push((channel.to_string(), note.to_string()));
        Ok(format!("已通知 {channel}"))
    }
}

impl MockApprovalGate {
    /// 批准。
    #[must_use]
    pub const fn approved() -> Self {
        Self { approved: true, unavailable: false }
    }

    /// 拒绝。
    #[must_use]
    pub const fn denied() -> Self {
        Self { approved: false, unavailable: false }
    }

    /// 审批系统不可用。
    #[must_use]
    pub const fn unavailable() -> Self {
        Self { approved: false, unavailable: true }
    }
}

#[async_trait]
impl ApprovalGate for MockApprovalGate {
    async fn approve(&self, _ctx: &RunContext, _reason: &str) -> Result<bool, String> {
        if self.unavailable {
            return Err("审批系统不可用".to_string());
        }
        Ok(self.approved)
    }
}

impl CompiledConditions {
    pub(crate) fn get_or_compile(&mut self, expression: &str) -> Result<&Program, PlaybookError> {
        if !self.programs.contains_key(expression) {
            let program = Program::compile(expression)
                .map_err(|e| PlaybookError::Condition(format!("表达式「{expression}」编译失败：{e}")))?;
            self.programs.insert(expression.to_string(), program);
        }
        self.programs
            .get(expression)
            .ok_or_else(|| PlaybookError::Condition(format!("表达式「{expression}」编译结果丢失")))
    }
}

impl Default for PlaybookEngine {
    fn default() -> Self {
        Self {
            step_max_attempts: 1,
            dry_run: false,
            default_condition: false,
            action_executor: None,
            notifier: None,
            approval: None,
            compiled: CompiledConditions::default(),
        }
    }
}
