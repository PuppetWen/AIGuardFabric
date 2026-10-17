//! 由 `playbook.rs` 拆分：`impl_TriggerInput`/`impl_TriggerInput` 等 10 项（纯搬移，逻辑不变）。
use super::*;

impl Default for TriggerInput {
    fn default() -> Self {
        Self { domain: None, severity: Severity::Info, rule_keys: Vec::new(), asset_kind: None }
    }
}

impl TriggerInput {
    /// 构造。
    #[must_use]
    pub fn new(severity: Severity) -> Self {
        Self { severity, ..Self::default() }
    }

    /// 设置安全域。
    #[must_use]
    pub const fn with_domain(mut self, domain: RiskDomain) -> Self {
        self.domain = Some(domain);
        self
    }

    /// 设置资产类型。
    #[must_use]
    pub const fn with_asset_kind(mut self, kind: AssetKind) -> Self {
        self.asset_kind = Some(kind);
        self
    }

    /// 追加规则键。
    #[must_use]
    pub fn with_rule_key(mut self, key: impl Into<String>) -> Self {
        self.rule_keys.push(key.into());
        self
    }

    /// 是否命中剧本触发条件（基础字段）。
    #[must_use]
    pub fn matches(&self, playbook: &Playbook) -> bool {
        playbook.enabled && playbook.trigger.matches(self.domain, self.severity, &self.rule_keys, self.asset_kind)
    }
}

impl RunContext {
    /// 构造最小上下文。
    #[must_use]
    pub fn new(tenant_id: TenantId, severity: Severity) -> Self {
        Self {
            tenant_id,
            case_id: None,
            alert_id: None,
            severity,
            domain: String::new(),
            rule_keys: Vec::new(),
            asset_ids: Vec::new(),
            finding_ids: Vec::new(),
            params: BTreeMap::new(),
        }
    }

    /// 设置案件。
    #[must_use]
    pub const fn with_case(mut self, case_id: Id) -> Self {
        self.case_id = Some(case_id);
        self
    }

    /// 设置告警。
    #[must_use]
    pub const fn with_alert(mut self, alert_id: Id) -> Self {
        self.alert_id = Some(alert_id);
        self
    }

    /// 设置安全域。
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    /// 追加规则键。
    #[must_use]
    pub fn with_rule_key(mut self, key: impl Into<String>) -> Self {
        self.rule_keys.push(key.into());
        self
    }

    /// 追加资产。
    #[must_use]
    pub fn with_asset(mut self, asset_id: Id) -> Self {
        self.asset_ids.push(asset_id);
        self
    }

    /// 设置参数。
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    /// 序列化为 CEL 输入 JSON。
    #[must_use]
    pub fn to_cel_input(&self) -> serde_json::Value {
        let params: serde_json::Map<String, serde_json::Value> =
            self.params.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect();
        serde_json::json!({
            "tenant_id": self.tenant_id.to_string(),
            "case_id": self.case_id.map(|c| c.to_string()),
            "alert_id": self.alert_id.map(|a| a.to_string()),
            "severity": self.severity.as_str(),
            "severity_weight": self.severity.weight(),
            "domain": self.domain,
            "rule_keys": self.rule_keys,
            "asset_count": self.asset_ids.len(),
            "finding_count": self.finding_ids.len(),
            "params": params,
        })
    }
}

impl WaitOutcome {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Aborted => "aborted",
            Self::TimedOut => "timed-out",
        }
    }
}

impl StepOutcome {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

impl RunOutcome {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Aborted => "aborted",
            Self::NotStarted => "not-started",
        }
    }

    /// 是否属于"跑完/正常结束"。
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl StepKind {
    /// 形态文本。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Condition { .. } => "condition",
            Self::Notify { .. } => "notify",
            Self::Action { .. } => "action",
            Self::Wait { .. } => "wait",
            Self::Approval => "approval",
            Self::Empty => "empty",
        }
    }

    /// 是否需要外部实现注入（`Condition`/`Approval` 分别需要 CEL 与审批门）。
    #[must_use]
    pub const fn needs_executor(&self) -> bool {
        matches!(self, Self::Action { .. } | Self::Wait { .. })
    }
}

/// 由 `agf-core` 步骤派生形态。
///
/// 优先级：`action` > `notify_channel` > `params` 中的 `wait_secs` / `require_approval` / `condition`。
#[must_use]
pub fn derive_step_kind(step: &PlaybookStep) -> StepKind {
    if let Some(action) = step.action {
        return StepKind::Action { action };
    }
    if let Some(channel) = step.notify_channel.as_deref().filter(|c| !c.trim().is_empty()) {
        return StepKind::Notify { channel: channel.trim().to_string() };
    }
    let params = &step.params;
    if let Some(secs) = params.get("wait_secs").and_then(serde_json::Value::as_i64) {
        return StepKind::Wait { secs };
    }
    if params.get("require_approval").and_then(serde_json::Value::as_bool).unwrap_or(false) {
        return StepKind::Approval;
    }
    if let Some(expression) = params.get("condition").and_then(serde_json::Value::as_str) {
        let expression = expression.trim();
        if !expression.is_empty() {
            return StepKind::Condition { expression: expression.to_string() };
        }
    }
    StepKind::Empty
}

impl StepTrace {
    /// 一行式描述。
    #[must_use]
    pub fn render(&self) -> String {
        let mut line = format!("[{}] {} <{}> {}", self.index + 1, self.name, self.kind, self.outcome.as_str());
        if self.attempts > 1 {
            line.push_str(&format!("（尝试 {} 次）", self.attempts));
        }
        if !self.note.is_empty() {
            line.push_str(&format!("：{}", self.note));
        }
        if let Some(error) = &self.error {
            line.push_str(&format!("｜错误：{error}"));
        }
        line
    }
}

impl PlaybookRun {
    /// 轨迹行数。
    #[must_use]
    pub fn steps(&self) -> usize {
        self.trace.len()
    }

    /// 是否存在失败步骤。
    #[must_use]
    pub fn has_failure(&self) -> bool {
        self.trace.iter().any(|t| t.outcome == StepOutcome::Failed)
    }

    /// 被执行成功过的处置动作（用于"实际做了什么"的上报）。
    #[must_use]
    pub fn executed_actions(&self) -> Vec<String> {
        self.trace
            .iter()
            .filter(|t| t.outcome == StepOutcome::Succeeded && t.kind == "action")
            .map(|t| t.name.clone())
            .collect()
    }

    /// 多行可读报告。
    #[must_use]
    pub fn report(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!(
            "剧本 {} v{} → {}（步骤 {}，租户 {}）",
            self.playbook_key,
            self.playbook_version,
            self.outcome.as_str(),
            self.trace.len(),
            self.tenant_id
        );
        if let Some(reason) = &self.reason {
            let _ = write!(out, "｜{reason}");
        }
        for step in &self.trace {
            out.push('\n');
            out.push_str(&step.render());
        }
        out
    }
}
