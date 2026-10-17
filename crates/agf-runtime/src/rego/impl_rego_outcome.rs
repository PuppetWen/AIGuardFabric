//! 由 `rego.rs` 拆分：`impl_RegoOutcome`/`impl_RegoBackend` 等 9 项（纯搬移，逻辑不变）。
use super::*;

impl RegoOutcome {
    /// 未命中。
    #[must_use]
    pub const fn miss() -> Self {
        Self { hit: false, action: None, reason: None, redact: false }
    }
}

impl RegoBackend {
    /// 编译策略源码。
    ///
    /// # Errors
    /// 包名不是 `agf`、语法错误、或规则类型不合法（如 `action` 非字符串）时返回
    /// [`DomainError::Parse`]，消息内带策略名与源码行。
    pub fn compile(policy: &Policy) -> DomainResult<Self> {
        let mut engine = Engine::new();
        let path = format!("{}.rego", sanitize_name(&policy.name));
        let package = engine.add_policy(path, policy.source.clone()).map_err(|e| {
            DomainError::Parse(format!("Rego 策略「{}」编译失败：{}", policy.name, flatten(&e.to_string())))
        })?;
        // 契约校验：包名必须是 data.agf
        let expected = format!("data.{PACKAGE}");
        if package != expected {
            return Err(DomainError::Parse(format!(
                "Rego 策略「{}」包名非法：期望 `package {PACKAGE}`（{expected}），实际 `{package}`",
                policy.name
            )));
        }
        let (has_action, has_reason, has_redact) = probe_rules(&mut engine);
        let backend = Self { policy_name: policy.name.clone(), engine, has_action, has_reason, has_redact };
        Ok(backend)
    }

    /// 是否定义了 `action` 规则。
    #[must_use]
    pub const fn has_action_rule(&self) -> bool {
        self.has_action
    }

    /// 是否定义了 `reason` 规则。
    #[must_use]
    pub const fn has_reason_rule(&self) -> bool {
        self.has_reason
    }

    /// 是否定义了 `redact` 规则。
    #[must_use]
    pub const fn has_redact_rule(&self) -> bool {
        self.has_redact
    }

    /// 以 [`PolicyContext`] 为输入求值。
    ///
    /// `hit_json` 为黑名单命中结果的 JSON（`None` ⇒ `input.hit = null`）。
    ///
    /// # Errors
    /// 输入序列化失败或规则求值失败（如规则体运行时类型错误）。
    pub fn evaluate(&self, ctx: &PolicyContext, hit_json: Option<&serde_json::Value>) -> DomainResult<RegoOutcome> {
        let mut engine = self.engine.clone();
        let input = build_input(ctx, hit_json)?;
        engine.set_input_json(&input.to_string()).map_err(|e| {
            DomainError::Parse(format!("Rego 策略「{}」输入注入失败：{}", self.policy_name, flatten(&e.to_string())))
        })?;

        // 三条规则各自求值：`Undefined`（规则体为假）归一为 `None`。
        // 是否"存在这条规则"由 [`probe_rules`] 在编译期从 AST 判定——**不能靠求值探测**：
        // regorus 对不存在的规则路径直接返回 `Err`，对"规则体为假"返回 `Undefined`，
        // 而用空输入探测还会把带条件的规则误判成不存在（历史上命中判丢的根因）。
        let action = if self.has_action {
            // 规则**存在**但本次输入下求值为 `Undefined`（条件为假）⇒ 视为"没有动作"，
            // 而不是错误：策略未命中本来就是正常结果。
            eval_rule(&mut engine, RULE_ACTION)?.map(|v| parse_action(&self.policy_name, Some(v))).transpose()?
        } else {
            None
        };
        let reason = if self.has_reason {
            eval_rule(&mut engine, RULE_REASON)?.and_then(|v| v.as_string().ok().map(ToString::to_string))
        } else {
            None
        };
        let redact = if self.has_redact {
            matches!(eval_rule(&mut engine, RULE_REDACT)?, Some(Value::Bool(true)))
        } else {
            false
        };

        let reason_non_empty = reason.as_ref().is_some_and(|r| !r.trim().is_empty());
        let action_defined = action.is_some();
        Ok(RegoOutcome { hit: action_defined || reason_non_empty, action, reason, redact })
    }
}

/// 求值一条规则，`undefined` 归一为 `None`。
pub(crate) fn eval_rule(engine: &mut Engine, rule: &str) -> DomainResult<Option<Value>> {
    match engine.eval_rule(rule.to_string()) {
        Ok(Value::Undefined) => Ok(None),
        Ok(v) => Ok(Some(v)),
        // regorus 用 `not a valid rule path` 区分"这条规则压根不存在"：
        // 策略只定义部分规则（例如只写 `reason`）是合法契约，归一为 `None` 而不是报错。
        Err(e) if is_missing_rule(&e) => Ok(None),
        Err(e) => Err(DomainError::Parse(format!("Rego 规则 `{rule}` 求值失败：{}", flatten(&e.to_string())))),
    }
}

/// regorus 的"规则路径不存在"判定。
pub(crate) fn is_missing_rule(err: &anyhow::Error) -> bool {
    err.to_string().contains("not a valid rule path")
}

/// 判定策略定义了 `action` / `reason` / `redact` 中的哪几条。
///
/// 依据是 regorus 的 `rule_paths`（不存在时 `eval_rule` 报 `not a valid rule path`），
/// 而不是"求值一次看有没有值"：规则体为假时求值结果是 `Undefined`，
/// 与"未定义"在取值层面无法区分，只有错误信息能区分两者。
pub(crate) fn probe_rules(engine: &mut Engine) -> (bool, bool, bool) {
    let defined = |engine: &mut Engine, rule: &str| match engine.eval_rule(rule.to_string()) {
        Ok(_) => true,
        Err(e) => !is_missing_rule(&e),
    };
    // 探测时给一个空对象输入：规则体求值可能失败（缺字段），但那不影响"路径是否存在"。
    engine.set_input(Value::new_object());
    let has_action = defined(engine, RULE_ACTION);
    let has_reason = defined(engine, RULE_REASON);
    let has_redact = defined(engine, RULE_REDACT);
    (has_action, has_reason, has_redact)
}

/// `action` 值 → [`PolicyAction`]。
pub(crate) fn parse_action(policy_name: &str, value: Option<Value>) -> DomainResult<PolicyAction> {
    let Some(v) = value else {
        return Err(DomainError::Parse(format!(
            "Rego 策略「{policy_name}」的 `{RULE_ACTION}` 未定义，无法确定动作；\
             若策略只做审计请改用 `reason` 规则"
        )));
    };
    let text = v.as_string().map_err(|_| {
        DomainError::Parse(format!("Rego 策略「{policy_name}」的 `{RULE_ACTION}` 必须返回字符串，实际为 {v:?}"))
    })?;
    PolicyAction::parse(text.as_ref()).map_err(|e| DomainError::Parse(format!("Rego 策略「{policy_name}」：{e}")))
}

/// 构造 `input`：`PolicyContext` 序列化 + `hit` 子对象。
pub(crate) fn build_input(
    ctx: &PolicyContext,
    hit_json: Option<&serde_json::Value>,
) -> DomainResult<serde_json::Value> {
    let mut value =
        serde_json::to_value(ctx).map_err(|e| DomainError::Parse(format!("PolicyContext 序列化失败: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("hit".to_string(), hit_json.cloned().unwrap_or(serde_json::Value::Null));
    }
    Ok(value)
}

/// 把策略名规范成合法 Rego 文件名。
///
/// 保留 Unicode 字母/数字（中文策略名是常态，`阻断 危险 命令` → `阻断_危险_命令`），
/// 只把分隔符与标点替换成下划线；这既是可读的虚拟文件名，也避免中文策略名全部塌成
/// 一串 `_` 后在排障时无法区分是哪个策略。
pub(crate) fn sanitize_name(name: &str) -> String {
    let s: String = name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    if s.is_empty() { "policy".to_string() } else { s }
}

/// 压缩多行错误信息为单行（regorus 的错误含多行源码片段）。
pub(crate) fn flatten(text: &str) -> String {
    let joined = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" | ");
    if joined.is_empty() { text.trim().to_string() } else { joined }
}
