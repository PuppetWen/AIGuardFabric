//! CEL 策略后端（`cel-interpreter`，§4.3 策略引擎）。
//!
//! # 策略契约（**对外发布**）
//!
//! 策略源码是**一条 CEL 表达式**（不是一段程序），求值结果必须属于以下两种形态之一：
//!
//! | 返回形态 | 示例 | 语义 |
//! |---|---|---|
//! | `map` | `{"action": "deny", "reason": "命中", "redact": true}` | 键 `action`（string）/ `reason`（string）/ `redact`（bool）；缺失键按缺省处理 |
//! | `string` | `"deny"` | 直接作为 `action`；等价于 `{"action": <该字符串>}` |
//!
//! 其它形态（数字、布尔、列表、null）视为**契约违规**，返回
//! [`DomainError::Parse`]——避免"表达式写错却静默放行"。
//!
//! ## 命中判定
//!
//! 与 Rego 后端保持一致：
//! - 表达式返回 `map` 且含 `action` 或非空 `reason` ⇒ 命中；两者都缺失 ⇒ **不命中**；
//! - 表达式返回 `string` ⇒ 命中（字符串非空）；空字符串 ⇒ 不命中；
//! - **未声明的引用**（变量不存在 / map 缺键）⇒ 视为**不命中**而非错误，
//!   这是 CEL 的常见写法：`has(input.command) && input.command.contains("rm -rf")`
//!   在 `input.command` 为 `null` 时仍可能触发 `no_such_key`，平台将其归一为"该策略不适用"。
//!   其它求值错误（参数类型错误、函数不存在等）返回 [`DomainError::Parse`]。
//!
//! ## 输入变量
//!
//! | 变量 | 类型 | 内容 |
//! |---|---|---|
//! | `input` | map | [`PolicyContext`] 的 JSON 映射（字段同 `PolicyContext`，另含 `hit`） |
//! | `hit` | map / null | 黑名单命中结果（与 `input.hit` 同值） |
//! | `tool_name` | string | 便捷变量：`input.tool_name`（缺省为空串） |
//! | `command` | string | 便捷变量：`input.command` |
//! | `path` | string | 便捷变量：`input.path` |
//! | `domain` | string | 便捷变量：`input.domain` |
//! | `session_id` | string | 便捷变量：`input.session_id` |
//! | `payload_bytes` | int | 便捷变量：`input.payload_bytes` |
//! | `data_class` | string | 便捷变量：`input.data_class` |
//!
//! 示例：
//!
//! ```text
//! command.contains("rm -rf") ? {"action": "deny", "reason": "危险命令"} : {"reason": ""}
//! ```

use agf_core::enums::PolicyAction;
use agf_core::error::{DomainError, DomainResult};
use agf_core::policy::{Policy, PolicyContext};
use cel_interpreter::{Context, Program, Value};

/// CEL 后端：持有编译好的表达式程序。
///
/// 注意：`cel_interpreter::Program` 不是 `Clone`（内部持有 AST 与表达式引用），
/// 因此本结构体**不实现 `Clone`**：需要共享时请放进 `Arc`（求值只读 `&self`，天然可并发）。
#[derive(Debug)]
pub struct CelBackend {
    /// 策略名（错误信息与审计用）。
    policy_name: String,
    /// 编译后的表达式。
    program: Program,
}

/// CEL 求值结论（与 [`crate::rego::RegoOutcome`] 同构）。
#[derive(Debug, Clone, PartialEq)]
pub struct CelOutcome {
    /// 是否命中。
    pub hit: bool,
    /// 表达式给出的动作（`None` = 未给出）。
    pub action: Option<PolicyAction>,
    /// 表达式给出的原因。
    pub reason: Option<String>,
    /// 是否要求脱敏。
    pub redact: bool,
}

impl CelOutcome {
    /// 未命中。
    #[must_use]
    pub const fn miss() -> Self {
        Self { hit: false, action: None, reason: None, redact: false }
    }
}

impl CelBackend {
    /// 编译 CEL 表达式。
    ///
    /// # Errors
    /// 语法错误或 `source` 为空时返回 [`DomainError::Parse`]（含策略名与解析器给出的位置）。
    pub fn compile(policy: &Policy) -> DomainResult<Self> {
        if policy.source.trim().is_empty() {
            return Err(DomainError::Parse(format!("CEL 策略「{}」表达式为空", policy.name)));
        }
        let program = Program::compile(&policy.source).map_err(|e| {
            DomainError::Parse(format!("CEL 策略「{}」编译失败：{}", policy.name, flatten(&e.to_string())))
        })?;
        Ok(Self { policy_name: policy.name.clone(), program })
    }

    /// 以 [`PolicyContext`] 为输入求值。
    ///
    /// `hit_json` 为黑名单命中结果的 JSON（`None` ⇒ `hit = null`）。
    ///
    /// # Errors
    /// 输入构造失败、表达式求值失败（非"未声明引用"类）、或返回值不符合契约形态。
    pub fn evaluate(&self, ctx: &PolicyContext, hit_json: Option<&serde_json::Value>) -> DomainResult<CelOutcome> {
        let input = build_input(ctx, hit_json)?;
        let mut context = Context::default();
        context
            .add_variable("input", input.clone())
            .map_err(|e| DomainError::Parse(format!("CEL 策略「{}」注入 input 失败：{e}", self.policy_name)))?;
        let hit_value = cel_interpreter::to_value(hit_json.cloned().unwrap_or(serde_json::Value::Null))
            .map_err(|e| DomainError::Parse(format!("CEL 策略「{}」注入 hit 失败：{e}", self.policy_name)))?;
        context.add_variable_from_value("hit", hit_value);
        let s = |key: &str| input.get(key).and_then(|v| v.as_str()).unwrap_or_default().to_string();
        for (name, value) in [
            ("tool_name", s("tool_name")),
            ("command", s("command")),
            ("path", s("path")),
            ("domain", s("domain")),
            ("session_id", s("session_id")),
            ("data_class", s("data_class")),
        ] {
            let _ = context.add_variable(name, value);
        }
        let bytes = input.get("payload_bytes").and_then(serde_json::Value::as_i64).unwrap_or(0);
        let _ = context.add_variable("payload_bytes", bytes);

        match self.program.execute(&context) {
            Ok(v) => interpret(&self.policy_name, &v),
            // 未声明引用 / 键不存在 ⇒ 该策略不适用（不命中），不是错误。
            Err(e) if is_undeclared(&e.to_string()) => Ok(CelOutcome::miss()),
            Err(e) => Err(DomainError::Parse(format!(
                "CEL 策略「{}」求值失败：{}",
                self.policy_name,
                flatten(&e.to_string())
            ))),
        }
    }
}

/// 判断求值错误是否为"未声明引用 / 键不存在"（归一为不命中）。
fn is_undeclared(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("undeclared reference") || lower.contains("no such key")
}

/// 把 CEL 返回值按契约翻译为结论。
fn interpret(policy_name: &str, value: &Value) -> DomainResult<CelOutcome> {
    match value {
        Value::String(s) => {
            let text = s.as_str();
            if text.trim().is_empty() {
                return Ok(CelOutcome::miss());
            }
            let action =
                PolicyAction::parse(text).map_err(|e| DomainError::Parse(format!("CEL 策略「{policy_name}」：{e}")))?;
            Ok(CelOutcome { hit: true, action: Some(action), reason: None, redact: false })
        }
        Value::Map(_) => {
            let json = value
                .json()
                .map_err(|e| DomainError::Parse(format!("CEL 策略「{policy_name}」返回值无法转换为 JSON：{e}")))?;
            let action = match json.get("action") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(s)) if s.trim().is_empty() => None,
                Some(serde_json::Value::String(s)) => Some(
                    PolicyAction::parse(s)
                        .map_err(|e| DomainError::Parse(format!("CEL 策略「{policy_name}」：{e}")))?,
                ),
                Some(other) => {
                    return Err(DomainError::Parse(format!(
                        "CEL 策略「{policy_name}」返回的 `action` 必须是字符串，实际为 {other}"
                    )));
                }
            };
            let reason = match json.get("reason") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                Some(other) => {
                    return Err(DomainError::Parse(format!(
                        "CEL 策略「{policy_name}」返回的 `reason` 必须是字符串，实际为 {other}"
                    )));
                }
            };
            let redact = match json.get("redact") {
                None | Some(serde_json::Value::Null) => false,
                Some(serde_json::Value::Bool(b)) => *b,
                Some(other) => {
                    return Err(DomainError::Parse(format!(
                        "CEL 策略「{policy_name}」返回的 `redact` 必须是布尔值，实际为 {other}"
                    )));
                }
            };
            let hit = action.is_some() || reason.as_ref().is_some_and(|r| !r.trim().is_empty());
            Ok(CelOutcome { hit, action, reason, redact })
        }
        other => Err(DomainError::Parse(format!(
            "CEL 策略「{policy_name}」返回值形态违反契约（要求 map 或 string），实际为 {other:?}"
        ))),
    }
}

/// 构造 `input`：`PolicyContext` 序列化 + `hit` 子对象。
fn build_input(ctx: &PolicyContext, hit_json: Option<&serde_json::Value>) -> DomainResult<serde_json::Value> {
    let mut value =
        serde_json::to_value(ctx).map_err(|e| DomainError::Parse(format!("PolicyContext 序列化失败: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("hit".to_string(), hit_json.cloned().unwrap_or(serde_json::Value::Null));
    }
    Ok(value)
}

/// 压缩多行错误信息为单行。
fn flatten(text: &str) -> String {
    let joined = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" | ");
    if joined.is_empty() { text.trim().to_string() } else { joined }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::sample_policy;
    use agf_core::enums::{DataClass, InterceptPoint, RiskDomain, Severity};
    use agf_core::ids::{Id, TenantId};
    use agf_core::policy::PolicyLanguage;
    use agf_core::time::Timestamp;

    fn ctx() -> PolicyContext {
        PolicyContext {
            tenant_id: TenantId::default_tenant(),
            session_id: "s-1".into(),
            agent_id: Some(Id::new()),
            department: Some("研发".into()),
            intercept_point: InterceptPoint::McpProxy,
            tool_name: Some("shell".into()),
            path: Some("/etc/shadow".into()),
            domain: Some("evil.example.com".into()),
            command: Some("rm -rf /".into()),
            payload: serde_json::json!({"name": "shell"}),
            payload_bytes: 4096,
            risk_domains: vec![RiskDomain::ToolAbuse],
            max_severity: Some(Severity::High),
            data_class: DataClass::Confidential,
            now: Timestamp::now(),
        }
    }

    fn cel_policy(name: &str, source: &str) -> Policy {
        let mut p = sample_policy(name);
        p.language = PolicyLanguage::Cel;
        p.source = source.to_string();
        p
    }

    #[test]
    fn map_form_gives_action_reason_redact() {
        let p = cel_policy(
            "cel-map",
            r#"command.contains("rm -rf") ? {"action": "deny", "reason": "危险命令", "redact": true} : {}"#,
        );
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok(), "{backend:?}");
        let Some(backend) = backend.ok() else { return };
        let out = backend.evaluate(&ctx(), None);
        assert!(out.is_ok(), "{out:?}");
        let Some(out) = out.ok() else { return };
        assert!(out.hit);
        assert_eq!(out.action, Some(PolicyAction::Deny));
        assert_eq!(out.reason.as_deref(), Some("危险命令"));
        assert!(out.redact);
    }

    #[test]
    fn empty_map_means_miss() {
        let p = cel_policy("cel-empty", r#"command.contains("nothing-here") ? {"action": "deny"} : {}"#);
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok());
        let Some(backend) = backend.ok() else { return };
        let out = backend.evaluate(&ctx(), None);
        assert!(out.is_ok());
        let Some(out) = out.ok() else { return };
        assert!(!out.hit);
        assert_eq!(out.action, None);
    }

    #[test]
    fn string_form_is_action() {
        let p = cel_policy("cel-string", r#"path.startsWith("/etc/") ? "redact" : """#);
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok(), "{backend:?}");
        let Some(backend) = backend.ok() else { return };
        let out = backend.evaluate(&ctx(), None);
        assert!(out.is_ok(), "{out:?}");
        let Some(out) = out.ok() else { return };
        assert!(out.hit);
        assert_eq!(out.action, Some(PolicyAction::Redact));
    }

    #[test]
    fn empty_string_means_miss() {
        let p = cel_policy("cel-empty-string", r#"command == "no-such-command" ? "deny" : """#);
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok());
        let Some(backend) = backend.ok() else { return };
        let out = backend.evaluate(&ctx(), None);
        assert!(out.is_ok());
        assert!(!out.ok().map(|o| o.hit).unwrap_or(true));
    }

    #[test]
    fn reason_only_map_counts_as_hit() {
        let p = cel_policy("cel-audit", r#"{"reason": "记录一次 shell 调用"}"#);
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok());
        let Some(backend) = backend.ok() else { return };
        let out = backend.evaluate(&ctx(), None);
        assert!(out.is_ok());
        let Some(out) = out.ok() else { return };
        assert!(out.hit);
        assert_eq!(out.action, None);
    }

    #[test]
    fn hit_variable_is_available() {
        let p = cel_policy("cel-hit", r#"hit != null ? {"action": "deny", "reason": "黑名单命中"} : {}"#);
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok());
        let Some(backend) = backend.ok() else { return };
        let miss = backend.evaluate(&ctx(), None);
        assert!(miss.is_ok());
        assert!(!miss.ok().map(|o| o.hit).unwrap_or(true));
        let hit = serde_json::json!({"rule_id": "cmd.rm-rf"});
        let out = backend.evaluate(&ctx(), Some(&hit));
        assert!(out.is_ok(), "{out:?}");
        let Some(out) = out.ok() else { return };
        assert!(out.hit);
        assert_eq!(out.action, Some(PolicyAction::Deny));
    }

    #[test]
    fn convenience_variables_are_bound() {
        let p = cel_policy(
            "cel-vars",
            r#"payload_bytes > 1024 && tool_name == "shell" && data_class == "confidential"
                ? {"action": "approval", "reason": "大载荷 shell 调用"} : {}"#,
        );
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok(), "{backend:?}");
        let Some(backend) = backend.ok() else { return };
        let out = backend.evaluate(&ctx(), None);
        assert!(out.is_ok(), "{out:?}");
        let Some(out) = out.ok() else { return };
        assert!(out.hit);
        assert_eq!(out.action, Some(PolicyAction::Approval));
    }

    #[test]
    fn compile_error_is_parse_error() {
        let p = cel_policy("cel-broken", "command.contains(");
        let err = CelBackend::compile(&p);
        assert!(err.is_err());
        let Some(e) = err.err() else { return };
        assert_eq!(e.code(), "parse_error");
        assert!(e.to_string().contains("cel-broken"), "{e}");
    }

    #[test]
    fn empty_source_is_rejected() {
        let p = cel_policy("cel-empty-src", "   ");
        let err = CelBackend::compile(&p);
        assert!(err.is_err());
        assert_eq!(err.err().map(|e| e.code()), Some("parse_error"));
    }

    #[test]
    fn wrong_return_shape_is_rejected() {
        let p = cel_policy("cel-bad-shape", "42");
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok());
        let Some(backend) = backend.ok() else { return };
        let err = backend.evaluate(&ctx(), None);
        assert!(err.is_err());
        assert_eq!(err.err().map(|e| e.code()), Some("parse_error"));
    }

    #[test]
    fn unknown_action_string_is_rejected() {
        let p = cel_policy("cel-bad-action", r#""explode""#);
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok());
        let Some(backend) = backend.ok() else { return };
        let err = backend.evaluate(&ctx(), None);
        assert!(err.is_err());
        assert!(err.err().map(|e| e.to_string().contains("未知策略动作")).unwrap_or(false));
    }

    #[test]
    fn non_string_action_in_map_is_rejected() {
        let p = cel_policy("cel-action-type", r#"{"action": 42}"#);
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok());
        let Some(backend) = backend.ok() else { return };
        let err = backend.evaluate(&ctx(), None);
        assert!(err.is_err());
        assert!(err.err().map(|e| e.to_string().contains("必须是字符串")).unwrap_or(false));
    }

    #[test]
    fn undeclared_reference_is_treated_as_miss() {
        // `input.no_such_field` 在 CEL 中会导致 no_such_key；归一为"该策略不适用"。
        let p = cel_policy("cel-missing-key", r#"input.no_such_field == "x" ? "deny" : """#);
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok());
        let Some(backend) = backend.ok() else { return };
        let out = backend.evaluate(&ctx(), None);
        assert!(out.is_ok(), "缺键应视为不命中：{out:?}");
        assert!(!out.ok().map(|o| o.hit).unwrap_or(true));
    }

    #[test]
    fn type_error_is_reported() {
        let p = cel_policy("cel-type-error", r#"size(42) > 0 ? "deny" : """#);
        let backend = CelBackend::compile(&p);
        assert!(backend.is_ok(), "{backend:?}");
        let Some(backend) = backend.ok() else { return };
        let out = backend.evaluate(&ctx(), None);
        assert!(out.is_err(), "真实类型错误必须报错而不是静默放行：{out:?}");
    }

    #[test]
    fn input_map_mirrors_context() {
        let json = build_input(&ctx(), None);
        assert!(json.is_ok());
        let Some(json) = json.ok() else { return };
        assert_eq!(json["payload_bytes"], serde_json::json!(4096));
        assert_eq!(json["hit"], serde_json::Value::Null);
        assert!(json.get("data_class").is_some());
    }
}
