//! 由 `playbook.rs` 拆分：`SAMPLE`/`at` 等 22 项（纯搬移，逻辑不变）。
use super::*;

pub(crate) const SAMPLE: &str = r"
key: isolate-on-exfil
name: 外传自动隔离
description: 高危外传先隔离再通知
trigger:
  domains: [model-data]
  min_severity: high
steps:
  - name: 确认高危
    params:
      condition: 'input.severity_weight >= 8'
  - name: 隔离 Agent
    action: isolate-agent
    continue_on_error: false
  - name: 通知责任人
    notify_channel: dingtalk
    continue_on_error: true
  - name: 等待业务确认
    params:
      wait_secs: 60
  - name: 吊销凭据需审批
    params:
      require_approval: true
";

pub(crate) fn at(offset: i64) -> Timestamp {
    Timestamp::parse_rfc3339("2026-03-02T10:00:00Z").map_or_else(|_| Timestamp::now(), |t| t.offset_secs(offset))
}

pub(crate) fn ctx(tenant: TenantId) -> RunContext {
    RunContext::new(tenant, Severity::Critical).with_case(Id::new()).with_domain("model-data")
}

pub(crate) fn trigger() -> TriggerInput {
    TriggerInput::new(Severity::Critical).with_domain(RiskDomain::ModelData)
}

#[test]
pub(crate) fn yaml_playbook_parses_and_validates() {
    let books = parse_playbooks_yaml(SAMPLE).expect("样例 YAML 应可解析");
    assert_eq!(books.len(), 1);
    let book = &books[0];
    assert_eq!(book.key, "isolate-on-exfil");
    assert_eq!(book.steps.len(), 5);
    let kinds = PlaybookEngine::step_kinds(book);
    assert_eq!(kinds[0].as_str(), "condition");
    assert_eq!(kinds[1].as_str(), "action");
    assert_eq!(kinds[2].as_str(), "notify");
    assert_eq!(kinds[3].as_str(), "wait");
    assert_eq!(kinds[4].as_str(), "approval");
    assert!(!kinds[4].needs_executor());
    assert!(kinds[1].needs_executor());
    // 注意口径：`agf-core` 的 `Playbook::needs_human_approval` 只认 `require_approval` 字段与
    // 步骤 `action` 里的不可逆动作，**不识别** `params.require_approval`；而本剧本的审批需求
    // 正是由"审批步骤"（`params.require_approval: true`）表达，所以按本 crate 的派生口径判定——
    // 引擎启动前的审批门用的也是它（见 `approval_is_denied_by_default_and_on_rejection`）。
    assert!(PlaybookEngine::needs_human_approval(book), "含不可逆动作/审批步骤应按保守策略要求审批");
    assert!(!book.require_approval, "剧本本身未声明 require_approval（审批需求由步骤体现）");
}

#[test]
pub(crate) fn yaml_multi_playbook_list_parses() {
    let yaml =
        format!("playbooks:\n{}\n", SAMPLE.trim().lines().map(|l| format!("  {l}")).collect::<Vec<_>>().join("\n"));
    let books = parse_playbooks_yaml(&yaml).expect("列表形态应可解析");
    assert_eq!(books.len(), 1);
    assert!(parse_playbooks_yaml("playbooks: []").is_err(), "空列表应被拒");
    assert!(parse_playbooks_yaml("key: only-key\n").is_err(), "缺字段应被拒");
}

#[test]
pub(crate) fn empty_step_form_is_rejected_by_validation() {
    let mut book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    book.steps.push(PlaybookStep {
        name: "空步骤".to_string(),
        action: None,
        notify_channel: None,
        params: serde_json::Value::Null,
        continue_on_error: false,
        timeout_secs: None,
    });
    let mut engine = PlaybookEngine::new();
    let err = engine.validate(&book);
    assert!(matches!(err, Err(PlaybookError::Invalid(_))), "空形态步骤必须被拒: {err:?}");
}

#[test]
pub(crate) fn bad_condition_and_overlong_timeout_are_rejected() {
    let mut book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    // 注意：这里刻意选一个"编译期返回错误"的表达式。上游 `cel-parser` 对部分残缺表达式
    // （如 `((`、未闭合字符串）会在 parser 内部 panic，本模块无法捕获（`#![forbid(unsafe_code)]`
    // 下不使用 catch_unwind），已登记为降级项 `TODO(correlate-playbook-cel-panic-guard)`。
    book.steps[0].params = serde_json::json!({ "condition": "input." });
    let mut engine = PlaybookEngine::new();
    assert!(matches!(engine.validate(&book), Err(PlaybookError::Condition(_))));

    let mut book2 = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    book2.timeout_secs = 10; // 声明 60s 等待 > 10s 超时
    let mut engine2 = PlaybookEngine::new();
    assert!(matches!(engine2.validate(&book2), Err(PlaybookError::Invalid(_))));
}

#[test]
pub(crate) fn trigger_matching_is_enforced() {
    let book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    assert!(trigger().matches(&book));
    assert!(!TriggerInput::new(Severity::Low).with_domain(RiskDomain::ModelData).matches(&book), "等级不足");
    assert!(!TriggerInput::new(Severity::Critical).with_domain(RiskDomain::RagPoison).matches(&book), "域不符");
    let mut disabled = book.clone();
    disabled.enabled = false;
    assert!(!trigger().matches(&disabled));
}

#[tokio::test]
pub(crate) async fn full_run_records_trace_with_all_step_kinds() {
    let book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    let t = TenantId::default_tenant();
    let executor = Box::new(MockActionExecutor::new());
    let sink = Box::new(MockNotifySink::new());
    let mut engine = PlaybookEngine::new()
        .with_action_executor(executor)
        .with_notifier(sink)
        .with_approval(Box::new(MockApprovalGate::approved()));
    let run = engine.run(&book, &trigger(), &ctx(t), at(0)).await.expect("执行应成功");
    assert_eq!(run.outcome, RunOutcome::Completed);
    assert_eq!(run.steps(), 5);
    assert!(!run.has_failure());
    assert!(run.trace.iter().all(|s| s.automated));
    assert!(run.trace[0].note.contains("条件成立"));
    assert_eq!(run.trace[1].kind, "action");
    assert!(run.trace[1].note.contains("isolate-agent"));
    assert!(run.trace[2].note.contains("dingtalk"));
    assert!(run.trace[3].note.contains("等待 60s"));
    assert!(run.trace[4].note.contains("审批通过"));
    assert_eq!(run.executed_actions(), vec!["隔离 Agent".to_string()]);
    assert!(run.report().contains("剧本 isolate-on-exfil v1"));
    assert!(run.report().contains("隔离 Agent"));
}

#[tokio::test]
pub(crate) async fn condition_false_skips_step_without_failing() {
    let mut book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    book.steps[0].params = serde_json::json!({ "condition": "input.severity_weight >= 99" });
    book.steps[1].continue_on_error = false;
    book.steps.retain(|s| {
        derive_step_kind(s) == StepKind::Condition { expression: "input.severity_weight >= 99".to_string() }
    });
    let t = TenantId::default_tenant();
    let mut engine = PlaybookEngine::new();
    let run = engine.run(&book, &trigger(), &ctx(t), at(0)).await.expect("执行应成功");
    assert_eq!(run.outcome, RunOutcome::Completed);
    assert_eq!(run.trace[0].outcome, StepOutcome::Skipped);
    assert!(!run.has_failure(), "跳过不是失败");
    assert!(run.trace[0].note.contains("条件不成立"));
}

#[tokio::test]
pub(crate) async fn undeclared_reference_is_treated_as_false() {
    let t = TenantId::default_tenant();
    let mut engine = PlaybookEngine::new();
    let result = engine.evaluate_condition("input.nonexistent_field == 'x'", &ctx(t));
    assert_eq!(result, Ok(false), "缺键（no such key）应归一为条件为假");
    let undeclared = engine.evaluate_condition("nosuchvar == 'x'", &ctx(t));
    assert_eq!(undeclared, Ok(false), "未声明引用应归一为条件为假");
    let not_bool = engine.evaluate_condition("input.severity", &ctx(t));
    assert!(matches!(not_bool, Err(PlaybookError::Condition(_))), "非布尔返回值应报错");
    let syntax = engine.evaluate_condition("input.", &ctx(t));
    assert!(matches!(syntax, Err(PlaybookError::Condition(_))), "语法错误应报错");
}

#[tokio::test]
pub(crate) async fn aborts_when_step_fails_and_continue_not_allowed() {
    let book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    let t = TenantId::default_tenant();
    let executor = Box::new(MockActionExecutor::new().failing_first(99));
    let mut engine = PlaybookEngine::new()
        .with_action_executor(executor)
        .with_notifier(Box::new(MockNotifySink::new()))
        .with_approval(Box::new(MockApprovalGate::approved()));
    let run = engine.run(&book, &trigger(), &ctx(t), at(0)).await.expect("执行应返回轨迹");
    assert_eq!(run.outcome, RunOutcome::Aborted);
    assert!(run.has_failure());
    assert_eq!(run.steps(), 2, "失败后不应继续执行后续步骤");
    assert!(run.reason.as_deref().is_some_and(|r| r.contains("隔离 Agent")));
    assert_eq!(run.trace[1].outcome, StepOutcome::Failed);
    assert!(run.trace[1].error.as_deref().is_some_and(|e| e.contains("mock 执行")));
    assert!(run.trace[1].render().contains("错误"));
}

#[tokio::test]
pub(crate) async fn continue_on_error_keeps_going() {
    let book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    let t = TenantId::default_tenant();
    // 让动作失败但 continue_on_error=true 的步骤是通知（mock 通知不会失败），
    // 因此这里把动作步骤改成允许继续，验证"失败继续"分支。
    let mut book = book;
    book.steps[1].continue_on_error = true;
    let executor = Box::new(MockActionExecutor::new().failing_first(99));
    let mut engine = PlaybookEngine::new()
        .with_action_executor(executor)
        .with_notifier(Box::new(MockNotifySink::new()))
        .with_approval(Box::new(MockApprovalGate::approved()));
    let run = engine.run(&book, &trigger(), &ctx(t), at(0)).await.expect("执行应成功");
    assert_eq!(run.outcome, RunOutcome::Completed);
    assert!(run.has_failure(), "失败被记录但未中止");
    assert_eq!(run.steps(), 5);
    assert_eq!(run.trace[1].outcome, StepOutcome::Failed);
    assert_eq!(run.trace[2].outcome, StepOutcome::Succeeded);
}

#[tokio::test]
pub(crate) async fn retries_when_configured() {
    let book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    let t = TenantId::default_tenant();
    let executor = Box::new(MockActionExecutor::new().failing_first(2));
    let mut engine = PlaybookEngine::new()
        .with_action_executor(executor)
        .with_notifier(Box::new(MockNotifySink::new()))
        .with_approval(Box::new(MockApprovalGate::approved()))
        .with_step_max_attempts(3);
    let run = engine.run(&book, &trigger(), &ctx(t), at(0)).await.expect("执行应成功");
    assert_eq!(run.outcome, RunOutcome::Completed);
    assert_eq!(run.trace[1].attempts, 3, "第 3 次应成功");
    assert!(run.trace[1].render().contains("尝试 3 次"));
}

#[tokio::test]
pub(crate) async fn approval_is_denied_by_default_and_on_rejection() {
    let book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    let t = TenantId::default_tenant();
    // 未注入审批门 → 拒绝（剧本级 gate，因为含不可逆动作/审批步骤）
    let executor = Box::new(MockActionExecutor::new());
    let mut engine =
        PlaybookEngine::new().with_action_executor(executor).with_notifier(Box::new(MockNotifySink::new()));
    let run = engine.run(&book, &trigger(), &ctx(t), at(0)).await.expect("执行应返回轨迹");
    assert_eq!(run.outcome, RunOutcome::NotStarted, "无审批门必须拒绝");
    assert!(run.reason.as_deref().is_some_and(|r| r.contains("审批")));
    assert_eq!(run.steps(), 1);
    assert_eq!(run.trace[0].kind, "approval");

    // 显式拒绝
    let mut engine2 = PlaybookEngine::new()
        .with_action_executor(Box::new(MockActionExecutor::new()))
        .with_notifier(Box::new(MockNotifySink::new()))
        .with_approval(Box::new(MockApprovalGate::denied()));
    let run2 = engine2.run(&book, &trigger(), &ctx(t), at(0)).await.expect("执行应返回轨迹");
    assert_eq!(run2.outcome, RunOutcome::NotStarted);
    assert!(run2.reason.as_deref().is_some_and(|r| r.contains("被拒")));

    // 审批系统不可用 → 同样不放行
    let mut engine3 = PlaybookEngine::new()
        .with_action_executor(Box::new(MockActionExecutor::new()))
        .with_notifier(Box::new(MockNotifySink::new()))
        .with_approval(Box::new(MockApprovalGate::unavailable()));
    let run3 = engine3.run(&book, &trigger(), &ctx(t), at(0)).await.expect("执行应返回轨迹");
    assert_eq!(run3.outcome, RunOutcome::NotStarted);
    assert!(run3.reason.as_deref().is_some_and(|r| r.contains("不可用")));
}

#[tokio::test]
pub(crate) async fn notify_requires_injected_sink() {
    let book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    let t = TenantId::default_tenant();
    let mut engine = PlaybookEngine::new()
        .with_action_executor(Box::new(MockActionExecutor::new()))
        .with_approval(Box::new(MockApprovalGate::approved()));
    // 无通知实现：第三步失败并中止（continue_on_error = true，所以继续，但记录失败）
    let run = engine.run(&book, &trigger(), &ctx(t), at(0)).await.expect("执行应成功");
    assert_eq!(run.trace[2].outcome, StepOutcome::Failed);
    assert!(run.trace[2].error.as_deref().is_some_and(|e| e.contains("未注入通知实现")));
    assert_eq!(run.outcome, RunOutcome::Completed, "该步允许失败继续");
}

#[tokio::test]
pub(crate) async fn dry_run_touches_nothing() {
    let book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    let t = TenantId::default_tenant();
    let mut engine = PlaybookEngine::new().dry_run().with_step_max_attempts(3);
    let run = engine.run(&book, &trigger(), &ctx(t), at(0)).await.expect("空转执行应成功");
    assert_eq!(run.outcome, RunOutcome::Completed, "空转不做依赖检查: {run:?}");
    assert!(run.dry_run);
    assert!(run.trace[1].note.contains("dry-run"));
    assert!(run.trace[3].note.contains("dry-run"));
    assert!(!run.has_failure());
}

#[tokio::test]
pub(crate) async fn wait_abort_and_timeout_abort_the_run() {
    let t = TenantId::default_tenant();
    let book = parse_playbooks_yaml(
        r"
key: wait-then-notify
name: 等待后通知
trigger: {}
steps:
  - name: 等待
    params: { wait_secs: 30 }
  - name: 通知
    notify_channel: feishu
",
    )
    .expect("YAML 可解析")
    .remove(0);
    let mut engine = PlaybookEngine::new()
        .with_action_executor(Box::new(MockActionExecutor::new().with_wait_outcome(WaitOutcome::Aborted)))
        .with_notifier(Box::new(MockNotifySink::new()));
    let run = engine.run(&book, &TriggerInput::new(Severity::High), &ctx(t), at(0)).await.expect("执行应返回轨迹");
    assert_eq!(run.outcome, RunOutcome::Aborted);
    assert_eq!(run.steps(), 1);
    assert!(run.reason.as_deref().is_some_and(|r| r.contains("被中止")));

    let mut engine2 = PlaybookEngine::new()
        .with_action_executor(Box::new(MockActionExecutor::new().with_wait_outcome(WaitOutcome::TimedOut)))
        .with_notifier(Box::new(MockNotifySink::new()));
    let run2 = engine2.run(&book, &TriggerInput::new(Severity::High), &ctx(t), at(0)).await.expect("执行应返回轨迹");
    assert_eq!(run2.outcome, RunOutcome::Aborted);
    assert!(run2.reason.as_deref().is_some_and(|r| r.contains("超时")));
    assert_eq!(WaitOutcome::TimedOut.as_str(), "timed-out");
    assert_eq!(StepOutcome::Skipped.as_str(), "skipped");
    assert_eq!(RunOutcome::NotStarted.as_str(), "not-started");
    assert!(!RunOutcome::NotStarted.is_success());
}

#[tokio::test]
pub(crate) async fn disabled_playbook_and_unmatched_trigger_do_not_run() {
    let mut book = parse_playbooks_yaml(SAMPLE).expect("样例可解析").remove(0);
    let t = TenantId::default_tenant();
    let mut engine = PlaybookEngine::new();
    let run = engine.run(&book, &TriggerInput::new(Severity::Low), &ctx(t), at(0)).await.expect("执行应成功");
    assert_eq!(run.outcome, RunOutcome::NotStarted);
    assert!(run.reason.as_deref().is_some_and(|r| r.contains("触发条件不匹配")));
    assert_eq!(run.steps(), 0);

    book.enabled = false;
    let run2 = engine.run(&book, &trigger(), &ctx(t), at(0)).await.expect("执行应成功");
    assert_eq!(run2.outcome, RunOutcome::NotStarted);
    assert!(run2.reason.as_deref().is_some_and(|r| r.contains("已禁用")));
}

#[test]
pub(crate) fn mock_executor_and_sink_record_invocations() {
    let executor = MockActionExecutor::new().with_wait_outcome(WaitOutcome::Completed);
    let ctx = ctx(TenantId::default_tenant());
    let runtime = tokio::runtime::Builder::new_current_thread().build().expect("测试运行时");
    runtime.block_on(async {
        let first = executor.execute(ContainmentAction::IsolateAgent, &ctx).await;
        assert_eq!(first, Ok("已执行 isolate-agent".to_string()));
        let wait = executor.wait(15, &ctx).await;
        assert_eq!(wait, Ok(WaitOutcome::Completed));
        let sink = MockNotifySink::new();
        let note = sink.notify("dingtalk", &ctx, "标题").await;
        assert_eq!(note, Ok("已通知 dingtalk".to_string()));
        assert_eq!(sink.calls(), vec![("dingtalk".to_string(), "标题".to_string())]);
    });
    assert_eq!(executor.waits(), vec![15]);
    assert_eq!(executor.calls().len(), 1);
    assert_eq!(parse_channel_key("dingtalk"), Some(core_notify::ChannelKind::DingTalk));
    assert_eq!(parse_channel_key("In_App"), Some(core_notify::ChannelKind::InApp));
    assert_eq!(parse_channel_key("nope"), None);
    assert!(ContainmentAction::IsolateAgent.auto_executable());
    let _ = PlaybookTrigger::default();
}

#[test]
pub(crate) fn context_serialization_carries_cel_variables() {
    let t = TenantId::default_tenant();
    let case = Id::new();
    let context = RunContext::new(t, Severity::High)
        .with_case(case)
        .with_alert(Id::new())
        .with_domain("model-data")
        .with_rule_key("MD-EXFIL-001")
        .with_asset(Id::new())
        .with_param("owner", "bob");
    let json = context.to_cel_input();
    assert_eq!(json.get("severity").and_then(serde_json::Value::as_str), Some("high"));
    assert_eq!(json.get("severity_weight").and_then(serde_json::Value::as_u64), Some(8));
    assert_eq!(json.get("asset_count").and_then(serde_json::Value::as_u64), Some(1));
    assert_eq!(json.get("params").and_then(|p| p.get("owner")).and_then(serde_json::Value::as_str), Some("bob"));
    assert_eq!(context.case_id, Some(case));
    let mut engine = PlaybookEngine::new();
    assert_eq!(engine.evaluate_condition("input.params.owner == 'bob'", &context), Ok(true));
    assert_eq!(engine.evaluate_condition("input.domain == 'model-data' && input.asset_count > 0", &context), Ok(true));
}
