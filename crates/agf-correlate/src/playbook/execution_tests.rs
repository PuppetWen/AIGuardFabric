//! Execution deadlines and per-step parameter isolation with a real asynchronous executor.
use super::*;

#[derive(Debug)]
struct SlowExecutor;
#[async_trait]
impl ActionExecutor for SlowExecutor {
    async fn execute(&self, _: ContainmentAction, ctx: &RunContext) -> Result<String, String> {
        if ctx.params.get("slow").is_some_and(|value| value == "true") {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        Ok(ctx.params.get("target").cloned().unwrap_or_else(|| "absent".into()))
    }
    async fn wait(&self, _: i64, _: &RunContext) -> Result<WaitOutcome, String> {
        Ok(WaitOutcome::Completed)
    }
}
#[tokio::test]
async fn target_parameters_are_scoped_to_one_step() {
    let book: Playbook =
        serde_json::from_value(serde_json::json!({"key":"parameters","name":"parameters","trigger":{},
        "steps":[{"name":"first","action":"isolate-agent","params":{"target":"first-target"}},
                 {"name":"second","action":"isolate-agent"}]}))
        .expect("valid book");
    let mut engine = PlaybookEngine::new().with_action_executor(Box::new(SlowExecutor));
    let context = RunContext::new(TenantId::new(), Severity::High);
    let result = engine.run(&book, &TriggerInput::new(Severity::High), &context, Timestamp::now()).await.expect("run");
    assert_eq!(result.trace[0].note, "first-target");
    assert_eq!(result.trace[1].note, "absent");
}
#[tokio::test]
async fn deadline_aborts_a_stalled_action_and_prevents_following_steps() {
    let book: Playbook =
        serde_json::from_value(serde_json::json!({"key":"timeout","name":"timeout","trigger":{},"timeout_secs":2,
        "steps":[{"name":"slow","action":"isolate-agent","timeout_secs":1,"params":{"slow":true}},
                 {"name":"must-not-run","action":"isolate-agent"}]}))
        .expect("valid book");
    let mut engine = PlaybookEngine::new().with_action_executor(Box::new(SlowExecutor));
    let context = RunContext::new(TenantId::new(), Severity::High);
    let result = engine.run(&book, &TriggerInput::new(Severity::High), &context, Timestamp::now()).await.expect("run");
    assert_eq!(result.outcome, RunOutcome::Aborted);
    assert_eq!(result.trace.len(), 1);
    assert!(result.trace[0].error.as_ref().is_some_and(|reason| reason.contains("超时")));
}
