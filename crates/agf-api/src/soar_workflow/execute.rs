//! Execute one claimed step. An interrupted side effect is never silently replayed.
use super::*;
use agf_correlate::playbook::{PlaybookEngine, RunOutcome, TriggerInput};

pub(super) async fn step(state: &AppState, run: &Run) -> DomainResult<StepTrace> {
    if state.config.mock_mode != run.mock_mode {
        return Err(DomainError::PreconditionFailed("执行环境已在模拟和真实模式间切换，请重新核对并提交任务".into()));
    }
    let principal = run.execute_as.resolve(state, run.tenant_id).await?;
    let mut book = run.playbook.clone();
    let mut step = book.steps[run.next_step].clone();
    // External calls are bounded. Long durations belong in persisted wait steps.
    let seconds = step
        .timeout_secs
        .unwrap_or(60)
        .min(60)
        .min(run.deadline_at.map_or(60, |at| at.unix_secs() - Timestamp::now().unix_secs()))
        .max(1);
    step.timeout_secs = Some(seconds);
    book.steps = vec![step];
    book.timeout_secs = seconds;
    book.require_approval = false;
    book.trigger = agf_core::case::PlaybookTrigger::default();
    let executor = crate::soar_executor::Executor {
        state: state.clone(),
        principal,
        workflow_step: Some(crate::soar_executor::WorkflowStep {
            request_id: agf_core::ids::deterministic_id("agf.soar.edr", &format!("{}:{}", run.id, run.next_step)),
            occurred_at: run.created_at,
        }),
    };
    let mut engine = PlaybookEngine::new()
        .with_action_executor(Box::new(executor.clone()))
        .with_notifier(Box::new(executor))
        .with_approval(Box::new(crate::soar_executor::Approval { approved: true }));
    let result = engine
        .run(&book, &TriggerInput::new(run.context.severity), &run.context, Timestamp::now())
        .await
        .map_err(|error| DomainError::Validation(error.to_string()))?;
    let mut trace = result
        .trace
        .into_iter()
        .next()
        .ok_or_else(|| DomainError::Internal("SOAR step returned no execution trace".into()))?;
    trace.index = run.next_step;
    if result.outcome == RunOutcome::NotStarted {
        trace.outcome = StepOutcome::Failed;
    }
    Ok(trace)
}

pub(super) async fn project(state: &AppState, run: &Run) -> DomainResult<()> {
    if !run.status.terminal() || run.projected_version >= run.version {
        return Ok(());
    }
    let result = agf_correlate::playbook::PlaybookRun {
        playbook_key: run.playbook.key.clone(),
        playbook_version: run.playbook.version,
        tenant_id: run.tenant_id,
        case_id: Some(run.case_id),
        outcome: match run.status {
            Status::Completed => RunOutcome::Completed,
            Status::NotStarted => RunOutcome::NotStarted,
            _ => RunOutcome::Aborted,
        },
        trace: run.trace.clone(),
        reason: run.reason.clone(),
        dry_run: false,
        finished_at: run.finished_at.unwrap_or(run.updated_at),
    };
    let record = crate::store::SoarRunRecord {
        id: run.id,
        tenant_id: run.tenant_id,
        case_id: run.case_id,
        started_at: run.created_at,
        run: result,
    };
    state.configurations.put(run.tenant_id, "soar-run", run.id, &record).await?;
    let event = agf_core::case::CaseEvent {
        id: agf_core::ids::deterministic_id("soar-workflow-result", &run.id.to_string()),
        tenant_id: run.tenant_id,
        case_id: run.case_id,
        kind: agf_core::case::CaseEventKind::PlaybookRun,
        actor: run.execute_as.display(),
        note: format!("剧本 {}：{:?}，执行记录 {}", run.playbook.key, run.status, run.id),
        detail: serde_json::json!({"run_id":run.id,"status":run.status}),
        automated: true,
        at: run.finished_at.unwrap_or(run.updated_at),
    };
    state.store.case_insert_event_durable(&event).await?;
    change(state, run.tenant_id, run.id, |current| {
        current.projected_version = current.projected_version.max(run.version);
        Ok(())
    })
    .await?;
    Ok(())
}
