//! Per-run SQL leases serialize workers without holding database locks during network calls.
use super::*;
use agf_correlate::playbook::{StepKind, derive_step_kind};
use futures::stream::{self, StreamExt};

pub async fn advance(state: &AppState, tenant: TenantId, id: Id, now: Timestamp) -> DomainResult<Run> {
    let token = Id::new();
    let mut claimed = false;
    let run = change(state, tenant, id, |run| {
        if run.status.terminal() || run.status == Status::Review {
            return Ok(());
        }
        if run.status == Status::Running {
            if run.lease_until.is_none_or(|at| at <= now) {
                run.status = Status::Review;
                run.reason = Some("执行进程中断，当前步骤结果不确定；请核对处置记录后确认完成或明确重试".into());
                run.lease_token = None;
                run.lease_until = None;
                run.record(now, "system:soar", "interrupted", "不会自动重放可能已生效的动作");
            }
            return Ok(());
        }
        if run.deadline_at.is_some_and(|at| at <= now)
            || (run.status == Status::Approval && run.wake_at.is_some_and(|at| at <= now))
        {
            run.finish(Status::Aborted, now, "剧本或审批超过时限；已完成动作不会自动撤销");
            run.record(now, "system:soar", "expired", "执行时限已到");
            return Ok(());
        }
        if run.status == Status::Approval {
            return Ok(());
        }
        if run.status == Status::Waiting {
            if run.wake_at.is_some_and(|at| at <= now) {
                run.complete_step(now, "持久化等待结束");
                run.record(now, "system:soar", "wait-completed", "等待时间到达，继续后续步骤");
            }
            return Ok(());
        }
        let step = &run.playbook.steps[run.next_step];
        match derive_step_kind(step) {
            StepKind::Approval => {
                run.status = Status::Approval;
                run.wake_at = Some(
                    now.offset_secs(step.timeout_secs.unwrap_or(86400))
                        .min(run.deadline_at.unwrap_or(now.offset_secs(86400))),
                );
                run.record(now, "system:soar", "approval-requested", "本步骤需要新的审批结论");
            }
            StepKind::Wait { secs } => {
                if step.timeout_secs.is_some_and(|limit| limit < secs) {
                    run.finish(Status::Aborted, now, "等待时长超过步骤时限");
                } else if secs == 0 {
                    run.complete_step(now, "无需等待");
                } else {
                    run.status = Status::Waiting;
                    run.wake_at = Some(now.offset_secs(secs));
                }
                run.record(now, "system:soar", "wait", "已保存等待状态；关闭网页或重启服务不会丢失");
            }
            _ => {
                run.status = Status::Running;
                run.lease_token = Some(token);
                run.lease_until = Some(now.offset_secs(120));
                run.record(now, "system:soar", "step-started", "开始当前步骤");
                claimed = true;
            }
        }
        Ok(())
    })
    .await?;
    if !claimed {
        execute::project(state, &run).await?;
        return Ok(run);
    }
    let result = tokio::time::timeout(std::time::Duration::from_secs(70), execute::step(state, &run)).await;
    let finished = Timestamp::now().max(now);
    let run = change(state, tenant, id, |current| {
        if current.lease_token != Some(token) || current.status != Status::Running {
            return Ok(());
        }
        current.lease_token = None;
        current.lease_until = None;
        let mut trace = match result {
            Ok(Ok(trace)) => trace,
            Ok(Err(error)) => StepTrace {
                index: current.next_step,
                name: current.playbook.steps[current.next_step].name.clone(),
                kind: derive_step_kind(&current.playbook.steps[current.next_step]).as_str().into(),
                outcome: StepOutcome::Failed,
                attempts: 1,
                error: Some(error.to_string()),
                note: "步骤未完成".into(),
                automated: true,
            },
            Err(_) => {
                current.status = Status::Review;
                current.reason = Some("步骤超时，结果待核对；不会自动重试".into());
                current.record(finished, "system:soar", "uncertain", "请先核对处置记录");
                return Ok(());
            }
        };
        if trace.error.as_deref().is_some_and(|error| {
            error.contains("步骤或剧本执行超时") || error.contains("EDR_UNCERTAIN:") || error.contains("IAM_UNCERTAIN:")
        }) {
            current.status = Status::Review;
            current.reason.clone_from(&trace.error);
            current.record(finished, "system:soar", "uncertain", "外部处置结果待核对；禁止自动重试");
            return Ok(());
        }
        trace.index = current.next_step;
        let abort =
            trace.outcome == StepOutcome::Failed && !current.playbook.steps[current.next_step].continue_on_error;
        let error = trace.error.clone();
        current.trace.push(trace);
        current.next_step += 1;
        current.status = Status::Queued;
        if abort {
            current.finish(Status::Aborted, finished, error.as_deref().unwrap_or("步骤失败"));
        } else if current.next_step == current.playbook.steps.len() {
            current.finish(Status::Completed, finished, "所有步骤已结束，请以逐步结果核对处置");
        }
        current.record(finished, "system:soar", "step-finished", "已保存步骤结果");
        Ok(())
    })
    .await?;
    execute::project(state, &run).await?;
    Ok(run)
}

pub async fn tick(state: &AppState, now: Timestamp) -> DomainResult<usize> {
    let mut work = Vec::new();
    for tenant in crate::tenant_directory::list(state).await?.into_iter().filter(|tenant| tenant.enabled) {
        work.extend(queries::due(state, tenant.id, now).await?.into_iter().map(|id| (tenant.id, id)));
    }
    let results: Vec<_> = stream::iter(work)
        .map(|(tenant, id)| async move { advance(state, tenant, id, now).await })
        .buffer_unordered(8)
        .collect()
        .await;
    let mut progressed = 0;
    for result in results {
        match result {
            Ok(_) => progressed += 1,
            Err(error) => tracing::warn!(%error, "SOAR workflow tick failed; durable state retained"),
        }
    }
    Ok(progressed)
}

pub async fn run_loop(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(error) = crate::soar_automation::tick(&state).await {
            tracing::warn!(%error, "Automatic response configuration unavailable");
        }
        if let Err(error) = tick(&state, Timestamp::now()).await {
            tracing::warn!(%error, "SOAR workflow store unavailable");
        }
    }
}
