//! Cloud callbacks use permanent API admission and a one-time start; local lanes remain separate.
use crate::{
    Registry, TaskOutcome,
    callback_binding::{Client, Identity, Receipt, artifacts},
    dispatch::{EXECUTION_ID, Handler},
    tasks,
};
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;

fn stopped() -> DomainError {
    DomainError::Conflict("原执行未获一次性启动许可或终态尚未发布；读取原回执，禁止重跑业务".into())
}
fn remaining(until: Timestamp) -> DomainResult<Duration> {
    let milliseconds = until
        .unix_millis()
        .checked_sub(Timestamp::now().unix_millis())
        .filter(|value| *value > 0)
        .ok_or_else(stopped)?;
    Ok(Duration::from_millis(u64::try_from(milliseconds).map_err(|_| stopped())?))
}
fn readable(receipt: Receipt) -> DomainResult<Receipt> {
    if receipt.may_confirm_start || receipt.may_execute {
        return Err(stopped());
    }
    Ok(receipt)
}
pub(crate) async fn run(
    registry: Arc<Registry>,
    identity: Identity,
    handler: Handler,
    deadline: Instant,
) -> DomainResult<Receipt> {
    identity.validate()?;
    let client = registry.execution.binding.clone().ok_or_else(stopped)?;
    client.identity(deadline).await?;
    let context = client.context(&identity, deadline).await?;
    let admitted = match client.claim(&identity, &context, deadline).await {
        Ok(receipt) => receipt,
        Err(error) => {
            return match client.lookup(&identity, &context, deadline).await {
                Ok(receipt) => readable(receipt),
                Err(_) => Err(error),
            };
        }
    };
    if !admitted.may_confirm_start {
        return readable(admitted);
    }
    if admitted.may_execute
        || admitted.state != "admitted"
        || admitted.completion_state != "admitted"
        || admitted.outcome.is_some()
        || !admitted.source_current
    {
        return Err(stopped());
    }
    let start_deadline = deadline.min(Instant::now() + remaining(admitted.start_lease_expires_at)?);
    let running = match client.validate(&admitted, start_deadline).await {
        Ok(receipt) => receipt,
        Err(error) => {
            // Status is evidence only; a lost validate reply can never grant handler execution.
            return match client.status(&admitted, deadline).await {
                Ok(receipt) => readable(receipt),
                Err(_) => Err(error),
            };
        }
    };
    if !running.may_execute {
        return readable(running);
    }
    if running.may_confirm_start
        || running.state != "running"
        || running.completion_state != "admitted"
        || running.outcome.is_some()
        || !running.source_current
    {
        return Err(stopped());
    }
    remaining(running.start_lease_expires_at)?;
    let handler_budget =
        remaining(running.execution_lease_expires_at.ok_or_else(stopped)?)?.min(Duration::from_mins(5));
    let started = std::time::Instant::now();
    let result =
        tokio::time::timeout(handler_budget, EXECUTION_ID.scope(identity.execution_id(), handler(identity.partition)))
            .await
            .map_err(|_| DomainError::Timeout("执行租约已到期，业务结果未知；禁止再次运行原身份".into()))?;
    let completion_deadline = Instant::now() + Duration::from_secs(110);
    publish_known(client, running, result, registry, crate::millis(started), completion_deadline).await
}
fn safe_note(result: &TaskOutcome) -> &'static str {
    if !result.ok {
        "云任务已执行，业务返回失败"
    } else if result.skipped {
        "云任务已执行，业务如实跳过"
    } else if result.degraded {
        "云任务已执行，业务明确降级"
    } else {
        "云任务已执行，等待平台终态回执"
    }
}
async fn publish_known(
    client: Arc<Client>,
    original: Receipt,
    result: TaskOutcome,
    registry: Arc<Registry>,
    elapsed: u64,
    deadline: Instant,
) -> DomainResult<Receipt> {
    // Only known results enter this task. Caller cancellation cannot discard a result while hashing artifacts.
    let task = tokio::spawn(async move {
        registry.record(original.kind.runtime(), result.ok, elapsed);
        tasks::note_set(&registry.notes, original.kind.runtime(), safe_note(&result).to_owned());
        let outcome =
            tokio::time::timeout_at(deadline, artifacts::summarize(&result, &registry.execution.artifact_roots))
                .await
                .map_err(|_| DomainError::Timeout("制品摘要超时；原业务不得重跑".into()))??;
        let receipt = match client.complete(&original, &outcome, deadline).await {
            Ok(receipt) => receipt,
            Err(error) => match client.status(&original, deadline).await {
                Ok(receipt) if receipt.outcome.as_ref().is_none_or(|known| known == &outcome) => receipt,
                Ok(_) => return Err(DomainError::Conflict("原回执的已知结果不同；禁止重跑或覆盖".into())),
                _ => return Err(error),
            },
        };
        readable(receipt)
    });
    task.await.map_err(|_| DomainError::Internal("已知回执提交任务中断；读取原回执，禁止重跑".into()))?
}
#[cfg(test)]
mod tests;
