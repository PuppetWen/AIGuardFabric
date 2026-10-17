use super::*;
use futures::stream::{self, StreamExt};

/// A per-job lease permits independent channels and tenants to send concurrently.
pub async fn attempt(state: &AppState, tenant: TenantId, id: Id, now: Timestamp) -> DomainResult<Value> {
    let token = Id::new();
    let mut claimed = false;
    let queue = state
        .configurations
        .mutate::<Queue, _>(tenant, KIND, queue_id(tenant), |queue| {
            let Some(job) = queue.jobs.get_mut(&id) else {
                return Ok(());
            };
            if job.completed_at.is_some() || job.next_at > now || job.lease_until.is_some_and(|at| at > now) {
                return Ok(());
            }
            if job.remaining_attempts == 0 || job.expires_at <= now {
                job.status = "failed".into();
                job.completed_at = Some(now);
                job.lease_token = None;
                job.lease_until = None;
                job.receipt = Some(json!({"channel_id":job.channel_id,"kind":job.channel,
                    "outcome":"failed","attempts":job.attempts,"receipt":null,
                    "error":"通知重试次数或时间已用尽，请检查渠道后手动重试",
                    "mocked":job.mocked && job.channel != ChannelKind::InApp,"at":now}));
                return Ok(());
            }
            let rate = queue.rate.entry(job.channel_id).or_default();
            rate.retain(|at| *at > now.unix_secs() - 60);
            if rate.len() >= 60 {
                job.next_at = now.offset_secs(60);
                return Ok(());
            }
            rate.push(now.unix_secs());
            job.attempts = job.attempts.saturating_add(1);
            job.remaining_attempts -= 1;
            job.status = "sending".into();
            job.lease_token = Some(token);
            job.lease_until = Some(now.offset_secs(120));
            claimed = true;
            Ok(())
        })
        .await?;
    let Some(job) = queue.jobs.get(&id).cloned() else {
        return Err(DomainError::NotFound { entity: "notification", id: id.to_string() });
    };
    if !claimed {
        return Ok(view(&job));
    }
    let result = send(state, tenant, &job).await;
    let finished = Timestamp::now().max(now);
    let queue = state
        .configurations
        .mutate::<Queue, _>(tenant, KIND, queue_id(tenant), |queue| {
            let Some(current) = queue.jobs.get_mut(&id) else {
                return Ok(());
            };
            if current.lease_token != Some(token) {
                return Ok(());
            }
            let (outcome, receipt, error) = match &result {
                Ok(receipt) => ("delivered", Some(serde_json::to_value(receipt)?), None),
                Err(SendError::Cancelled(message)) => ("suppressed", None, Some(message.clone())),
                Err(SendError::Retry(message)) => ("failed", None, Some(message.clone())),
            };
            let terminal = outcome != "failed" || current.remaining_attempts == 0 || current.expires_at <= finished;
            current.status = if terminal { outcome.into() } else { "retrying".into() };
            current.lease_token = None;
            current.lease_until = None;
            if terminal {
                current.completed_at = Some(finished);
                if outcome != "failed" {
                    current.payload = None;
                }
            } else {
                current.next_at =
                    finished.offset_secs((30_i64 * (1_i64 << current.attempts.min(6).saturating_sub(1))).min(900));
            }
            current.receipt = Some(json!({
                "channel_id":current.channel_id,"kind":current.channel,"outcome":outcome,
                "attempts":current.attempts,"receipt":receipt,"error":error,
                "mocked":current.mocked && current.channel != ChannelKind::InApp,"at":finished,
            }));
            Ok(())
        })
        .await?;
    queue.jobs.get(&id).map(view).ok_or_else(|| DomainError::Internal("通知任务保存后缺失".into()))
}

enum SendError {
    Retry(String),
    Cancelled(String),
}

async fn send(
    state: &AppState,
    tenant: TenantId,
    job: &Job,
) -> Result<agf_correlate::notify::ChannelReceipt, SendError> {
    if job.channel != ChannelKind::InApp && job.mocked != state.config.mock_mode {
        return Err(SendError::Cancelled("运行模式已改变，请确认当前模式后重新发起通知".into()));
    }
    let row = state
        .configurations
        .get::<StoredChannel>(tenant, crate::notification_config::KIND, job.channel_id)
        .await
        .map_err(|_| SendError::Retry("读取通知渠道失败".into()))?
        .filter(|row| row.enabled)
        .ok_or_else(|| SendError::Cancelled("通知渠道已停用或删除".into()))?;
    let message =
        decrypt(state, tenant, job).map_err(|_| SendError::Retry("通知正文解密失败，请检查加密主密钥".into()))?;
    if let Some(escalation) = message.subject_kind.strip_prefix("alert-escalation:") {
        let level = escalation
            .split_once(':')
            .and_then(|(_, level)| level.parse::<u8>().ok())
            .filter(|level| (1..=3).contains(level))
            .ok_or_else(|| SendError::Cancelled("升级通知层级无效".into()))?;
        crate::alert_escalation::permit_delivery(state, tenant, message.subject_id, level, job.channel).await.map_err(
            |error| match error {
                DomainError::Forbidden(_)
                | DomainError::Unauthenticated(_)
                | DomainError::NotFound { .. }
                | DomainError::PreconditionFailed(_)
                | DomainError::TenantViolation { .. } => SendError::Cancelled(error.to_string()),
                other => SendError::Retry(other.to_string()),
            },
        )?;
    }
    // Report subscriptions bypass alert severity filters; channel disable still takes effect.
    if message.subject_kind != "report" && message.severity < row.min_severity {
        return Err(SendError::Cancelled("通知低于渠道当前最低等级".into()));
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(25),
        crate::notification_delivery::send_one(state, tenant, &row, &message),
    )
    .await
    .map_err(|_| SendError::Retry("通知投递超时；将按原幂等编号重试".into()))?
    .map_err(SendError::Retry)
}

/// At most eight concurrent deliveries; no database or process mutex spans network I/O.
pub async fn tick(state: &AppState, now: Timestamp) -> DomainResult<usize> {
    let mut work = Vec::new();
    for tenant in crate::tenant_directory::list(state).await? {
        let queue: Queue = state.configurations.get(tenant.id, KIND, queue_id(tenant.id)).await?.unwrap_or_default();
        let completed: Vec<_> = queue.jobs.values().filter_map(|job| job.completed_at).collect();
        if completed.len() > MAX_COMPLETED || completed.iter().any(|at| at.offset_secs(30 * 86400) <= now) {
            state
                .configurations
                .mutate::<Queue, _>(tenant.id, KIND, queue_id(tenant.id), |queue| {
                    prune(queue, now);
                    Ok(())
                })
                .await?;
        }
        if !tenant.enabled {
            continue;
        }
        let mut jobs: Vec<_> = queue
            .jobs
            .values()
            .filter(|job| {
                job.completed_at.is_none() && job.next_at <= now && job.lease_until.is_none_or(|at| at <= now)
            })
            .collect();
        jobs.sort_by_key(|job| (std::cmp::Reverse(job.severity), job.created_at));
        work.extend(jobs.into_iter().take(32).map(|job| (tenant.id, job.id)));
    }
    let results: Vec<_> = stream::iter(work)
        .map(|(tenant, id)| async move { attempt(state, tenant, id, now).await })
        .buffer_unordered(8)
        .collect()
        .await;
    let mut delivered = 0;
    for result in results {
        match result {
            Ok(value) => delivered += usize::from(value["outcome"] == "delivered"),
            Err(error) => tracing::warn!(%error, "notification queue attempt failed"),
        }
    }
    Ok(delivered)
}

pub async fn run_loop(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(error) = tick(&state, Timestamp::now()).await {
            tracing::warn!(%error, "notification queue iteration failed");
        }
    }
}
