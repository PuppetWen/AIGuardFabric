//! 由 `schedulerx3.rs` 拆分：`impl_SchedulerX3Adapter`/`parse_jobs` 等 5 项（纯搬移，逻辑不变）。
use super::*;

/// 解析任务列表响应。
#[must_use]
pub fn parse_jobs(body: &serde_json::Value, tenant_id: TenantId) -> Vec<SchedulerX3Job> {
    json_array(body, &["Job", "Jobs"])
        .into_iter()
        .map(|item| {
            let job_kind = json_str(item, "JobName").map(|name| normalize_job_kind(&name)).unwrap_or_default();
            SchedulerX3Job {
                cloud_parameters: BTreeMap::new(),
                id: deterministic_id(NS_SCHEDULE, &format!("{tenant_id}/{job_kind}")),
                name: json_str(item, "JobName").unwrap_or_default(),
                job_kind: job_kind.clone(),
                cron: json_str(item, "TimeExpression").unwrap_or_else(|| "0 0 * * *".to_string()),
                shard_count: json_i64(item, "ShardCount").unwrap_or(1).max(1).unsigned_abs() as u32,
                max_retries: json_i64(item, "MaxAttempt").unwrap_or(3).max(0).unsigned_abs().try_into().unwrap_or(3),
                depends_on: Vec::new(),
                enabled: item.get("Enabled").and_then(serde_json::Value::as_bool).unwrap_or(true),
                backend: ScheduleBackend::SchedulerX3,
                cloud_job_id: json_str(item, "JobId"),
                handler: json_str(item, "Handler").unwrap_or_default(),
            }
        })
        .collect()
}

/// 把云侧任务名归一化为平台 `job_kind`。
#[must_use]
pub fn normalize_job_kind(name: &str) -> String {
    let lower = name.to_ascii_lowercase().replace([' ', '_'], "-");
    PLATFORM_JOB_KINDS.iter().find(|kind| lower.contains(*kind)).map_or_else(|| lower, |kind| (*kind).to_string())
}

/// 解析执行历史响应。
#[must_use]
pub fn parse_executions(body: &serde_json::Value) -> Vec<SchedulerX3Execution> {
    json_array(body, &["Execution", "Executions"])
        .into_iter()
        .map(|item| SchedulerX3Execution {
            job_id: json_str(item, "JobId").unwrap_or_default(),
            execution_id: json_str(item, "ExecutionId").or_else(|| json_str(item, "Id")).unwrap_or_default(),
            shard_index: json_i64(item, "ShardIndex").and_then(|v| v.try_into().ok()),
            status: json_str(item, "Status").unwrap_or_else(|| "UNKNOWN".to_string()),
            at: json_i64(item, "StartTime")
                .or_else(|| json_i64(item, "ScheduleTime"))
                .and_then(|ms| Timestamp::from_unix_millis(ms).ok()),
            scheduled_at_raw: None,
            duration_ms: json_i64(item, "DurationMs").and_then(|v| v.try_into().ok()),
            duration_native: None,
            result: json_str(item, "Result").or_else(|| json_str(item, "Message")).unwrap_or_default(),
        })
        .collect()
}

/// 校验平台任务定义的自洽性（cron 段数、分片范围、重试范围、依赖可达）。
///
/// # Errors
/// 返回全部问题描述（空则合法）。
pub fn validate_platform_jobs(jobs: &[SchedulerX3Job]) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    if jobs.len() != PLATFORM_JOB_KINDS.len() {
        problems.push(format!("平台任务数应为 {}，实际 {}", PLATFORM_JOB_KINDS.len(), jobs.len()));
    }
    for kind in PLATFORM_JOB_KINDS {
        if !jobs.iter().any(|j| j.job_kind == kind) {
            problems.push(format!("缺少任务类型 {kind}"));
        }
    }
    for job in jobs {
        let fields = job.cron.split_whitespace().count();
        if !(5..=6).contains(&fields) {
            problems.push(format!("任务 {} 的 cron 段数非法（{fields} 段）: {}", job.job_kind, job.cron));
        }
        if job.shard_count == 0 || job.shard_count > 64 {
            problems.push(format!("任务 {} 的分片数超出 1-64: {}", job.job_kind, job.shard_count));
        }
        if job.max_retries > 10 {
            problems.push(format!("任务 {} 的重试次数过大: {}", job.job_kind, job.max_retries));
        }
        if !job.dependencies_satisfied(jobs) {
            problems.push(format!("任务 {} 依赖了批次外的任务 id", job.job_kind));
        }
        if job.id == Id::nil() {
            problems.push(format!("任务 {} 缺少 id", job.job_kind));
        }
    }
    if problems.is_empty() { Ok(()) } else { Err(problems) }
}
