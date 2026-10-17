//! Durable reports and scheduled jobs. A lease and deterministic report id prevent duplicate artifacts.
use crate::{report_cron::Cron, state::AppState};
use agf_core::{
    audit::{AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    report::{Report, ReportFormat, ReportKind, ReportSchedule},
    time::{TimeRange, Timestamp},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REPORTS: &str = "report-artifact";
pub const SCHEDULES: &str = "report-schedule";

#[derive(Debug)]
pub enum RunOrigin {
    Manual(AuditActor),
    Scheduled,
}

#[derive(Serialize, Deserialize)]
struct StoredReport {
    #[serde(flatten)]
    report: Report,
    #[serde(default)]
    artifact_base64: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScheduleRecord {
    #[serde(default)]
    pub version: u64,
    /// 不随暂停/恢复改变，避免重试生成重复制品。
    #[serde(default)]
    pub content_version: u64,
    #[serde(flatten)]
    pub schedule: Option<ReportSchedule>,
    pub claimed_at: Option<Timestamp>,
    pub lease_until: Option<Timestamp>,
    pub last_report_id: Option<Id>,
    pub last_error: Option<String>,
}

pub async fn prepare(
    state: &AppState,
    tenant: TenantId,
    kind: ReportKind,
    title: String,
    range: TimeRange,
    format: ReportFormat,
    actor: Option<Id>,
) -> DomainResult<Report> {
    let markdown = crate::routes::platform::render_report(state, tenant, kind, &range).await?;
    let markdown =
        format!("# {}\n{}", title.replace(['\r', '\n'], " "), markdown.split_once('\n').map_or("", |(_, body)| body));
    let mut report = crate::store::new_report(tenant, kind, title, range, markdown, actor);
    report.format = format;
    finalise(&mut report)?;
    Ok(report)
}

fn finalise(report: &mut Report) -> DomainResult<()> {
    let (bytes, _) = crate::report_artifact::encode(report)?;
    report.artifact_bytes = Some(bytes.len() as u64);
    report.content_hash = Some(hex::encode(Sha256::digest(&bytes)));
    report.artifact_ref = Some(format!("reports/{}/{}", report.tenant_id, report.id));
    Ok(())
}

/// Manual only: require the authenticated actor and re-encode/hash the final assisted body.
pub async fn add_model_review(state: &AppState, principal: &crate::Principal, report: &mut Report) -> DomainResult<()> {
    if report.tenant_id != principal.tenant {
        return Err(DomainError::Forbidden("Report belongs to another tenant".into()));
    }
    let snapshot =
        crate::security_analysis::load_report(state, principal, report.id, report.kind, &report.range).await?;
    let analysis = crate::security_analysis::analyze(state, principal, snapshot).await?;
    let body = report.body.get_or_insert_with(String::new);
    body.push_str(&crate::security_analysis::markdown(&analysis));
    finalise(report)
}

pub async fn save_audited(state: &AppState, report: &Report, audit: AuditLog) -> DomainResult<()> {
    let (bytes, _) = crate::report_artifact::encode(report)?;
    let stored = StoredReport { report: report.clone(), artifact_base64: Some(STANDARD.encode(bytes)) };
    let sealed =
        state.configurations.create_audited(report.tenant_id, REPORTS, report.id, &stored, audit.clone()).await?;
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的报表审计内存投影刷新失败");
        }
    } else {
        state.store.audit_append_durable(audit).await?;
    }
    Ok(())
}

/// Keep the original bytes across renderer upgrades so hashes and past reports remain stable.
pub async fn artifact(state: &AppState, report: &Report) -> DomainResult<(Vec<u8>, &'static str)> {
    if let Some(stored) = state.configurations.get::<StoredReport>(report.tenant_id, REPORTS, report.id).await? {
        if let Some(encoded) = stored.artifact_base64 {
            let bytes = STANDARD.decode(encoded).map_err(|_| DomainError::Internal("报表制品编码损坏".into()))?;
            if report.content_hash.as_deref() != Some(hex::encode(Sha256::digest(&bytes)).as_str()) {
                return Err(DomainError::Internal("报表制品完整性校验失败".into()));
            }
            return Ok((bytes, crate::report_artifact::mime(report.format)));
        }
    }
    crate::report_artifact::encode(report)
}

pub async fn list(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Report>> {
    // Merge legacy seeded / campaign reports with newly persisted artifacts.
    let mut rows = state.store.report_list(tenant)?;
    for row in state.configurations.list::<Report>(tenant, REPORTS).await? {
        rows.retain(|old| old.id != row.id);
        rows.push(row);
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.created_at));
    Ok(rows)
}

pub async fn get(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Option<Report>> {
    if let Some(report) = state.configurations.get(tenant, REPORTS, id).await? {
        return Ok(Some(report));
    }
    state.store.report_get(tenant, id)
}

pub async fn schedules(state: &AppState, tenant: TenantId) -> DomainResult<Vec<ScheduleRecord>> {
    state.configurations.list(tenant, SCHEDULES).await
}

pub async fn run_one(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    now: Timestamp,
    origin: RunOrigin,
) -> DomainResult<Option<Report>> {
    let manual = matches!(&origin, RunOrigin::Manual(_));
    let (actor, note) = match origin {
        RunOrigin::Manual(actor) => (actor, "立即生成周期报表"),
        RunOrigin::Scheduled => (AuditActor::system("agf-report-scheduler"), "定时生成周期报表"),
    };
    let mut claimed = false;
    let record = state
        .configurations
        .mutate::<ScheduleRecord, _>(tenant, SCHEDULES, id, |record| {
            let schedule = record
                .schedule
                .as_ref()
                .ok_or_else(|| DomainError::NotFound { entity: "report-schedule", id: id.to_string() })?;
            if record.lease_until.is_some_and(|until| until > now) {
                return Ok(());
            }
            // Retry a failed/interrupted run using its original data window and id.
            if record.claimed_at.is_none() {
                if !manual
                    && (!schedule.enabled
                        || !Cron::parse(&schedule.cron)?.matches(now)
                        || schedule.last_generated_at.is_some_and(|last| last.unix_secs() / 60 == now.unix_secs() / 60))
                {
                    return Ok(());
                }
                record.claimed_at =
                    Some(Timestamp::from_unix_secs(now.unix_secs() / 60 * 60).map_err(DomainError::Validation)?);
            }
            if !schedule.enabled && !manual {
                return Ok(());
            }
            record.lease_until = Some(now.offset_secs(300));
            claimed = true;
            Ok(())
        })
        .await?;
    if !claimed {
        return Ok(None);
    }
    let schedule = record.schedule.as_ref().ok_or_else(|| DomainError::Internal("missing claimed schedule".into()))?;
    let at = record.claimed_at.unwrap_or(now);
    let result = async {
        let report = generate_scheduled(state, schedule, at, record.content_version, actor, note).await?;
        // Save notification work with the claimed channel snapshot before releasing the plan.
        // A crash here retries the same report and dedup keys, without changing recipients.
        notify(state, schedule, &report).await?;
        Ok(report)
    }
    .await;
    state
        .configurations
        .mutate::<ScheduleRecord, _>(tenant, SCHEDULES, id, |current| {
            if current.claimed_at != record.claimed_at || current.content_version != record.content_version {
                return Ok(());
            }
            match &result {
                Ok(report) => {
                    if let Some(schedule) = current.schedule.as_mut() {
                        schedule.last_generated_at = Some(at);
                    }
                    current.last_report_id = Some(report.id);
                    current.claimed_at = None;
                    current.last_error = None;
                    current.lease_until = None;
                }
                Err(_) => {
                    current.last_error = Some("生成或保存失败，将在一分钟后重试；请检查服务日志与数据库".into());
                    current.lease_until = Some(now.offset_secs(60));
                }
            }
            Ok(())
        })
        .await?;
    result.map(Some)
}

async fn generate_scheduled(
    state: &AppState,
    schedule: &ReportSchedule,
    at: Timestamp,
    version: u64,
    actor: AuditActor,
    note: &str,
) -> DomainResult<Report> {
    let key = if version == 0 {
        format!("{}:{}", schedule.id, at.unix_secs())
    } else {
        format!("{}:{}:v{version}", schedule.id, at.unix_secs())
    };
    let id = deterministic_id("agf.scheduled-report", &key);
    if let Some(report) = get(state, schedule.tenant_id, id).await? {
        return Ok(report);
    }
    let mut report = prepare(
        state,
        schedule.tenant_id,
        schedule.kind,
        schedule.name.clone(),
        schedule.window_at(at),
        schedule.format,
        None,
    )
    .await?;
    report.id = id;
    report.schedule_id = Some(schedule.id);
    report.created_at = at;
    report.completed_at = Some(at);
    finalise(&mut report)?;
    let audit = AppState::audit_entry(
        schedule.tenant_id,
        AuditAction::Export,
        AuditOutcome::Success,
        actor,
        AuditTarget::new("report", Some(report.id.to_string()), Some(report.title.clone())),
        note,
    );
    match save_audited(state, &report, audit).await {
        Ok(()) => Ok(report),
        Err(DomainError::Conflict(_)) => get(state, schedule.tenant_id, id)
            .await?
            .ok_or_else(|| DomainError::Conflict("报表编号已被占用，请重新执行计划".into())),
        Err(error) => Err(error),
    }
}

/// Invoked by the main server every 15 seconds. Inactive tenants are never processed.
pub async fn tick(state: &AppState, now: Timestamp) -> DomainResult<usize> {
    let mut generated = 0;
    for tenant in crate::tenant_directory::list(state).await?.into_iter().filter(|row| row.enabled) {
        for record in schedules(state, tenant.id).await? {
            let Some(schedule) = record.schedule else {
                continue;
            };
            if !schedule.enabled || record.lease_until.is_some_and(|until| until > now) {
                continue;
            }
            if record.claimed_at.is_none()
                && (!Cron::parse(&schedule.cron)?.matches(now)
                    || schedule.last_generated_at.is_some_and(|at| at.unix_secs() / 60 == now.unix_secs() / 60))
            {
                continue;
            }
            match run_one(state, tenant.id, schedule.id, now, RunOrigin::Scheduled).await {
                Ok(Some(_)) => generated += 1,
                Ok(None) => {}
                Err(error) => tracing::warn!(%error,schedule=%schedule.id,"scheduled report failed"),
            }
        }
    }
    Ok(generated)
}

pub async fn notify(state: &AppState, schedule: &ReportSchedule, report: &Report) -> DomainResult<()> {
    let rows = state
        .configurations
        .list::<crate::notification_config::StoredChannel>(schedule.tenant_id, crate::notification_config::KIND)
        .await?
        .into_iter()
        .filter(|row| schedule.channel_ids.contains(&row.id))
        .map(|mut row| {
            row.min_severity = agf_core::enums::Severity::Info;
            row
        })
        .collect();
    let ids = crate::notification_outbox::enqueue(
        state,
        schedule.tenant_id,
        rows,
        "report",
        report.id,
        &report.title,
        &format!("报表已生成。请登录控制台报表页面查看或下载。报表编号：{}", report.id),
        agf_core::enums::Severity::Info,
    )
    .await?;
    // Queue persistence is required; delivery failures are retried by the independent worker.
    use futures::stream::{self, StreamExt};
    let mut work =
        stream::iter(ids)
            .map(|id| async move {
                crate::notification_outbox::attempt(state, schedule.tenant_id, id, Timestamp::now()).await
            })
            .buffer_unordered(8);
    while let Some(result) = work.next().await {
        if let Err(error) = result {
            tracing::warn!(%error, report=%report.id, "report notification pending");
        }
    }
    Ok(())
}

pub async fn run_loop(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(error) = tick(&state, Timestamp::now()).await {
            tracing::warn!(%error,"report scheduler iteration failed");
        }
    }
}
