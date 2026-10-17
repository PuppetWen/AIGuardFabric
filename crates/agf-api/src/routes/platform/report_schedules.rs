//! Persistent report schedules and manual execution.
use super::*;
use crate::report_service::{self as service, SCHEDULES, ScheduleRecord};
use agf_core::ids::TenantId;

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ReportScheduleBody {
    pub name: String,
    pub kind: Option<String>,
    pub format: Option<String>,
    pub cron: String,
    pub window_secs: Option<i64>,
    #[serde(default)]
    pub channel_ids: Vec<String>,
    #[serde(default)]
    pub recipients: Vec<String>,
    pub enabled: Option<bool>,
}

pub async fn report_schedules(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "reports", "read")?;
    let mut rows = service::schedules(&state, principal.tenant).await?;
    let enabled = query.filter_bool("enabled")?;
    let kind = query.filter("kind").map(parse_report_kind).transpose()?;
    rows.retain(|row| {
        row.schedule
            .as_ref()
            .is_some_and(|s| enabled.is_none_or(|v| s.enabled == v) && kind.is_none_or(|v| s.kind == v))
    });
    Ok(Json(serde_json::json!({"items":rows,"total":rows.len(),"timezone":"UTC","scheduler":"server","seeded_now":0})))
}

pub async fn create_report_schedule(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<ReportScheduleBody>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "reports", "write")?;
    let window_secs = body.window_secs.unwrap_or(86_400);
    if body.name.trim().is_empty() || body.name.len() > 256 || !(60..=90 * 86_400).contains(&window_secs) {
        return Err(DomainError::Validation("名称须为 1..256 字节，统计窗口须为 60 秒至 90 天".into()).into());
    }
    validate_cron(&body.cron)?;
    if !body.recipients.is_empty() {
        return Err(
            DomainError::Validation("请先在设置中配置通知渠道的收件人，再通过 channel_ids 选择渠道".into()).into()
        );
    }
    let channel_ids = validate_channels(&state, principal.tenant, &body.channel_ids).await?;
    let schedule = ReportSchedule {
        id: Id::new(),
        tenant_id: principal.tenant,
        name: body.name.trim().into(),
        kind: parse_report_kind(body.kind.as_deref().unwrap_or("posture"))?,
        format: parse_report_format(body.format.as_deref().unwrap_or("markdown"))?,
        cron: body.cron.trim().into(),
        window_secs,
        channel_ids,
        recipients: Vec::new(),
        enabled: body.enabled.unwrap_or(true),
        last_generated_at: None,
        created_at: Timestamp::now(),
    };
    let id = schedule.id;
    let name = schedule.name.clone();
    let record = ScheduleRecord { schedule: Some(schedule), version: 1, content_version: 1, ..Default::default() };
    let record = audited_schedule_change(
        &state,
        &principal,
        id,
        AuditAction::Create,
        "report-schedule-create",
        Some(name),
        "创建周期报表计划（UTC）",
        |row| {
            if row.version != 0 || row.schedule.is_some() {
                return Err(DomainError::Conflict("计划编号已存在，请重试".into()));
            }
            *row = record;
            Ok(())
        },
    )
    .await?;
    Ok((axum::http::StatusCode::CREATED, Json(serde_json::json!({"schedule":record}))))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleUpdate {
    pub enabled: Option<bool>,
    pub expected_version: Option<u64>,
    pub name: Option<String>,
    pub kind: Option<String>,
    pub format: Option<String>,
    pub cron: Option<String>,
    pub window_secs: Option<i64>,
    pub channel_ids: Option<Vec<String>>,
}

pub async fn update_report_schedule(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ScheduleUpdate>,
) -> ApiResult<Json<ScheduleRecord>> {
    principal.require(&state, "reports", "write")?;
    let id = parse_id(&id, "report-schedule")?;
    let editing = body.name.is_some()
        || body.kind.is_some()
        || body.format.is_some()
        || body.cron.is_some()
        || body.window_secs.is_some()
        || body.channel_ids.is_some();
    let expected_version = body
        .expected_version
        .ok_or_else(|| DomainError::Validation("修改计划须提供 expected_version，请重新加载".into()))?;
    if !editing && body.enabled.is_none() {
        return Err(DomainError::Validation("没有要修改的计划字段".into()).into());
    }
    if body.name.as_ref().is_some_and(|v| v.trim().is_empty() || v.len() > 256)
        || body.window_secs.is_some_and(|v| !(60..=90 * 86_400).contains(&v))
    {
        return Err(DomainError::Validation("名称须为 1..256 字节，统计窗口须为 60 秒至 90 天".into()).into());
    }
    if let Some(cron) = &body.cron {
        validate_cron(cron)?;
    }
    let kind = body.kind.as_deref().map(parse_report_kind).transpose()?;
    let format = body.format.as_deref().map(parse_report_format).transpose()?;
    let channels = match &body.channel_ids {
        Some(ids) => Some(validate_channels(&state, principal.tenant, ids).await?),
        None => None,
    };
    let record = audited_schedule_change(
        &state,
        &principal,
        id,
        AuditAction::Update,
        "report-schedule-update",
        None,
        "修改周期报表计划",
        |row| {
            if expected_version != row.version {
                return Err(DomainError::Conflict("计划已被修改，请重新加载后再编辑".into()));
            }
            if editing && row.lease_until.is_some_and(|until| until > Timestamp::now()) {
                return Err(DomainError::Conflict("计划正在执行或等待重试，请完成后编辑；仍可暂停".into()));
            }
            let schedule = row
                .schedule
                .as_mut()
                .ok_or_else(|| DomainError::NotFound { entity: "report-schedule", id: id.to_string() })?;
            if let Some(enabled) = body.enabled {
                schedule.enabled = enabled;
            }
            if let Some(name) = &body.name {
                schedule.name = name.trim().into();
            }
            if let Some(kind) = kind {
                schedule.kind = kind;
            }
            if let Some(format) = format {
                schedule.format = format;
            }
            if let Some(cron) = &body.cron {
                schedule.cron = cron.trim().into();
            }
            if let Some(window) = body.window_secs {
                schedule.window_secs = window;
            }
            if let Some(channels) = &channels {
                schedule.channel_ids.clone_from(channels);
            }
            if editing {
                row.content_version = row.content_version.saturating_add(1);
                row.claimed_at = None;
                row.lease_until = None;
                row.last_error = None;
            }
            row.version = row.version.saturating_add(1);
            Ok(())
        },
    )
    .await?;
    Ok(Json(record))
}

/// Report operators only need channel identity and availability, not secrets or recipients.
pub async fn report_channels(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "reports", "read")?;
    let rows = state
        .configurations
        .list::<crate::notification_config::StoredChannel>(principal.tenant, crate::notification_config::KIND)
        .await?;
    let items: Vec<_> = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id":row.id,"channel":row.channel,"enabled":row.enabled,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({"items":items})))
}

async fn validate_channels(state: &AppState, tenant: TenantId, raw: &[String]) -> ApiResult<Vec<Id>> {
    if raw.len() > 16 {
        return Err(DomainError::Validation("每个计划最多 16 个通知渠道".into()).into());
    }
    let mut ids = Vec::new();
    for value in raw {
        let id = parse_id(value, "notification-channel")?;
        if ids.contains(&id) {
            continue;
        }
        let channel = state
            .configurations
            .get::<crate::notification_config::StoredChannel>(tenant, crate::notification_config::KIND, id)
            .await?;
        if !channel.is_some_and(|row| row.enabled) {
            return Err(DomainError::Validation("通知渠道不存在或已停用".into()).into());
        }
        ids.push(id);
    }
    Ok(ids)
}

#[derive(Debug, Deserialize)]
pub struct DeleteScheduleQuery {
    pub expected_version: u64,
}

pub async fn delete_report_schedule(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<DeleteScheduleQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "reports", "write")?;
    let id = parse_id(&id, "report-schedule")?;
    // Keep a tombstone so an in-flight worker cannot accidentally recreate a deleted schedule.
    audited_schedule_change(
        &state,
        &principal,
        id,
        AuditAction::Delete,
        "report-schedule-delete",
        None,
        "删除周期报表计划",
        |row| {
            if row.schedule.is_none() {
                return Err(DomainError::NotFound { entity: "report-schedule", id: id.to_string() });
            }
            if row.version != query.expected_version {
                return Err(DomainError::Conflict("计划已被修改，请重新加载后再删除".into()));
            }
            if row.lease_until.is_some_and(|until| until > Timestamp::now()) {
                return Err(DomainError::Conflict("计划正在执行，请稍后删除".into()));
            }
            row.schedule = None;
            row.claimed_at = None;
            row.lease_until = None;
            Ok(())
        },
    )
    .await?;
    Ok(Json(serde_json::json!({"deleted":true})))
}

async fn audited_schedule_change<F>(
    state: &AppState,
    principal: &Principal,
    id: Id,
    action: AuditAction,
    actor: &str,
    name: Option<String>,
    note: &str,
    apply: F,
) -> ApiResult<ScheduleRecord>
where
    F: FnOnce(&mut ScheduleRecord) -> agf_core::error::DomainResult<()> + Send,
{
    let entry = AppState::audit_entry(
        principal.tenant,
        action,
        AuditOutcome::Success,
        AppState::audit_actor(principal, actor),
        AuditTarget::new("report-schedule", Some(id.to_string()), name),
        note,
    );
    let (row, sealed) =
        state.configurations.mutate_audited(principal.tenant, SCHEDULES, id, entry.clone(), apply).await?;
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的报表计划审计内存投影刷新失败");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(row)
}

pub async fn run_report_schedule(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "reports", "write")?;
    let id = parse_id(&id, "report-schedule")?;
    let origin = service::RunOrigin::Manual(AppState::audit_actor(&principal, "report-schedule-run"));
    let report = service::run_one(&state, principal.tenant, id, Timestamp::now(), origin)
        .await?
        .ok_or_else(|| DomainError::Conflict("该计划已有任务正在运行".into()))?;
    Ok(Json(serde_json::json!({"report":report})))
}

pub fn parse_report_format(raw: &str) -> Result<ReportFormat, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "markdown" | "md" => Ok(ReportFormat::Markdown),
        "pdf" => Ok(ReportFormat::Pdf),
        "html" => Ok(ReportFormat::Html),
        "csv" => Ok(ReportFormat::Csv),
        "json" => Ok(ReportFormat::Json),
        _ => Err(DomainError::Validation("输出格式须为 markdown/pdf/html/csv/json".into()).into()),
    }
}

pub fn validate_cron(raw: &str) -> Result<(), ApiError> {
    crate::report_cron::Cron::parse(raw).map(|_| ()).map_err(Into::into)
}
