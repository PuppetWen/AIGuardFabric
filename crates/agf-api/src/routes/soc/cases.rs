//! 案件端点：列表 / 创建 / 详情 / 状态 / 时间线 / SLA / 剧本执行。

use super::*;

// ===========================================================================
// 案件
// ===========================================================================

/// 案件列表（`GET /api/v1/cases`）。
///
/// # Errors
/// 过滤参数非法。
pub async fn list_cases(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let state_filter = match query.filter("state") {
        Some(raw) => Some(parse_case_state(raw)?),
        None => None,
    };
    let cases = state.store.case_list_durable(principal.tenant).await?;
    let cases: Vec<_> = match state_filter {
        Some(want) => cases.into_iter().filter(|c| c.state == want).collect(),
        None => cases,
    };
    let page =
        query.paginate_vec(&cases, |c| format!("{} {} {}", c.code, c.title, c.summary), |c| c.created_at.to_rfc3339());
    let mut response = query.render_page(&page)?;
    response["can_write"] = serde_json::json!(principal.require(&state, "cases", "write").is_ok());
    Ok(Json(response))
}

/// 新建案件 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct CaseBody {
    /// 标题。
    pub title: String,
    /// 摘要。
    #[serde(default)]
    pub summary: String,
    /// 严重等级（默认 `medium`）。
    #[serde(default)]
    pub severity: Option<String>,
    /// 关联告警。
    #[serde(default)]
    pub alert_ids: Vec<String>,
    /// 关联发现。
    #[serde(default)]
    pub finding_ids: Vec<String>,
    /// 关联资产。
    #[serde(default)]
    pub asset_ids: Vec<String>,
    /// 负责人。
    #[serde(default)]
    pub owner: Option<String>,
}

/// 新建案件（`POST /api/v1/cases`）。
///
/// # Errors
/// 参数非法。
pub async fn create_case(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<CaseBody>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "cases", "write")?;
    if body.title.trim().is_empty()
        || body.title.len() > 800
        || body.summary.len() > 40_000
        || body.owner.as_ref().is_some_and(|owner| owner.len() > 200)
        || body.alert_ids.len() + body.finding_ids.len() + body.asset_ids.len() > 1000
    {
        return Err(ApiError::new(DomainError::Validation("案件标题、说明或关联对象数量超出范围".to_string())));
    }
    let severity = match body.severity.as_deref() {
        Some(raw) => Severity::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?,
        None => Severity::Medium,
    };
    let alert_ids = body.alert_ids.iter().map(|a| parse_id(a, "alert")).collect::<Result<Vec<_>, _>>()?;
    let finding_ids = body.finding_ids.iter().map(|a| parse_id(a, "finding")).collect::<Result<Vec<_>, _>>()?;
    let asset_ids = body.asset_ids.iter().map(|a| parse_id(a, "asset")).collect::<Result<Vec<_>, _>>()?;
    for id in &asset_ids {
        if state.store.asset_get_durable(principal.tenant, *id).await?.is_none() {
            return Err(DomainError::Validation("关联资产不存在于当前租户".into()).into());
        }
    }
    for id in &finding_ids {
        if state.store.finding_get_durable(principal.tenant, *id).await?.is_none() {
            return Err(DomainError::Validation("关联发现不存在于当前租户".into()).into());
        }
    }
    for id in &alert_ids {
        if state.store.alert_get_durable(principal.tenant, *id).await?.is_none() {
            return Err(DomainError::Validation("关联告警不存在于当前租户".into()).into());
        }
    }
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Create,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "case-create"),
        AuditTarget::new("case", None, None),
        "新建案件",
    );
    let case = state
        .store
        .case_create_durable(
            principal.tenant,
            &body.title,
            &body.summary,
            severity,
            &alert_ids,
            &finding_ids,
            &asset_ids,
            body.owner.as_deref(),
            &principal.display(),
            Some(audit),
        )
        .await?;
    state.publish(crate::state::WsEvent {
        kind: "case".to_string(),
        tenant_id: principal.tenant,
        at: Timestamp::now(),
        payload: serde_json::json!({ "case_id": case.id, "code": case.code }),
    });
    Ok((axum::http::StatusCode::CREATED, Json(serde_json::json!({ "case": case }))))
}

/// 案件详情（`GET /api/v1/cases/{id}`）。
///
/// # Errors
/// 案件不存在。
pub async fn get_case(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let case_id = parse_id(&id, "case")?;
    let Some(case) = state.store.case_get_durable(principal.tenant, case_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "case", id: id.clone() }));
    };
    let timeline = state.store.case_events_durable(principal.tenant, case_id).await?;
    Ok(Json(serde_json::json!({ "case": case, "timeline": timeline,
        "can_write":principal.require(&state,"cases","write").is_ok() })))
}

/// 案件状态流转 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct CaseStateBody {
    /// 目标状态：`new`/`investigating`/`containing`/`resolved`/`closed`。
    pub state: String,
    /// 处置结论（关闭时建议填写）。
    #[serde(default)]
    pub resolution: Option<String>,
}

/// 案件状态流转（`POST /api/v1/cases/{id}/state`）。
///
/// # Errors
/// 案件不存在或非法流转。
pub async fn set_case_state(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<CaseStateBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "write")?;
    let case_id = parse_id(&id, "case")?;
    let target = parse_case_state(&body.state)?;
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Update,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "case-state"),
        AuditTarget::new("case", Some(case_id.to_string()), None),
        &format!("案件状态流转到 {}", target.as_str()),
    );
    let case = state
        .store
        .case_set_state_audited_durable(
            principal.tenant,
            case_id,
            target,
            body.resolution,
            &principal.display(),
            Some(audit),
        )
        .await?;
    Ok(Json(serde_json::json!({ "case": case })))
}

/// 案件时间线（`GET /api/v1/cases/{id}/timeline`）。
///
/// # Errors
/// 案件不存在。
pub async fn case_timeline(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let case_id = parse_id(&id, "case")?;
    if state.store.case_get_durable(principal.tenant, case_id).await?.is_none() {
        return Err(ApiError::new(DomainError::NotFound { entity: "case", id: id.clone() }));
    }
    let events = state.store.case_events_durable(principal.tenant, case_id).await?;
    Ok(Json(serde_json::json!({ "case_id": case_id, "events": events })))
}

/// 追加案件时间线 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct CaseTimelineBody {
    /// 备注。
    pub note: String,
    /// 事件类型（默认 `comment`）。
    #[serde(default)]
    pub kind: Option<String>,
}

/// 追加案件时间线（`POST /api/v1/cases/{id}/timeline`）。
///
/// # Errors
/// 案件不存在或事件类型非法。
pub async fn append_case_timeline(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<CaseTimelineBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "write")?;
    let case_id = parse_id(&id, "case")?;
    let kind = match body.kind.as_deref() {
        Some(raw) => parse_case_event_kind(raw)?,
        None => CaseEventKind::Comment,
    };
    let event =
        state.store.case_add_event_durable(principal.tenant, case_id, kind, &principal.display(), &body.note).await?;
    Ok(Json(serde_json::json!({ "event": event })))
}

/// 案件 SLA（`GET /api/v1/cases/{id}/sla`）。
///
/// 数据来源：案件台账（`created_at` 起点 + `severity` 取策略）+ **案件时间线**。
/// 三档里程碑不是编造的，而是由真实时间线事件推导：
///
/// | 目标 | 推导规则 |
/// |---|---|
/// | 首次响应 | 最早的**人工**事件（`automated = false` 的 `assigned`/`state-changed`/`comment`） |
/// | 遏制 | 最早的处置类事件（`containment`/`isolation`/`credential-revoked`/`blocklisted`） |
/// | 解决 | 案件 `closed_at`，否则最早的 `closed` 事件 |
///
/// 早于时钟起点的里程碑会被引擎拒绝（`SlaError::InvalidTime`），这里跳过并在
/// `ignored_milestones` 里如实列出，不静默吞掉。
///
/// SLA 两个派生字段事务写回台账；不覆盖案件状态、处置结论或时间线。
/// 暂停窗口无存储面 ⇒ 暂停时长恒 0（`TODO(correlate-sla-persist)`）。
///
/// # Errors
/// 权限不足（`cases:read`）、id 非法（400）、案件不存在（404）、存储错误。
pub async fn case_sla(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let case_id = parse_id(&id, "case")?;
    let Some(case) = state.store.case_get_durable(principal.tenant, case_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "case", id }));
    };
    let now = Timestamp::now();
    let mut clock = sla_clock(&principal.tenant, case.id, case.created_at, case.severity)?;
    let events = state.store.case_events_durable(principal.tenant, case_id).await?;

    let candidates: [(SlaTarget, Option<Timestamp>); 3] = [
        (SlaTarget::FirstResponse, first_human_touch(&events)),
        (SlaTarget::Containment, first_containment(&events)),
        (SlaTarget::Resolution, resolution_at(&case, &events)),
    ];
    let mut milestones: Vec<serde_json::Value> = Vec::new();
    let mut ignored: Vec<serde_json::Value> = Vec::new();
    for (target, at) in candidates {
        let Some(at) = at else { continue };
        match clock.reach(target, at, None) {
            Ok(()) => milestones.push(serde_json::json!({ "target": target.as_str(), "at": at })),
            Err(error) => {
                ignored.push(serde_json::json!({ "target": target.as_str(), "at": at, "reason": error.to_string() }));
            }
        }
    }

    let (due_at, breached) = agf_correlate::sla::case_sla_fields(&clock, now);
    let overall = clock.overall(now);
    let next_due = clock.next_due_at(now);
    let stored_before = serde_json::json!({
        "sla_due_at": case.sla_due_at,
        "sla_breached": case.sla_breached,
    });
    // 读时刷新：SLA 是**派生字段**，这里把引擎结论写回案件的两个派生字段，
    // 保证控制台/报表读到的与引擎判定一致（幂等；不触碰状态/决议/时间线）。
    let written = state.store.case_set_sla_durable(principal.tenant, case.id, Some(due_at), breached).await?;
    state
        .audit(
            principal.tenant,
            AuditAction::Read,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "case-sla"),
            AuditTarget::new("case", Some(case_id.to_string()), Some(case.code.clone())),
            &format!("案件 SLA 判定：{}({})，写回派生字段", overall.as_str(), case.severity.as_str()),
        )
        .await?;
    Ok(Json(serde_json::json!({
        "case_id": case.id,
        "case_code": case.code,
        "case_state": case.state.as_str(),
        "severity": case.severity.as_str(),
        "tenant_id": principal.tenant,
        "judged_at": now,
        "started_at": clock.started_at,
        "policy": clock.policy,
        "overall": overall.as_str(),
        "breached": breached,
        "due_at": due_at,
        "overdue_secs": clock.overdue_secs(now),
        "next_due": next_due.map(|(target, due)| serde_json::json!({
            "target": target.as_str(),
            "due_at": due,
        })),
        "escalation_due": clock.due_escalation(now).map(|s: EscalationStep| serde_json::json!({
            "level": s.level,
            "target": s.target.as_str(),
        })),
        "targets": clock.statuses(now),
        "milestones": milestones,
        "ignored_milestones": ignored,
        "timeline_events": events.len(),
        "stored_before": stored_before,
        "stored_after": {
            "sla_due_at": written.sla_due_at,
            "sla_breached": written.sla_breached,
        },
        "written_back": true,
        "notes": [
            "SLA 结论为派生值：本 GET 会幂等写回案件台账的 sla_due_at / sla_breached（控制台口径与引擎一致）",
            "暂停窗口无存储面 ⇒ 暂停时长为 0；工作日历不支持（TODO(correlate-sla-calendar)）",
        ],
    })))
}
