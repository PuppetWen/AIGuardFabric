//! 报表端点：生成 / 列表 / 详情 / 下载 / 计划。

use super::*;

// ===========================================================================
// 报表
// ===========================================================================

/// 报表生成 Body。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ReportBody {
    /// 报表类型（`posture`/`findings`/`redteam`/`compliance`/`asset-inventory`/`drift`/`billing`/`incident`/`custom`）。
    #[serde(default)]
    pub kind: Option<String>,
    /// 标题（缺省按类型生成）。
    #[serde(default)]
    pub title: Option<String>,
    /// 统计窗口（秒，默认 24 小时）。
    #[serde(default)]
    pub window_secs: Option<i64>,
    #[serde(default)]
    pub format: Option<String>,
    /// Explicit manual model review; ordinary reports and schedules remain deterministic.
    #[serde(default)]
    pub model_assisted: bool,
}

/// 生成 Markdown 报表（`POST /api/v1/reports`）。
///
/// # Errors
/// 类型非法或存储错误。
pub async fn generate_report(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<ReportBody>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    principal.require(&state, "reports", "write")?;
    if body.model_assisted {
        crate::security_analysis::authorize(&state, &principal, crate::security_analysis::Purpose::Report, true)?;
    }
    let kind = match body.kind.as_deref() {
        Some(raw) => parse_report_kind(raw)?,
        None => ReportKind::Posture,
    };
    let window = body.window_secs.unwrap_or(86_400);
    if !(60..=90 * 86_400).contains(&window) {
        return Err(DomainError::Validation("报表窗口须为 60 秒至 90 天".into()).into());
    }
    let range = TimeRange::last_secs(window);
    let title = body.title.unwrap_or_else(|| format!("{} 报表", kind.as_str()));
    let format = parse_report_format(body.format.as_deref().unwrap_or("markdown"))?;
    if title.trim().is_empty() || title.len() > 256 {
        return Err(DomainError::Validation("报表标题须为 1..256 字节".into()).into());
    }
    let mut report =
        crate::report_service::prepare(&state, principal.tenant, kind, title, range, format, principal.subject_id)
            .await?;
    if body.model_assisted {
        crate::report_service::add_model_review(&state, &principal, &mut report).await?;
    }
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Export,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "report-generate"),
        AuditTarget::new("report", Some(report.id.to_string()), Some(report.title.clone())),
        "生成并保存报表",
    );
    crate::report_service::save_audited(&state, &report, audit).await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "report": report, "download": format!("/api/v1/reports/{}/download", report.id) })),
    ))
}

/// 报表列表（`GET /api/v1/reports`）。
///
/// # Errors
/// 权限不足。
pub async fn list_reports(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "reports", "read")?;
    let mut reports = crate::report_service::list(&state, principal.tenant).await?;
    if let Some(kind) = query.filter("kind") {
        reports.retain(|r| r.kind.as_str() == kind);
    }
    let page =
        query.paginate_vec(&reports, |r| format!("{} {}", r.title, r.kind.as_str()), |r| r.created_at.to_rfc3339());
    Ok(Json(query.render_page(&page)?))
}

/// 报表详情（`GET /api/v1/reports/{id}`）。
///
/// # Errors
/// 报表不存在。
pub async fn get_report(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "reports", "read")?;
    let report_id = parse_id(&id, "report")?;
    let Some(report) = crate::report_service::get(&state, principal.tenant, report_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "report", id }));
    };
    Ok(Json(serde_json::json!({
        "report": report,
        "filename": report.suggested_filename(),
        "downloadable": report.is_downloadable(),
    })))
}

/// 报表下载（`GET /api/v1/reports/{id}/download`，Markdown 文本）。
///
/// # Errors
/// 报表不存在或未生成完成。
pub async fn download_report(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<axum::response::Response> {
    use axum::response::IntoResponse;
    principal.require(&state, "reports", "read")?;
    let report_id = parse_id(&id, "report")?;
    let Some(report) = crate::report_service::get(&state, principal.tenant, report_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "report", id }));
    };
    if !report.is_downloadable() {
        return Err(ApiError::new(DomainError::PreconditionFailed("报表尚未生成完成".to_string())));
    }
    let filename = report.suggested_filename();
    // 文件名可能含中文（报表标题）：HTTP 头必须是 ASCII，这里退化为 ASCII 安全名，
    // 避免 `HeaderValue::from_str` 失败导致头被静默丢弃。
    let ascii_name: String = filename
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    let (body, content_type) = crate::report_service::artifact(&state, &report).await?;
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, content_type.to_string()),
            (axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{ascii_name}\"")),
        ],
        body,
    )
        .into_response())
}
