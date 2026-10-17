//! 通知派发端点：请求体与渠道规格。

use super::*;

/// 通知派发 Body。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NotifySendBody {
    /// 关联对象类型：`case` / `alert` / `custom`（默认 `case`）。
    #[serde(default)]
    pub subject_kind: Option<String>,
    /// 关联对象 id（`case`/`alert` 必填；`custom` 时忽略）。
    #[serde(default)]
    pub subject_id: Option<String>,
    /// 标题（`custom` 时必填；`case`/`alert` 时缺省取台账标题）。
    #[serde(default)]
    pub title: Option<String>,
    /// 正文（缺省按对象与等级生成）。
    #[serde(default)]
    pub body: Option<String>,
    /// 覆盖严重等级（缺省取台账值；`custom` 时必填）。
    #[serde(default)]
    pub severity: Option<String>,
    /// 目标渠道（缺省 = `ChannelKind` 全量 9 个；逐条独立判定）。
    #[serde(default)]
    pub channels: Vec<NotifyChannelSpec>,
}

/// 单个目标渠道（Mock 实现 + 渠道配置）。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NotifyChannelSpec {
    /// 渠道类型（`dingtalk`/`feishu`/`wecom`/`email`/`sms`/`webhook`/`pagerduty`/`slack`/`in-app`）。
    pub kind: String,
    /// 收件目标（邮箱/频道名等；仅作展示，Mock 渠道不投递）。
    #[serde(default)]
    pub targets: Vec<String>,
    /// 该渠道适用的最低等级（低于此等级判 `unroutable`）。
    #[serde(default)]
    pub min_severity: Option<String>,
    /// 消息模板（支持 `{{title}}`/`{{severity}}`/`{{at}}` 等占位符）。
    #[serde(default)]
    pub template: Option<String>,
    /// 渠道显示名（缺省 `mock-<kind>`）。
    #[serde(default)]
    pub name: Option<String>,
}

/// 通知派发（`POST /api/v1/notifications/send`）。
///
/// 已配置渠道先加密入持久队列，再投递；去重包含租户、对象、渠道和严重等级。
/// 租户内事务控制领取与限流，失败由后台退避重试，网络调用不持有全局派发锁。
/// 未配置渠道的离线演示保留内存 Mock 决策链，响应明确标记模拟。
///
/// # Errors
/// 权限不足（`alerts:write`）、`subject_id` 缺失/非法（400）、对象不存在（404）、
/// 渠道类型非法或等级非法（400）。
pub async fn notify_send(
    State(state): State<AppState>,
    principal: Principal,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alerts", "write")?;
    let body: NotifySendBody = optional_body(&body)?;

    let subject_kind = body.subject_kind.as_deref().unwrap_or("case").trim().to_ascii_lowercase();
    let severity_override = match body.severity.as_deref() {
        Some(raw) => Some(Severity::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?),
        None => None,
    };

    // 对象与标题/等级的来源：case/alert 读台账（不存在即 404），custom 用请求体。
    let (subject_id, title, severity) = match subject_kind.as_str() {
        "case" | "alert" => {
            let raw = body.subject_id.as_deref().map(str::trim).filter(|v| !v.is_empty()).ok_or_else(|| {
                ApiError::new(DomainError::Validation(format!("{subject_kind} 通知必须提供 subject_id")))
            })?;
            let id = parse_id(raw, if subject_kind == "case" { "case" } else { "alert" })?;
            if subject_kind == "case" {
                let Some(case) = state.store.case_get_durable(principal.tenant, id).await? else {
                    return Err(ApiError::new(DomainError::NotFound { entity: "case", id: raw.to_string() }));
                };
                (
                    id,
                    body.title.clone().unwrap_or_else(|| format!("案件 {}：{}", case.code, case.title)),
                    severity_override.unwrap_or(case.severity),
                )
            } else {
                let Some(alert) = state.store.alert_get_durable(principal.tenant, id).await? else {
                    return Err(ApiError::new(DomainError::NotFound { entity: "alert", id: raw.to_string() }));
                };
                (
                    id,
                    body.title.clone().unwrap_or_else(|| alert.title.clone()),
                    severity_override.unwrap_or(alert.severity),
                )
            }
        }
        "custom" => {
            let title = body
                .title
                .clone()
                .filter(|t| !t.trim().is_empty())
                .ok_or_else(|| ApiError::new(DomainError::Validation("custom 通知必须提供 title".to_string())))?;
            let severity = severity_override
                .ok_or_else(|| ApiError::new(DomainError::Validation("custom 通知必须提供 severity".to_string())))?;
            // `custom` 没有台账对象：给了 subject_id 就必须是合法 UUID（非法即 400），
            // 没给则为本次通知生成一个新 id（仅用于去重键，不代表任何业务对象）。
            let subject = match body.subject_id.as_deref().map(str::trim).filter(|raw| !raw.is_empty()) {
                Some(raw) => parse_id(raw, "notification")?,
                None => Id::new(),
            };
            (subject, title, severity)
        }
        other => {
            return Err(ApiError::new(DomainError::Validation(format!(
                "未知 subject_kind: {other}（可选 case/alert/custom）"
            ))));
        }
    };

    let rows = state
        .configurations
        .list::<crate::notification_config::StoredChannel>(principal.tenant, crate::notification_config::KIND)
        .await?;
    if !rows.is_empty() || !state.config.mock_mode {
        let selected = rows
            .into_iter()
            .filter(|row| {
                row.enabled
                    && (body.channels.is_empty() || body.channels.iter().any(|c| c.kind == row.channel.as_str()))
            })
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Err(DomainError::PreconditionFailed("请先在系统设置中配置并启用通知渠道".into()).into());
        }
        let value = crate::notification_delivery::dispatch(
            &state,
            principal.tenant,
            selected,
            &subject_kind,
            subject_id,
            &title,
            body.body.as_deref().unwrap_or(&title),
            severity,
        )
        .await?;
        return Ok(Json(value));
    }
    let specs = if body.channels.is_empty() {
        ChannelKind::all()
            .into_iter()
            .map(|kind| NotifyChannelSpec { kind: kind.as_str().to_string(), ..NotifyChannelSpec::default() })
            .collect()
    } else {
        body.channels
    };
    let configs = specs.iter().map(|spec| channel_config(&principal.tenant, spec)).collect::<Result<Vec<_>, _>>()?;
    let now = Timestamp::now();
    let body_text = body.body.unwrap_or_else(|| {
        format!("{} 通知：{}（等级 {}，时间 {}）", subject_kind, title, severity.as_str(), now.to_rfc3339())
    });

    let mut dispatcher = state.notifier.lock().await;
    let audit_before = dispatcher.audit().len();
    let mut deliveries: Vec<serde_json::Value> = Vec::with_capacity(configs.len());
    for config in &configs {
        let mock = std::sync::Arc::new(MockChannel::new(config.id, config.kind, principal.tenant));
        dispatcher.register(mock, config.clone()).map_err(notify_error)?;
        let message = dispatcher.build_message(
            principal.tenant,
            config,
            &subject_kind,
            subject_id,
            &title,
            &body_text,
            severity,
            now,
        );
        let delivery = dispatcher.dispatch(&message).await.map_err(notify_error)?;
        deliveries.push(serde_json::json!({
            "channel_id": config.id,
            "kind": config.kind.as_str(),
            "name": config.name,
            "outcome": delivery.outcome.as_str(),
            "attempts": delivery.attempts,
            "suppressed_by": delivery.suppressed_by.map(|cause| cause.as_str()),
            "receipt": delivery.receipt,
            "error": delivery.error,
            "dedup_key": message.dedup_key,
        }));
    }
    let audit: Vec<serde_json::Value> = dispatcher
        .audit()
        .iter()
        .skip(audit_before)
        .map(|attempt| {
            serde_json::json!({
                "channel_id": attempt.channel_id,
                "kind": attempt.kind.as_str(),
                "outcome": attempt.outcome.as_str(),
                "attempts": attempt.attempts,
                "suppressed_by": attempt.suppressed_by.map(|cause| cause.as_str()),
                "backoff_ms": attempt.backoff_ms,
                "summary": attempt.summary(),
            })
        })
        .collect();
    let delivered = deliveries.iter().filter(|d| d["outcome"] == "delivered").count();
    drop(dispatcher);

    state
        .audit(
            principal.tenant,
            AuditAction::Execute,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "notify-send"),
            AuditTarget::new(&subject_kind, Some(subject_id.to_string()), Some(title.clone())),
            &format!("通知派发：{} 个渠道，成功 {delivered} 个（Mock 渠道，不联网）", deliveries.len()),
        )
        .await?;

    Ok(Json(serde_json::json!({
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "title": title,
        "severity": severity.as_str(),
        "channel_count": deliveries.len(),
        "delivered_count": delivered,
        "any_delivered": delivered > 0,
        "fully_suppressed": delivered == 0,
        "deliveries": deliveries,
        "audit": audit,
        "note": "渠道为 MockChannel（不联网）：receipt 形如 mock-N 仅代表内存投递；真实渠道见 agf-adapters（TODO(correlate-notify-adapters)）",
    })))
}
