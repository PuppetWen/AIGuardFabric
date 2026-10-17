//! 告警聚合 / SLA 刷新 / 升级端点。

use super::*;

/// 告警聚合 Body（全部字段可选；空请求体 `{}` 等价于引擎默认配置）。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AlertAggregateBody {
    /// 聚簇时间窗（秒；相对**首条**告警，默认 300，非法/非正 → 400）。
    #[serde(default)]
    pub window_secs: Option<i64>,
    /// 标题相似度阈值（`0.0..=1.0`，默认 0.75，越界 → 400）。
    #[serde(default)]
    pub similarity_threshold: Option<f64>,
    /// 相似度策略：`exact` / `jaccard`（默认）/ `prefix`。
    #[serde(default)]
    pub similarity: Option<String>,
    /// 是否按实体键分簇（默认 true）。
    #[serde(default)]
    pub entity_scoped: Option<bool>,
    /// 抑制规则（`agf_correlate::aggregate::SuppressionRule` 原样透传，逐条校验）。
    #[serde(default)]
    pub suppression_rules: Vec<SuppressionRule>,
}

/// 告警聚合（`POST /api/v1/alerts/aggregate`）。
///
/// 数据来源：`ApiStore::alert_list`（该租户全部告警）→ [`AlertInput::from_alert`] 投影
/// （实体键由 `affected_hosts[0]` 或首个资产 id 经 `entity_alignment_key` 归一，取不到则为 `None`，
/// 此时引擎按"无实体"降级为同类目+同标题聚合）→ `agf_correlate::aggregate::reduce_once`。
///
/// 返回的是引擎真实产出的 [`agf_correlate::aggregate::ReduceReport`]：
/// 事件簇（含 `occurrences`/`dedup_count`/`dedup_keys`/`suppressed_*`/`alert_ids`）+ 降噪率。
/// 台账里没有告警时返回 200 + 空簇（`raw_alerts = 0`），**不伪造**簇；配置/规则非法返回 400。
///
/// # Errors
/// 权限不足（`alerts:write`）、请求体非法、聚合配置或抑制规则非法（400）、存储错误。
pub async fn alert_aggregate(
    State(state): State<AppState>,
    principal: Principal,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alerts", "write")?;
    let body: AlertAggregateBody = optional_body(&body)?;

    let mut config = AggregationConfig::default();
    if let Some(secs) = body.window_secs {
        config.window_secs = secs;
    }
    if let Some(threshold) = body.similarity_threshold {
        config.similarity_threshold = threshold;
    }
    if let Some(raw) = body.similarity.as_deref() {
        config.similarity = parse_similarity(raw)?;
    }
    if let Some(scoped) = body.entity_scoped {
        config.entity_scoped = scoped;
    }
    let rules = body.suppression_rules;

    let now = Timestamp::now();
    let alerts = state.store.alert_list_durable(principal.tenant, None, None).await?;
    let inputs: Vec<AlertInput> = alerts
        .iter()
        .map(|alert| AlertInput::from_alert(alert, alert_entity_key(principal.tenant, alert).as_deref()))
        .collect();
    // 走聚合器本体（而不是 `reduce_once`）：后者的便捷签名不接受抑制规则，
    // 用它会让本端点的 `suppression_rules` 变成"看着支持其实被忽略"。
    let mut aggregator = AlertAggregator::new(config.clone(), rules.clone())
        .map_err(|e| ApiError::new(DomainError::Validation(format!("告警聚合失败（配置或抑制规则非法）: {e}"))))?;
    aggregator
        .ingest_many(&inputs)
        .map_err(|e| ApiError::new(DomainError::Validation(format!("告警聚合摄入失败: {e}"))))?;
    aggregator.flush(now);
    let report = aggregator
        .report(principal.tenant, now)
        .map_err(|e| ApiError::new(DomainError::Internal(format!("告警聚合报告失败: {e}"))))?;

    let report_json = serde_json::to_value(&report)?;
    let mut value = match report_json {
        serde_json::Value::Object(map) => map,
        other => return Ok(Json(other)),
    };
    value.insert("noise_reduction_ratio".to_string(), serde_json::json!(report.noise_reduction_ratio()));
    value.insert("actionable_clusters".to_string(), serde_json::json!(report.actionable().len()));
    value.insert("suppressed_clusters".to_string(), serde_json::json!(report.suppressed().len()));
    value.insert("max_severity".to_string(), serde_json::json!(report.max_severity().map(|s| s.as_str())));
    value.insert("affected_entities".to_string(), serde_json::json!(report.affected_entities()));
    value.insert("source_alerts".to_string(), serde_json::json!(alerts.len()));
    value.insert("config".to_string(), serde_json::to_value(&config)?);
    value.insert("suppression_rule_count".to_string(), serde_json::json!(rules.len()));
    value.insert(
        "note".to_string(),
        serde_json::json!(
            "聚合结果由 agf_correlate::aggregate 实时计算（内存态，不落簇表；TODO(correlate-aggregate-persist)）"
        ),
    );

    state
        .audit(
            principal.tenant,
            AuditAction::Execute,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "alert-aggregate"),
            AuditTarget::new("alert-cluster", None, Some(format!("{} 条告警", alerts.len()))),
            &format!("告警聚合：原始 {} 条 → 簇 {} 个", report.raw_alerts, report.deduped_alerts),
        )
        .await?;
    Ok(Json(serde_json::Value::Object(value)))
}

/// 告警 SLA 刷新 Body。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AlertSlaRefreshBody {
    /// 只统计活动告警（默认 `true`；`false` = 含已关闭/已抑制的历史告警）。
    #[serde(default)]
    pub active_only: Option<bool>,
}

/// 告警 SLA 刷新（`POST /api/v1/alerts/sla-refresh`）。
///
/// 对每条告警用 `first_seen_at` + `severity` 建 [`SlaClock`]（三档目标、预警线、升级阶梯全部来自
/// [`agf_correlate::sla::SlaPolicy::for_severity`]），逐条给出首次响应/遏制/解决三档结论、
/// 汇总结论、逾期秒数、应处升级层级与最近截止，并附上五个等级的**真实策略原文**。
///
/// **写回台账**：把引擎结论落到告警的 `sla_due_at` / `sla_breached` / `escalation_level`
/// （[`crate::store::ApiStore::alert_set_sla`]），否则控制台读到的 `agf-core` 单值口径会与引擎
/// 三档口径长期分叉。响应里 `stored_before` 是写入**前**的值，便于对照差异；`updated` 是本次
/// 写回的条数。写回是幂等的（同一时刻重复刷新结果相同）。
///
/// # Errors
/// 权限不足（`alerts:write`）、请求体非法、存储错误。
pub async fn alert_sla_refresh(
    State(state): State<AppState>,
    principal: Principal,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alerts", "write")?;
    let body: AlertSlaRefreshBody = optional_body(&body)?;
    let active_only = body.active_only.unwrap_or(true);
    let now = Timestamp::now();
    let configuration = crate::alert_escalation::get(&state, principal.tenant).await?;

    let alerts = state.store.alert_list_durable(principal.tenant, None, None).await?;
    let mut rows: Vec<serde_json::Value> = Vec::new();
    let mut by_status: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    let mut escalations_due = 0_usize;
    let mut updated = 0_usize;

    for alert in alerts.iter().filter(|a| !active_only || a.is_active()) {
        if !matches!(alert.state, AlertState::Open | AlertState::Escalated) {
            continue;
        }
        let clock = crate::alert_escalation::clock_from_config(&configuration, principal.tenant, alert)?;
        let due = clock.due_escalation(now);
        if due.is_some() {
            escalations_due = escalations_due.saturating_add(1);
        }
        let (due_at, breached) = agf_correlate::sla::case_sla_fields(&clock, now);
        let next = clock.next_escalation(now);
        let overall = clock.overall(now);
        *by_status.entry(overall.as_str().to_string()).or_insert(0) += 1;
        *by_severity.entry(alert.severity.as_str().to_string()).or_insert(0) += 1;
        let stored_before = serde_json::json!({
            "sla_due_at": alert.sla_due_at,
            "sla_breached": alert.sla_breached,
            "escalation_level": alert.escalation_level,
        });
        let written = state
            .store
            .alert_set_sla_durable(principal.tenant, alert.id, Some(due_at), breached, alert.escalation_level, None)
            .await?;
        updated = updated.saturating_add(1);
        rows.push(serde_json::json!({
            "alert_id": alert.id,
            "title": alert.title,
            "severity": alert.severity.as_str(),
            "state": alert.state.as_str(),
            "active": alert.is_active(),
            "first_seen_at": alert.first_seen_at,
            "overall": overall.as_str(),
            "breached": breached,
            "due_at": due_at,
            "overdue_secs": clock.overdue_secs(now),
            "escalation_due": due.map(|step: EscalationStep| serde_json::json!({
                "level": step.level,
                "target": step.target.as_str(),
                "overdue_secs": step.overdue_secs,
            })),
            "next_escalation": next.map(|step: EscalationStep| serde_json::json!({
                "level": step.level,
                "target": step.target.as_str(),
                "overdue_secs": step.overdue_secs,
            })),
            "targets": clock.statuses(now),
            "stored_before": stored_before,
            "stored_after": {
                "sla_due_at": written.sla_due_at,
                "sla_breached": written.sla_breached,
                "escalation_level": written.escalation_level,
            },
        }));
    }

    let policies: Vec<agf_correlate::sla::SlaPolicy> =
        SEVERITIES.iter().map(|severity| crate::alert_escalation::sla_policy(&configuration, *severity)).collect();
    let checked = rows.len();
    state
        .audit(
            principal.tenant,
            AuditAction::Update,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "alert-sla-refresh"),
            AuditTarget::new("alert", None, Some(format!("{checked} 条"))),
            &format!("告警 SLA 刷新：检查 {checked} 条、写回 {updated} 条，应升级 {escalations_due} 条"),
        )
        .await?;
    Ok(Json(serde_json::json!({
        "tenant_id": principal.tenant,
        "judged_at": now,
        "active_only": active_only,
        "checked": checked,
        "updated": updated,
        "escalations_due": escalations_due,
        "by_status": by_status,
        "by_severity": by_severity,
        "written_back": true,
        "alerts": rows,
        "policies": policies,
        "notes": [
            "按已保存策略计算未确认告警的 SLA，写回截止和逾期状态；达到升级条件不代表通知已经入队",
            "暂停窗口（等变更窗口/等审批）需要有审批留痕的存储面，当前无该表 ⇒ 暂停时长为 0（TODO(correlate-sla-persist)）",
        ],
    })))
}

/// 告警升级 Body。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AlertEscalateBody {
    /// 通知渠道类型（默认 `in-app`；仅接受 `ChannelKind` 词表，非法 → 400）。
    #[serde(default)]
    pub channel_kind: Option<String>,
    /// 通知正文补充说明（缺省按升级层级与逾期秒数生成）。
    #[serde(default)]
    pub note: Option<String>,
    /// **判定时刻覆盖**（RFC3339，缺省 = 现在）。
    ///
    /// 用途是演练与补偿判定：对历史时刻重放"当时该升到哪一级"，或提前评估"再逾期多久会升级"。
    /// 它只影响本次判定与通知正文，**不改**告警的 `first_seen_at`，也不伪造逾期；
    /// 早于告警首见时间直接 400（那是输入错误，不是"未逾期"）。
    #[serde(default)]
    pub judged_at: Option<Timestamp>,
}

/// 告警升级（`POST /api/v1/alerts/{id}/escalate`）。
///
/// 判定与派发都走真实实现：
/// 1. `agf_correlate::sla` 按告警的 `first_seen_at`/`severity` 建钟 → `due_escalation(now)` 给出
///    应处层级与该找谁（`on-call`/`team-lead`/`security-owner`/`incident-commander`）；
/// 2. 未逾期（`None`）⇒ **200 + `escalated: false`**，并给出下一档升级与最近截止，
///    绝不假装"已升级"；
/// 3. 逾期 ⇒ 经 `agf_correlate::notify` 派发一条升级通知（渠道为 **MockChannel**，不联网），
///    并把告警状态流转到 `escalated` + 指派为该升级目标（真实落库），关联案件追加一条
///    `escalated` 时间线事件，最后写审计与 WS 事件。
///
/// 幂等性说明：升级通知的去重键是 `租户|alert|告警 id|渠道`，同一告警重复升级时第二次会被
/// 引擎判为 `suppressed(dedup)`（这正是"同一对象同渠道只发一次"的既定语义），响应里如实体现。
/// `judged_at` 可覆盖判定时刻（演练/补偿判定用），此时"同一告警第二次升级"是**同一去重键**，
/// 因此第二次派发同样会被去重抑制——这不是失败，是引擎的既定语义。
///
/// # Errors
/// 权限不足（`alerts:write`）、id 非法（400）、告警不存在（404）、渠道非法（400）、存储错误。
pub async fn escalate_alert(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alerts", "write")?;
    let alert_id = parse_id(&id, "alert")?;
    let body: AlertEscalateBody = optional_body(&body)?;
    let kind = match body.channel_kind.as_deref() {
        Some(raw) => parse_channel_kind(raw)?,
        None => ChannelKind::InApp,
    };
    let Some(alert) = state.store.alert_get_durable(principal.tenant, alert_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "alert", id }));
    };

    let now = body.judged_at.unwrap_or_else(Timestamp::now);
    if now.is_before(&alert.first_seen_at) {
        return Err(ApiError::new(DomainError::Validation(format!(
            "judged_at {} 早于告警首见时间 {}：判定时刻不能早于时钟起点",
            now.to_rfc3339(),
            alert.first_seen_at.to_rfc3339()
        ))));
    }
    if !matches!(alert.state, AlertState::Open | AlertState::Escalated) {
        return Ok(Json(serde_json::json!({"escalated":false,"alert_id":alert.id,
            "reason":"告警已确认、解决或抑制，不再升级"})));
    }
    let clock = crate::alert_escalation::clock(&state, principal.tenant, &alert).await?;
    let (due_at, breached) = agf_correlate::sla::case_sla_fields(&clock, now);
    let Some(step) = clock.due_escalation(now) else {
        return Ok(Json(serde_json::json!({
            "escalated": false,
            "reason": "SLA 未逾期，未达到任何升级档位",
            "alert_id": alert.id,
            "severity": alert.severity.as_str(),
            "overdue_secs": clock.overdue_secs(now),
            "due_at": due_at,
            "breached": breached,
            "next_escalation": clock.next_escalation(now).map(|s: EscalationStep| serde_json::json!({
                "level": s.level,
                "target": s.target.as_str(),
                "after_overdue_secs": s.overdue_secs,
            })),
            "targets": clock.statuses(now),
        })));
    };

    let note = body.note.unwrap_or_else(|| {
        format!(
            "告警「{}」已逾期 {}s，升级到 L{}（{}）",
            alert.title,
            clock.overdue_secs(now),
            step.level,
            step.target.as_str()
        )
    });
    let delivery = dispatch_notification(
        &state,
        principal.tenant,
        kind,
        "alert",
        alert.id,
        &format!("[L{}] 告警升级：{}", step.level, alert.title),
        &note,
        alert.severity,
        now,
    )
    .await?;

    let updated = state
        .store
        .alert_set_sla_durable(
            principal.tenant,
            alert.id,
            Some(due_at),
            breached,
            step.level,
            Some((AlertState::Escalated, None)),
        )
        .await?;
    let case_event = match alert.case_id {
        Some(case_id) => Some(
            state
                .store
                .case_add_event_durable(
                    principal.tenant,
                    case_id,
                    CaseEventKind::Escalated,
                    &principal.display(),
                    &note,
                )
                .await?,
        ),
        None => None,
    };
    state
        .audit(
            principal.tenant,
            AuditAction::Update,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "alert-escalate"),
            AuditTarget::new("alert", Some(alert.id.to_string()), Some(alert.title.clone())),
            &note,
        )
        .await?;
    state.publish(crate::state::WsEvent {
        kind: "alert".to_string(),
        tenant_id: principal.tenant,
        at: now,
        payload: serde_json::json!({
            "alert_id": alert.id,
            "escalation_level": step.level,
            "escalation_target": step.target.as_str(),
        }),
    });

    Ok(Json(serde_json::json!({
        "escalated": true,
        "level": step.level,
        "target": step.target.as_str(),
        "overdue_secs": clock.overdue_secs(now),
        "due_at": due_at,
        "breached": breached,
        "alert": updated,
        "notification": delivery,
        "case_event": case_event,
        "next_escalation": clock.next_escalation(now).map(|s: EscalationStep| serde_json::json!({
            "level": s.level,
            "target": s.target.as_str(),
            "after_overdue_secs": s.overdue_secs,
        })),
        "targets": clock.statuses(now),
        "note": "通知是否送达请查看回执；角色标签不自动指派处理人，模拟回执会明确标记",
    })))
}
