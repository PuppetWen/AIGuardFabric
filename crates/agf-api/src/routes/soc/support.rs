//! SOC 闭环接线辅助：引擎入参构造 / 错误映射 / Mock 渠道。

use super::*;

// ===========================================================================
// SOC 闭环接线辅助（引擎入参构造 / 错误映射 / Mock 渠道）
// ===========================================================================

/// 五个严重等级（SLA 策略与升级阶梯按等级各一条）。
pub(super) const SEVERITIES: [Severity; 5] =
    [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];

/// 通知渠道 id 命名空间（确定性 id：同租户同类型渠道跨请求稳定 ⇒ 去重/限流跨请求生效）。
const NS_NOTIFY_CHANNEL: &str = "aiguardfabric.api.notify_channel";

/// 解析可选 JSON 请求体：**空体** → `T::default()`，非法 JSON → 400。
///
/// 为什么不用 `ApiJson<T>`：`Option<ApiJson<T>>` 需要 axum 的 `OptionalFromRequest`，
/// 而这些端点的既定契约是"可以不传体"（`POST /alerts/aggregate` 空体即默认配置），
/// 用 `Bytes` 手工解析能同时覆盖"空体"和"坏体"两种边界，且坏体仍然返回 problem+json。
///
/// # Errors
/// 请求体不是合法 JSON 或字段类型不符。
pub(super) fn optional_body<T: serde::de::DeserializeOwned + Default>(body: &Bytes) -> Result<T, ApiError> {
    if body.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_slice(body.as_ref())
        .map_err(|e| ApiError::new(DomainError::Validation(format!("请求体解析失败: {e}"))))
}

/// 解析相似度策略。
///
/// # Errors
/// 未知策略名。
pub(super) fn parse_similarity(raw: &str) -> Result<SimilarityPolicy, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "exact" => Ok(SimilarityPolicy::Exact),
        "jaccard" => Ok(SimilarityPolicy::Jaccard),
        "prefix" => Ok(SimilarityPolicy::Prefix),
        other => {
            Err(ApiError::new(DomainError::Validation(format!("未知相似度策略: {other}（可选 exact/jaccard/prefix）"))))
        }
    }
}

/// 解析通知渠道类型（大小写不敏感，`_` 视为 `-`）。
///
/// # Errors
/// 未知渠道类型。
pub(super) fn parse_channel_kind(raw: &str) -> Result<ChannelKind, ApiError> {
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    ChannelKind::all().into_iter().find(|kind| kind.as_str() == normalized).ok_or_else(|| {
        ApiError::new(DomainError::Validation(format!(
            "未知通知渠道: {raw}（可选 dingtalk/feishu/wecom/email/sms/webhook/pagerduty/slack/in-app）"
        )))
    })
}

/// 告警 → 实体对齐键。
///
/// 优先用 `affected_hosts[0]`（主机实体），退化用首个关联资产 id（`generic` 类型）；
/// 两者都没有时返回 `None`，引擎按"无实体"处理（宁可少聚合，也不编造实体）。
pub(super) fn alert_entity_key(tenant: TenantId, alert: &agf_core::alert::Alert) -> Option<String> {
    if let Some(host) = alert.affected_hosts.first().map(|h| h.trim()).filter(|h| !h.is_empty()) {
        return Some(entity_alignment_key(tenant, Some(EntityKind::Host), &host.to_ascii_lowercase()));
    }
    alert.asset_ids.first().map(|id| entity_alignment_key(tenant, None, &id.to_string()))
}

/// 按等级建 SLA 时钟（起点 = 对象创建/首见时间）。
///
/// # Errors
/// 默认策略理论恒合法；返回错误说明引擎侧策略非法（不应发生，映射为 500）。
pub(super) fn sla_clock(
    tenant: &TenantId,
    subject: Id,
    started_at: Timestamp,
    severity: Severity,
) -> ApiResult<SlaClock> {
    SlaClock::for_severity(*tenant, subject, started_at, severity)
        .map_err(|e| ApiError::new(DomainError::Internal(format!("SLA 时钟构造失败: {e}"))))
}

/// 首次响应里程碑：最早的**人工**事件（剧本/系统产生的 `automated` 事件不算响应）。
pub(super) fn first_human_touch(events: &[CaseEvent]) -> Option<Timestamp> {
    events
        .iter()
        .filter(|event| !event.automated)
        .filter(|event| {
            matches!(event.kind, CaseEventKind::Assigned | CaseEventKind::StateChanged | CaseEventKind::Comment)
        })
        .map(|event| event.at)
        .min()
}

/// 遏制里程碑：最早的处置类事件。
pub(super) fn first_containment(events: &[CaseEvent]) -> Option<Timestamp> {
    events
        .iter()
        .filter(|event| {
            matches!(
                event.kind,
                CaseEventKind::Containment
                    | CaseEventKind::Isolation
                    | CaseEventKind::CredentialRevoked
                    | CaseEventKind::Blocklisted
            )
        })
        .map(|event| event.at)
        .min()
}

/// 解决里程碑：案件 `closed_at`，否则最早的 `closed` 事件。
pub(super) fn resolution_at(case: &Case, events: &[CaseEvent]) -> Option<Timestamp> {
    case.closed_at
        .or_else(|| events.iter().filter(|event| event.kind == CaseEventKind::Closed).map(|event| event.at).min())
}

/// 案件的第一个关联发现的域（剧本触发条件与 CEL 上下文都用它；没有发现则为 `None`）。
///
/// # Errors
/// 存储错误。
pub(super) async fn first_finding_domain(state: &AppState, tenant: TenantId, case: &Case) -> ApiResult<Option<String>> {
    for finding_id in &case.finding_ids {
        if let Some(finding) = state.store.finding_get_durable(tenant, *finding_id).await? {
            return Ok(Some(finding.domain.as_str().to_string()));
        }
    }
    Ok(None)
}

/// 从请求体选出要执行的剧本（YAML 优先于 JSON）。
///
/// # Errors
/// 两者都没给（400）、YAML/JSON 非法（400）、指定的 `key` 不存在（400）。
pub(super) fn select_playbook(body: &CasePlaybookBody) -> Result<Playbook, ApiError> {
    select_playbook_with_timeout(body, 3600)
}

pub(super) fn select_playbook_with_timeout(body: &CasePlaybookBody, max_secs: i64) -> Result<Playbook, ApiError> {
    let books: Vec<Playbook> = if let Some(yaml) = body.yaml.as_deref().map(str::trim).filter(|y| !y.is_empty()) {
        agf_correlate::playbook::parse_playbooks_yaml(yaml)
            .map_err(|e| ApiError::new(DomainError::Validation(format!("剧本 YAML 非法: {e}"))))?
    } else if let Some(value) = &body.playbook {
        let book: Playbook = serde_json::from_value(value.clone())
            .map_err(|e| ApiError::new(DomainError::Validation(format!("剧本 JSON 非法: {e}"))))?;
        vec![book]
    } else {
        return Err(ApiError::new(DomainError::Validation("缺少剧本定义：请在 yaml 或 playbook 字段提供".to_string())));
    };
    for book in &books {
        PlaybookEngine::new().validate_with_timeout_limit(book, max_secs).map_err(|e| playbook_error(e, &book.key))?;
    }
    match body.key.as_deref().map(str::trim).filter(|key| !key.is_empty()) {
        Some(key) => books
            .into_iter()
            .find(|book| book.key == key)
            .ok_or_else(|| ApiError::new(DomainError::Validation(format!("剧本集里没有 key = {key} 的剧本")))),
        None => {
            books.into_iter().next().ok_or_else(|| ApiError::new(DomainError::Validation("剧本集为空".to_string())))
        }
    }
}

/// 剧本引擎错误 → API 错误：缺注入实现 = 依赖不可用（503），其余（定义/条件非法）= 400。
pub(super) fn playbook_error(error: PlaybookError, key: &str) -> ApiError {
    match error {
        PlaybookError::MissingDependency(detail) => ApiError::new(DomainError::DependencyUnavailable {
            dependency: "agf-correlate::playbook".to_string(),
            cause: format!("剧本 {key}: {detail}"),
        }),
        other => ApiError::new(DomainError::Validation(format!("剧本 {key} 执行失败: {other}"))),
    }
}

/// 通知引擎错误 → API 错误：跨租户 = 403，其余（配置非法）= 400。
pub(super) fn notify_error(error: NotifyError) -> ApiError {
    match error {
        NotifyError::TenantViolation { .. } => ApiError::new(DomainError::Forbidden(error.to_string())),
        other => ApiError::new(DomainError::Validation(format!("通知派发失败: {other}"))),
    }
}

/// 由请求体的渠道声明构造 `agf-core` 渠道配置（Mock 实现随派发时注入）。
///
/// # Errors
/// 渠道类型或最低等级非法。
pub(super) fn channel_config(tenant: &TenantId, spec: &NotifyChannelSpec) -> Result<ChannelConfig, ApiError> {
    let kind = parse_channel_kind(&spec.kind)?;
    let min_severity = match spec.min_severity.as_deref() {
        Some(raw) => Some(Severity::parse(raw).map_err(|e| ApiError::new(DomainError::Validation(e)))?),
        None => None,
    };
    Ok(ChannelConfig {
        id: notification_channel_id(*tenant, kind),
        tenant_id: *tenant,
        name: spec.name.clone().unwrap_or_else(|| format!("mock-{}", kind.as_str())),
        kind,
        enabled: true,
        secret_ref: None,
        targets: spec.targets.clone(),
        min_severity,
        headers: BTreeMap::new(),
        template: spec.template.clone(),
        silence_secs: 300,
        max_retries: 3,
        last_sent_at: None,
        last_error: None,
        created_at: Timestamp::now(),
    })
}

/// 渠道 id（确定性）：`租户 + 渠道类型`。
///
/// 确定性是**去重与限流跨请求生效的前提**：若每次请求随机生成渠道 id，引擎的去重键
/// （`租户|对象|对象 id|渠道 id`）就会变，同一告警会被反复投递。
fn notification_channel_id(tenant: TenantId, kind: ChannelKind) -> Id {
    agf_core::ids::deterministic_id(NS_NOTIFY_CHANNEL, &format!("{tenant}:{}", kind.as_str()))
}

/// 经 `AppState.notifier`（进程单例派发器）向指定渠道投递一条通知，返回派发结果投影。
///
/// # Errors
/// 渠道配置非法、租户不符或锁中毒（`tokio::sync::Mutex` 不会中毒，见引擎侧）。
pub(super) async fn dispatch_notification(
    state: &AppState,
    tenant: TenantId,
    kind: ChannelKind,
    subject_kind: &str,
    subject_id: Id,
    title: &str,
    body: &str,
    severity: Severity,
    at: Timestamp,
) -> ApiResult<serde_json::Value> {
    if let Some(row) = state
        .configurations
        .get::<crate::notification_config::StoredChannel>(
            tenant,
            crate::notification_config::KIND,
            crate::notification_config::id(tenant, kind),
        )
        .await?
    {
        return Ok(crate::notification_delivery::dispatch(
            state,
            tenant,
            vec![row],
            subject_kind,
            subject_id,
            title,
            body,
            severity,
        )
        .await?);
    }
    if !state.config.mock_mode {
        return Err(DomainError::PreconditionFailed(format!("通知渠道 {} 未配置", kind.as_str())).into());
    }
    let spec = NotifyChannelSpec { kind: kind.as_str().to_string(), ..NotifyChannelSpec::default() };
    let config = channel_config(&tenant, &spec)?;
    let mut dispatcher = state.notifier.lock().await;
    let mock = std::sync::Arc::new(MockChannel::new(config.id, config.kind, tenant));
    dispatcher.register(mock, config.clone()).map_err(notify_error)?;
    let message = dispatcher.build_message(tenant, &config, subject_kind, subject_id, title, body, severity, at);
    let delivery = dispatcher.dispatch(&message).await.map_err(notify_error)?;
    Ok(serde_json::json!({
        "channel_id": config.id,
        "kind": config.kind.as_str(),
        "outcome": delivery.outcome.as_str(),
        "attempts": delivery.attempts,
        "suppressed_by": delivery.suppressed_by.map(|cause| cause.as_str()),
        "receipt": delivery.receipt,
        "error": delivery.error,
        "dedup_key": message.dedup_key,
    }))
}
