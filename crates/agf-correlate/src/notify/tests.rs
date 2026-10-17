//! 由 `notify.rs` 拆分：`EPOCH`/`at` 等 18 项（纯搬移，逻辑不变）。
use super::*;

pub(crate) const EPOCH: &str = "2026-03-02T10:00:00Z";

pub(crate) fn at(offset: i64) -> Timestamp {
    Timestamp::parse_rfc3339(EPOCH).map_or_else(|_| Timestamp::now(), |t| t.offset_secs(offset))
}

pub(crate) fn channel_config(id: Id, kind: ChannelKind, tenant: TenantId) -> ChannelConfig {
    ChannelConfig {
        id,
        tenant_id: tenant,
        name: format!("channel-{}", kind.as_str()),
        kind,
        enabled: true,
        secret_ref: None,
        targets: vec!["soc@corp.example".to_string()],
        min_severity: None,
        headers: BTreeMap::new(),
        template: None,
        silence_secs: 300,
        max_retries: 3,
        last_sent_at: None,
        last_error: None,
        created_at: at(0),
    }
}

pub(crate) fn message_for(tenant: TenantId, channel: &ChannelConfig, subject: Id) -> OutboundMessage {
    OutboundMessage {
        tenant_id: tenant,
        channel_id: channel.id,
        kind: channel.kind,
        subject_kind: "case".to_string(),
        subject_id: subject,
        dedup_key: dedup_key(tenant, "case", subject, channel.id),
        title: "案件超 SLA".to_string(),
        body: "请立即处理".to_string(),
        severity: Severity::High,
        targets: channel.targets.clone(),
        at: at(0),
        extra: BTreeMap::new(),
    }
}

#[tokio::test]
pub(crate) async fn mock_channel_records_deliveries() {
    let t = TenantId::default_tenant();
    let id = Id::new();
    let mock = Arc::new(MockChannel::new(id, ChannelKind::DingTalk, t));
    let config = channel_config(id, ChannelKind::DingTalk, t);
    let mut dispatcher = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    dispatcher.register(mock.clone(), config.clone()).expect("注册应成功");
    let message = message_for(t, &config, Id::new());
    let delivery = dispatcher.dispatch(&message).await.expect("派发应成功");
    assert_eq!(delivery.outcome, DeliveryOutcome::Delivered);
    assert_eq!(delivery.attempts, 1);
    assert!(delivery.receipt.as_deref().is_some_and(|r| r.contains("mock-1")));
    assert_eq!(mock.attempts(), 1);
    assert_eq!(mock.sent().len(), 1);
    assert!(mock.sent()[0].summary().contains("案件超 SLA"));
    assert!(is_delivered(&delivery));
}

#[tokio::test]
pub(crate) async fn same_subject_and_channel_is_deduplicated() {
    let t = TenantId::default_tenant();
    let id = Id::new();
    let mock = Arc::new(MockChannel::new(id, ChannelKind::Feishu, t));
    let config = channel_config(id, ChannelKind::Feishu, t);
    let mut dispatcher = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    dispatcher.register(mock.clone(), config.clone()).expect("注册应成功");
    let subject = Id::new();
    let first = dispatcher.dispatch(&message_for(t, &config, subject)).await.expect("派发应成功");
    let second = dispatcher.dispatch(&message_for(t, &config, subject)).await.expect("派发应成功");
    assert_eq!(first.outcome, DeliveryOutcome::Delivered);
    assert_eq!(second.outcome, DeliveryOutcome::Suppressed);
    assert_eq!(second.suppressed_by, Some(SuppressCause::Dedup));
    assert_eq!(mock.attempts(), 1, "重复派发不得再次触达渠道");
    assert_eq!(dispatcher.delivered_keys(), 1);
    // 换个关联对象 → 允许再发
    let other = dispatcher.dispatch(&message_for(t, &config, Id::new())).await.expect("派发应成功");
    assert_eq!(other.outcome, DeliveryOutcome::Delivered);
}

#[tokio::test]
pub(crate) async fn maintenance_window_suppresses_silently() {
    let t = TenantId::default_tenant();
    let id = Id::new();
    let mock = Arc::new(MockChannel::new(id, ChannelKind::Email, t));
    let config = channel_config(id, ChannelKind::Email, t);
    let mut dispatcher = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    dispatcher.register(mock.clone(), config.clone()).expect("注册应成功");
    dispatcher.add_maintenance_window(MaintenanceWindow {
        reason: "变更窗口".to_string(),
        from: at(-600),
        to: at(600),
        asset_ids: Vec::new(),
    });
    let delivery = dispatcher.dispatch(&message_for(t, &config, Id::new())).await.expect("派发应成功");
    assert_eq!(delivery.outcome, DeliveryOutcome::Suppressed);
    assert_eq!(delivery.suppressed_by, Some(SuppressCause::Maintenance));
    assert_eq!(mock.attempts(), 0, "维护窗口内不得触达渠道");
    let audit = dispatcher.audit_owned();
    assert_eq!(audit.len(), 1);
    assert!(!audit[0].is_real_attempt());
    assert!(audit[0].summary().contains("maintenance"));
}

#[tokio::test]
pub(crate) async fn rate_limit_caps_then_suppresses_without_consuming() {
    let t = TenantId::default_tenant();
    let id = Id::new();
    let mock = Arc::new(MockChannel::new(id, ChannelKind::Webhook, t));
    let config = channel_config(id, ChannelKind::Webhook, t);
    let mut dispatcher = NotificationDispatcher::new(DispatchConfig { rate_limit_max: 2, ..DispatchConfig::default() })
        .expect("配置合法");
    dispatcher.register(mock.clone(), config.clone()).expect("注册应成功");
    for _ in 0..2 {
        let delivery = dispatcher.dispatch(&message_for(t, &config, Id::new())).await.expect("派发应成功");
        assert_eq!(delivery.outcome, DeliveryOutcome::Delivered);
    }
    let blocked = dispatcher.dispatch(&message_for(t, &config, Id::new())).await.expect("派发应成功");
    assert_eq!(blocked.suppressed_by, Some(SuppressCause::RateLimit));
    assert_eq!(mock.attempts(), 2);
    assert_eq!(dispatcher.rate_used(id, at(0)), 2, "被限流挡下的不应继续占配额");
    // 窗口滑过 → 恢复
    let later = {
        let mut m = message_for(t, &config, Id::new());
        m.at = at(120);
        m
    };
    let recovered = dispatcher.dispatch(&later).await.expect("派发应成功");
    assert_eq!(recovered.outcome, DeliveryOutcome::Delivered);
}

#[tokio::test]
pub(crate) async fn retry_with_exponential_backoff_then_success() {
    let t = TenantId::default_tenant();
    let id = Id::new();
    let mock = Arc::new(MockChannel::new(id, ChannelKind::PagerDuty, t).failing_times(2));
    let config = channel_config(id, ChannelKind::PagerDuty, t);
    let mut dispatcher = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    dispatcher.register(mock.clone(), config.clone()).expect("注册应成功");
    let delivery = dispatcher.dispatch(&message_for(t, &config, Id::new())).await.expect("派发应成功");
    assert_eq!(delivery.outcome, DeliveryOutcome::Delivered, "第 3 次应成功: {delivery:?}");
    assert_eq!(delivery.attempts, 3);
    assert_eq!(mock.attempts(), 3);
    let audit = dispatcher.audit_owned();
    // 两次失败各自留一条带退避的审计 + 最终成功一条
    let failed: Vec<&DeliveryAttempt> = audit.iter().filter(|a| a.outcome == DeliveryOutcome::Failed).collect();
    assert_eq!(failed.len(), 2);
    assert_eq!(failed[0].backoff_ms, Some(500));
    assert_eq!(failed[1].backoff_ms, Some(1_000));
    assert!(audit.last().is_some_and(|a| a.outcome == DeliveryOutcome::Delivered));
}

#[tokio::test]
pub(crate) async fn retries_exhausted_reports_failure() {
    let t = TenantId::default_tenant();
    let id = Id::new();
    let mock = Arc::new(MockChannel::new(id, ChannelKind::Sms, t).failing_times(99).with_fail_reason("网关超时"));
    let config = channel_config(id, ChannelKind::Sms, t);
    let mut dispatcher = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    dispatcher.register(mock.clone(), config.clone()).expect("注册应成功");
    let delivery = dispatcher.dispatch(&message_for(t, &config, Id::new())).await.expect("派发应成功");
    assert_eq!(delivery.outcome, DeliveryOutcome::Failed);
    assert_eq!(delivery.attempts, 3, "默认最多尝试 3 次");
    assert!(delivery.error.as_deref().is_some_and(|e| e.contains("网关超时")));
    assert_eq!(mock.attempts(), 3);
    assert_eq!(dispatcher.delivered_keys(), 0, "失败不得记为已投递");
}

#[tokio::test]
pub(crate) async fn unroutable_cases_are_audited() {
    let t = TenantId::default_tenant();
    let mut dispatcher = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    // 未注册渠道
    let unregistered = Id::new();
    let config = channel_config(unregistered, ChannelKind::InApp, t);
    let delivery = dispatcher.dispatch(&message_for(t, &config, Id::new())).await.expect("派发应成功");
    assert_eq!(delivery.suppressed_by, Some(SuppressCause::Unroutable));

    // 注册了元数据但没注入实现
    let id2 = Id::new();
    let mut dispatcher2 = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    dispatcher2.channel_meta.insert(id2, channel_config(id2, ChannelKind::Slack, t));
    let delivery2 = dispatcher2
        .dispatch(&message_for(t, &channel_config(id2, ChannelKind::Slack, t), Id::new()))
        .await
        .expect("派发应成功");
    assert_eq!(delivery2.suppressed_by, Some(SuppressCause::Unroutable));

    // 等级不足
    let id3 = Id::new();
    let mock = Arc::new(MockChannel::new(id3, ChannelKind::Email, t));
    let mut config3 = channel_config(id3, ChannelKind::Email, t);
    config3.min_severity = Some(Severity::Critical);
    let mut dispatcher3 = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    dispatcher3.register(mock.clone(), config3.clone()).expect("注册应成功");
    let mut low = message_for(t, &config3, Id::new());
    low.severity = Severity::Low;
    let delivery3 = dispatcher3.dispatch(&low).await.expect("派发应成功");
    assert_eq!(delivery3.suppressed_by, Some(SuppressCause::Unroutable));
    assert_eq!(mock.attempts(), 0);

    // 渠道关闭
    let id4 = Id::new();
    let mock4 = Arc::new(MockChannel::new(id4, ChannelKind::Email, t));
    let mut config4 = channel_config(id4, ChannelKind::Email, t);
    config4.enabled = false;
    let mut dispatcher4 = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    dispatcher4.register(mock4.clone(), config4.clone()).expect("注册应成功");
    let delivery4 = dispatcher4.dispatch(&message_for(t, &config4, Id::new())).await.expect("派发应成功");
    assert_eq!(delivery4.suppressed_by, Some(SuppressCause::Unroutable));
    assert_eq!(SuppressCause::Unroutable.as_str(), "unroutable");
}

#[tokio::test]
pub(crate) async fn cross_tenant_dispatch_is_refused() {
    let t1 = TenantId::default_tenant();
    let t2 = TenantId::new();
    let id = Id::new();
    let mock = Arc::new(MockChannel::new(id, ChannelKind::WeCom, t1));
    let config = channel_config(id, ChannelKind::WeCom, t1);
    let mut dispatcher = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    dispatcher.register(mock.clone(), config.clone()).expect("注册应成功");
    let mut foreign = message_for(t1, &config, Id::new());
    foreign.tenant_id = t2;
    let err = dispatcher.dispatch(&foreign).await;
    assert!(matches!(err, Err(NotifyError::TenantViolation { .. })), "跨租户必须报错: {err:?}");
    assert_eq!(mock.attempts(), 0);
}

#[tokio::test]
pub(crate) async fn dispatch_all_covers_each_channel_once() {
    let t = TenantId::default_tenant();
    let mut dispatcher = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    let mut configs = Vec::new();
    let mut mocks = Vec::new();
    for kind in [ChannelKind::DingTalk, ChannelKind::Email, ChannelKind::Sms] {
        let id = Id::new();
        let mock = Arc::new(MockChannel::new(id, kind, t));
        let config = channel_config(id, kind, t);
        dispatcher.register(mock.clone(), config.clone()).expect("注册应成功");
        configs.push(config);
        mocks.push(mock);
    }
    let subject = Id::new();
    let result = dispatcher
        .dispatch_all(t, &configs, "case", subject, "案件升级", "请处理", Severity::Critical, at(0))
        .await
        .expect("派发应成功");
    assert_eq!(result.deliveries.len(), 3);
    assert!(result.any_delivered());
    assert_eq!(result.delivered_count(), 3);
    assert!(!result.is_fully_suppressed());
    assert_eq!(result.dedup_key, dedup_key(t, "case", subject, configs[0].id));
    for mock in &mocks {
        assert_eq!(mock.sent().len(), 1);
    }
    assert!(result.delivery(configs[1].id).is_some());
    assert!(result.delivery(Id::new()).is_none());
}

#[tokio::test]
pub(crate) async fn dry_run_never_touches_the_channel() {
    let t = TenantId::default_tenant();
    let id = Id::new();
    let mock = Arc::new(MockChannel::new(id, ChannelKind::Slack, t));
    let config = channel_config(id, ChannelKind::Slack, t);
    let mut dispatcher =
        NotificationDispatcher::new(DispatchConfig { dry_run: true, ..DispatchConfig::default() }).expect("配置合法");
    dispatcher.register(mock.clone(), config.clone()).expect("注册应成功");
    let delivery = dispatcher.dispatch(&message_for(t, &config, Id::new())).await.expect("派发应成功");
    assert_eq!(delivery.outcome, DeliveryOutcome::Delivered);
    assert!(delivery.receipt.as_deref().is_some_and(|r| r.contains("dry-run")));
    assert_eq!(mock.attempts(), 0, "空转模式不得真正调用渠道");
}

#[tokio::test]
pub(crate) async fn template_rendering_and_record_mapping() {
    let t = TenantId::default_tenant();
    let id = Id::new();
    let mock = Arc::new(MockChannel::new(id, ChannelKind::Email, t));
    let mut config = channel_config(id, ChannelKind::Email, t);
    config.template = Some("【{{severity}}】{{title}} @ {{at}}".to_string());
    let mut dispatcher = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    dispatcher.register(mock.clone(), config.clone()).expect("注册应成功");
    let message =
        dispatcher.build_message(t, &config, "alert", Id::new(), "外传告警", "详情", Severity::Critical, at(0));
    assert!(message.body.contains("【critical】外传告警"), "body={}", message.body);
    assert!(message.body.contains(EPOCH));
    let delivery = dispatcher.dispatch(&message).await.expect("派发应成功");
    let record =
        dispatcher.to_record(t, &delivery, "alert", message.subject_id, &message.dedup_key, "外传告警", &message.body);
    assert_eq!(record.state, DeliveryState::Delivered);
    assert!(record.delivered_at.is_some());
    assert_eq!(record.attempts, 1);
    assert_eq!(record.channel_id, id);
    assert!(record.delivered_at.is_some_and(|d| d.unix_secs() > 0));
}

#[test]
pub(crate) fn config_validation_and_backoff_curve() {
    let bad = DispatchConfig { rate_limit_window_secs: 0, ..DispatchConfig::default() };
    assert!(matches!(bad.validate(), Err(NotifyError::InvalidConfig(_))));
    let bad2 = DispatchConfig { max_attempts: 0, ..DispatchConfig::default() };
    assert!(matches!(bad2.validate(), Err(NotifyError::InvalidConfig(_))));
    let bad3 = DispatchConfig { backoff_base_ms: 0, ..DispatchConfig::default() };
    assert!(matches!(bad3.validate(), Err(NotifyError::InvalidConfig(_))));
    let bad4 = DispatchConfig { backoff_base_ms: 1_000, backoff_max_ms: 500, ..DispatchConfig::default() };
    assert!(matches!(bad4.validate(), Err(NotifyError::InvalidConfig(_))));
    assert!(NotificationDispatcher::new(bad).is_err());

    let config = DispatchConfig::default();
    assert_eq!(config.backoff_ms(1), 500);
    assert_eq!(config.backoff_ms(2), 1_000);
    assert_eq!(config.backoff_ms(3), 2_000);
    assert_eq!(config.backoff_ms(99), 30_000, "退避必须封顶");
}

#[test]
pub(crate) fn rate_limiter_is_per_channel() {
    let config = DispatchConfig { rate_limit_max: 1, rate_limit_window_secs: 60, ..DispatchConfig::default() };
    let mut limiter = RateLimiter::new(config);
    let a = Id::new();
    let b = Id::new();
    assert!(limiter.try_acquire(a, at(0)));
    assert!(!limiter.try_acquire(a, at(1)));
    assert!(limiter.try_acquire(b, at(1)), "限流必须按渠道独立");
    assert_eq!(limiter.used(a, at(1)), 1);
    assert_eq!(limiter.used(b, at(1)), 1);
    assert!(limiter.try_acquire(a, at(120)), "窗口滑过后恢复");
    limiter.reset();
    assert_eq!(limiter.used(a, at(120)), 0);
}

#[test]
pub(crate) fn seeds_and_audit_accessors_work() {
    let t = TenantId::default_tenant();
    let id = Id::new();
    let key = dedup_key(t, "case", Id::new(), id);
    let mut dispatcher = NotificationDispatcher::with_defaults().expect("默认配置应合法");
    assert!(!dispatcher.already_delivered(id, &key));
    dispatcher.seed_delivered(id, key.clone());
    assert!(dispatcher.already_delivered(id, &key));
    assert_eq!(dispatcher.delivered_keys(), 1);
    assert!(dispatcher.audit().is_empty());
    assert!(dispatcher.config().max_attempts >= 1);
    dispatcher.reset_rate_limit();
    assert_eq!(dispatcher.rate_used(id, at(0)), 0);
    let windows = vec![MaintenanceWindow { reason: "r".into(), from: at(0), to: at(1), asset_ids: Vec::new() }];
    dispatcher.set_maintenance_windows(windows);
    assert_eq!(DeliveryState::Suppressed.as_str(), "suppressed");
    assert_eq!(DeliveryOutcome::Failed.to_core_state(), DeliveryState::Failed);
    assert_eq!(SuppressCause::Dedup.as_str(), "dedup");
    assert_eq!(SuppressCause::RateLimit.as_str(), "rate-limit");
}
