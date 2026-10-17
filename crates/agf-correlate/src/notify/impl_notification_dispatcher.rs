//! 由 `notify.rs` 拆分：`NotificationDispatcher` 的实现（纯搬移，逻辑不变）。
use super::*;

impl NotificationDispatcher {
    /// 构造（校验配置）。
    ///
    /// # Errors
    /// 配置非法时返回 [`NotifyError::InvalidConfig`]。
    pub fn new(config: DispatchConfig) -> Result<Self, NotifyError> {
        config.validate()?;
        let limiter = RateLimiter::new(config.clone());
        Ok(Self {
            config,
            channels: BTreeMap::new(),
            channel_meta: BTreeMap::new(),
            maintenance: Vec::new(),
            limiter,
            delivered: BTreeMap::new(),
            audit: Vec::new(),
        })
    }

    /// 默认配置。
    ///
    /// # Errors
    /// 默认配置理论恒合法。
    pub fn with_defaults() -> Result<Self, NotifyError> {
        Self::new(DispatchConfig::default())
    }

    /// 注入渠道（需带渠道配置以便做等级/静默判断）。
    ///
    /// # Errors
    /// 渠道配置与入参 id 不一致、名称为空时返回 [`NotifyError::InvalidChannel`]。
    pub fn register(
        &mut self,
        channel: std::sync::Arc<dyn NotificationChannel>,
        config: ChannelConfig,
    ) -> Result<(), NotifyError> {
        if config.name.trim().is_empty() {
            return Err(NotifyError::InvalidChannel("渠道名称不能为空".to_string()));
        }
        let id = config.id;
        self.channels.insert(id, channel);
        self.channel_meta.insert(id, config);
        Ok(())
    }

    /// 追加维护窗口（静默期：窗口内一律抑制，**含**本窗口开始时已存在的去重记录无关）。
    pub fn add_maintenance_window(&mut self, window: MaintenanceWindow) {
        self.maintenance.push(window);
    }

    /// 覆盖维护窗口集合。
    pub fn set_maintenance_windows(&mut self, windows: Vec<MaintenanceWindow>) {
        self.maintenance = windows;
    }

    /// 只读配置。
    #[must_use]
    pub const fn config(&self) -> &DispatchConfig {
        &self.config
    }

    /// 审计记录（按发生顺序）。
    #[must_use]
    pub fn audit(&self) -> &[DeliveryAttempt] {
        &self.audit
    }

    /// 审计记录快照。
    #[must_use]
    pub fn audit_owned(&self) -> Vec<DeliveryAttempt> {
        self.audit.clone()
    }

    /// 已成功投递过的去重键数。
    #[must_use]
    pub fn delivered_keys(&self) -> usize {
        self.delivered.len()
    }

    /// 是否已向该渠道投递过该去重键。
    #[must_use]
    pub fn already_delivered(&self, channel_id: Id, dedup_key: &str) -> bool {
        self.delivered.get(dedup_key) == Some(&channel_id)
    }

    /// 把去重键标记为已投递（供外部回填历史，避免重启后重复轰炸）。
    pub fn seed_delivered(&mut self, channel_id: Id, dedup_key: impl Into<String>) {
        self.delivered.insert(dedup_key.into(), channel_id);
    }

    /// 清空限流计数。
    pub fn reset_rate_limit(&mut self) {
        self.limiter.reset();
    }

    /// 某渠道当前窗口内已用配额。
    #[must_use]
    pub fn rate_used(&self, channel_id: Id, now: Timestamp) -> usize {
        self.limiter.used(channel_id, now)
    }

    /// 构造一条待投递消息（自动推导去重键）。
    #[must_use]
    pub fn build_message(
        &self,
        tenant_id: TenantId,
        channel: &ChannelConfig,
        subject_kind: &str,
        subject_id: Id,
        title: &str,
        body: &str,
        severity: Severity,
        at: Timestamp,
    ) -> OutboundMessage {
        OutboundMessage {
            tenant_id,
            channel_id: channel.id,
            kind: channel.kind,
            subject_kind: subject_kind.to_string(),
            subject_id,
            dedup_key: dedup_key(tenant_id, subject_kind, subject_id, channel.id),
            title: title.to_string(),
            body: channel.template.as_deref().map_or_else(
                || body.to_string(),
                |t| {
                    let ctx = NotifyContext {
                        title: title.to_string(),
                        severity: severity.as_str().to_string(),
                        domain: String::new(),
                        asset: String::new(),
                        summary: body.to_string(),
                        console_url: String::new(),
                        at: display_timestamp(at),
                        extra: BTreeMap::new(),
                    };
                    ctx.render(t)
                },
            ),
            severity,
            targets: channel.targets.clone(),
            at,
            extra: BTreeMap::new(),
        }
    }

    /// 派发一条消息到其指定渠道。
    ///
    /// # Errors
    /// 消息租户与已注册渠道元数据不一致时返回 [`NotifyError::TenantViolation`]。
    pub async fn dispatch(&mut self, message: &OutboundMessage) -> Result<ChannelDelivery, NotifyError> {
        let meta = self.channel_meta.get(&message.channel_id).cloned();
        if let Some(meta) = &meta {
            if meta.tenant_id != message.tenant_id {
                return Err(NotifyError::TenantViolation {
                    expected: message.tenant_id.to_string(),
                    actual: meta.tenant_id.to_string(),
                });
            }
        }
        let delivery = self.deliver_one(message, meta.as_ref()).await;
        self.audit.push(DeliveryAttempt {
            id: Id::new(),
            tenant_id: message.tenant_id,
            channel_id: message.channel_id,
            kind: message.kind,
            subject_kind: message.subject_kind.clone(),
            subject_id: message.subject_id,
            dedup_key: message.dedup_key.clone(),
            attempts: delivery.attempts,
            outcome: delivery.outcome,
            suppressed_by: delivery.suppressed_by,
            backoff_ms: None,
            receipt: delivery.receipt.clone(),
            error: delivery.error.clone(),
            at: message.at,
        });
        Ok(delivery)
    }

    /// 按顺序派发到多个渠道（各渠道独立判定，互不影响）。
    ///
    /// # Errors
    /// 任一渠道租户不符时返回错误（已派发的渠道不回滚——通知不可撤回，
    /// 因此错误信息会明确说明已经发出的部分）。
    pub async fn dispatch_all(
        &mut self,
        tenant_id: TenantId,
        channels: &[ChannelConfig],
        subject_kind: &str,
        subject_id: Id,
        title: &str,
        body: &str,
        severity: Severity,
        at: Timestamp,
    ) -> Result<DispatchResult, NotifyError> {
        let mut deliveries = Vec::with_capacity(channels.len());
        // 结果级去重键取**首个渠道**的键：去重键内含渠道 id，多渠道没有唯一的"那一个"键，
        // 取首个渠道与派发顺序一致，便于上层按渠道对账（逐渠道键见各条 `ChannelDelivery` 的审计）。
        let dedup_key_value = channels
            .first()
            .map_or_else(String::new, |channel| dedup_key(tenant_id, subject_kind, subject_id, channel.id));
        for channel in channels {
            let message = self.build_message(tenant_id, channel, subject_kind, subject_id, title, body, severity, at);
            deliveries.push(self.dispatch(&message).await?);
        }
        Ok(DispatchResult { dedup_key: dedup_key_value, deliveries })
    }

    /// 单渠道投递（决策 + 重试）。
    pub(crate) async fn deliver_one(
        &mut self,
        message: &OutboundMessage,
        meta: Option<&ChannelConfig>,
    ) -> ChannelDelivery {
        let base = ChannelDelivery {
            channel_id: message.channel_id,
            kind: message.kind,
            outcome: DeliveryOutcome::Suppressed,
            suppressed_by: None,
            attempts: 0,
            receipt: None,
            error: None,
        };
        // ① 渠道可用性
        let Some(meta) = meta else {
            return ChannelDelivery {
                suppressed_by: Some(SuppressCause::Unroutable),
                error: Some("渠道未注册".to_string()),
                ..base
            };
        };
        if !meta.accepts_severity(message.severity) {
            return ChannelDelivery {
                suppressed_by: Some(SuppressCause::Unroutable),
                error: Some(format!("渠道 {} 不接受等级 {}", meta.name, message.severity.as_str())),
                ..base
            };
        }
        let Some(channel) = self.channels.get(&message.channel_id).cloned() else {
            return ChannelDelivery {
                suppressed_by: Some(SuppressCause::Unroutable),
                error: Some("渠道未注入实现".to_string()),
                ..base
            };
        };
        // ② 去重
        if self.already_delivered(message.channel_id, &message.dedup_key) {
            return ChannelDelivery { suppressed_by: Some(SuppressCause::Dedup), ..base };
        }
        // ③ 维护窗口
        let asset = message.extra.get("asset_id").and_then(|s| Id::parse(s).ok());
        if self.maintenance.iter().any(|w| w.covers(message.at, asset.as_ref())) {
            return ChannelDelivery { suppressed_by: Some(SuppressCause::Maintenance), ..base };
        }
        // ④ 限流（抑制不消耗配额）
        if !self.limiter.try_acquire(message.channel_id, message.at) {
            return ChannelDelivery { suppressed_by: Some(SuppressCause::RateLimit), ..base };
        }
        // ⑤ 投递 + 重试
        let mut attempts = 0u32;
        let mut last_error = String::new();
        while attempts < self.config.max_attempts {
            attempts = attempts.saturating_add(1);
            if self.config.dry_run {
                return ChannelDelivery {
                    outcome: DeliveryOutcome::Delivered,
                    attempts,
                    receipt: Some("dry-run：未实际投递".to_string()),
                    ..base
                };
            }
            match channel.send(message).await {
                Ok(receipt) => {
                    self.delivered.insert(message.dedup_key.clone(), message.channel_id);
                    return ChannelDelivery {
                        outcome: DeliveryOutcome::Delivered,
                        attempts,
                        receipt: Some(receipt.detail),
                        ..base
                    };
                }
                Err(reason) => {
                    last_error = reason;
                    if attempts < self.config.max_attempts {
                        let backoff = self.config.backoff_ms(attempts);
                        self.audit.push(DeliveryAttempt {
                            id: Id::new(),
                            tenant_id: message.tenant_id,
                            channel_id: message.channel_id,
                            kind: message.kind,
                            subject_kind: message.subject_kind.clone(),
                            subject_id: message.subject_id,
                            dedup_key: message.dedup_key.clone(),
                            attempts,
                            outcome: DeliveryOutcome::Failed,
                            suppressed_by: None,
                            backoff_ms: Some(backoff),
                            receipt: None,
                            error: Some(last_error.clone()),
                            at: message.at,
                        });
                    }
                }
            }
        }
        ChannelDelivery { outcome: DeliveryOutcome::Failed, attempts, error: Some(last_error), ..base }
    }

    /// 派发结果 → `agf-core` 投递记录（落库用）。
    #[must_use]
    pub fn to_record(
        &self,
        tenant_id: TenantId,
        delivery: &ChannelDelivery,
        subject_kind: &str,
        subject_id: Id,
        dedup_key: &str,
        title: &str,
        body: &str,
    ) -> NotificationRecord {
        NotificationRecord {
            id: Id::new(),
            tenant_id,
            channel_id: delivery.channel_id,
            kind: delivery.kind,
            subject_kind: subject_kind.to_string(),
            subject_id,
            dedup_key: dedup_key.to_string(),
            title: title.to_string(),
            body: body.to_string(),
            state: delivery.outcome.to_core_state(),
            attempts: delivery.attempts,
            error: delivery.error.clone(),
            created_at: Timestamp::now(),
            delivered_at: if delivery.outcome == DeliveryOutcome::Delivered { Some(Timestamp::now()) } else { None },
        }
    }
}
