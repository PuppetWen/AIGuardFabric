//! 由 `quota.rs` 拆分：`FailingStore`/`impl_FailingStore` 等 23 项（纯搬移，逻辑不变）。
use super::*;
use agf_core::time::Timestamp;

/// 可控失败的存储替身：覆盖 fail-open / fail-closed 两条路径。
#[derive(Debug, Default)]
pub(crate) struct FailingStore {
    /// 是否对 `check_and_consume` 报错。
    pub(crate) fail_consume: bool,
    /// 是否对 `peek` 报错。
    pub(crate) fail_peek: bool,
    /// 报错时 `closed` 的取值。
    pub(crate) closed: bool,
    /// 记录被释放的额度（键 → 累计）。
    pub(crate) releases: Mutex<BTreeMap<String, i64>>,
}

#[async_trait]
impl QuotaStore for FailingStore {
    async fn check_and_consume(
        &self,
        _key: &QuotaKey,
        _limit: i64,
        _amount: i64,
        _window_secs: i64,
    ) -> Result<ConsumeOutcome, QuotaStoreError> {
        if self.fail_consume {
            return Err(QuotaStoreError { reason: "redis 不可达".into(), closed: self.closed });
        }
        Ok(ConsumeOutcome { allowed: true, used: 1 })
    }

    async fn release(&self, key: &QuotaKey, amount: i64) -> Result<i64, QuotaStoreError> {
        if let Ok(mut m) = self.releases.lock() {
            *m.entry(key.describe()).or_insert(0) += amount;
        }
        Ok(0)
    }

    async fn peek(&self, _key: &QuotaKey) -> Result<i64, QuotaStoreError> {
        if self.fail_peek {
            return Err(QuotaStoreError { reason: "redis 不可达".into(), closed: self.closed });
        }
        Ok(0)
    }
}

pub(crate) fn quota(scope: QuotaScope, dimension: QuotaDimension, limit: i64, action: PolicyAction) -> Quota {
    let mut q = Quota::tenant_default(TenantId::default_tenant(), dimension, limit);
    q.scope = scope;
    q.on_exceed = action;
    q.soft_threshold = 0;
    q
}

/// 构造测试用计数器定位（与 `QuotaService::quota_key` 的规则一致）。
pub(crate) fn key_of(scope: QuotaScope, dimension: QuotaDimension, target: Option<&str>) -> QuotaKey {
    QuotaKey {
        tenant: TenantId::default_tenant(),
        scope: scope.as_str().to_string(),
        dimension: dimension.as_str().to_string(),
        bucket: QuotaWindow::Day.bucket_key(Timestamp::now()),
        target: target.map(str::to_string),
    }
}

pub(crate) fn one() -> QuotaConsumption {
    QuotaConsumption::one_request()
}

#[tokio::test]
pub(crate) async fn three_levels_are_all_enforced() {
    let tenant = TenantId::default_tenant();
    let agent = Id::new();
    let service = QuotaService::in_memory(vec![
        quota(QuotaScope::Tenant, QuotaDimension::Requests, 100, PolicyAction::Deny),
        quota(QuotaScope::Agent, QuotaDimension::Requests, 5, PolicyAction::Deny),
        quota(QuotaScope::Session, QuotaDimension::Requests, 2, PolicyAction::Throttle),
    ]);
    // 会话级最先顶到（limit 2）
    for i in 0..2 {
        let r = service.check(tenant, Some(agent), "s-1", &one()).await;
        assert!(r.is_ok());
        assert!(r.is_ok_and(|o| o.allowed()), "第 {i} 次应放行");
    }
    let third = service.check(tenant, Some(agent), "s-1", &one()).await;
    assert!(third.is_ok());
    let Some(third) = third.ok() else { return };
    assert!(!third.allowed());
    assert_eq!(third.check.scope, Some(QuotaScope::Session));
    assert_eq!(third.check.action, PolicyAction::Throttle);
    // 换会话：会话级计数重置，但仍受 Agent 级（5）限制。
    // 账目：s-1 已用 Agent 额度 2（第三次被会话级挡下、未消费），
    // 因此 s-2 只能再走 2 次（会话级上限 2），此时 Agent 已用 4。
    for i in 0..2 {
        let r = service.check(tenant, Some(agent), "s-2", &one()).await;
        assert!(r.is_ok_and(|o| o.allowed()), "s-2 第 {i} 次应放行（会话额度未满）");
    }
    // s-3 第一次：会话额度 1/2、Agent 5/5（恰好用满不算超限）⇒ 放行
    let s3_first = service.check(tenant, Some(agent), "s-3", &one()).await;
    assert!(s3_first.as_ref().is_ok_and(QuotaCheckOutcome::allowed), "Agent 额度恰好用满时仍应放行: {s3_first:?}");
    // s-3 第二次：会话额度还剩 3/2 之内，但 Agent 将达 6/5 ⇒ 以 **Agent** 作用域拒绝
    let agent_blocked = service.check(tenant, Some(agent), "s-3", &one()).await;
    assert!(agent_blocked.is_ok());
    let Some(ab) = agent_blocked.ok() else { return };
    assert!(!ab.allowed());
    assert_eq!(ab.check.scope, Some(QuotaScope::Agent), "应报 Agent 级超限而不是会话级");
    assert_eq!(ab.check.used, 6);
    assert_eq!(ab.check.limit, 5);
}

#[tokio::test]
pub(crate) async fn tenant_level_limit_applies_across_agents() {
    let tenant = TenantId::default_tenant();
    let service =
        QuotaService::in_memory(vec![quota(QuotaScope::Tenant, QuotaDimension::Requests, 3, PolicyAction::Deny)]);
    for agent in [Id::new(), Id::new(), Id::new()] {
        let r = service.check(tenant, Some(agent), "s", &one()).await;
        assert!(r.is_ok_and(|o| o.allowed()));
    }
    let fourth = service.check(tenant, Some(Id::new()), "s", &one()).await;
    assert!(fourth.is_ok());
    let Some(f) = fourth.ok() else { return };
    assert!(!f.allowed());
    assert_eq!(f.check.scope, Some(QuotaScope::Tenant));
    assert_eq!(f.check.dimension, Some(QuotaDimension::Requests));
    assert_eq!(f.check.used, 4);
    assert_eq!(f.check.limit, 3);
}

#[tokio::test]
pub(crate) async fn agent_level_quota_is_skipped_without_agent_identity() {
    let service =
        QuotaService::in_memory(vec![quota(QuotaScope::Agent, QuotaDimension::Requests, 1, PolicyAction::Deny)]);
    for _ in 0..5 {
        let r = service.check(TenantId::default_tenant(), None, "s", &one()).await;
        assert!(r.is_ok_and(|o| o.allowed()), "无 Agent 身份时 Agent 级配额不适用");
    }
}

#[tokio::test]
pub(crate) async fn concurrency_is_consumed_and_released() {
    let tenant = TenantId::default_tenant();
    let agent = Id::new();
    let service =
        QuotaService::in_memory(vec![quota(QuotaScope::Session, QuotaDimension::Concurrency, 1, PolicyAction::Deny)]);
    // 第一个请求在飞：占用 1 个并发
    let first = service.check(tenant, Some(agent), "s-1", &one()).await;
    assert!(first.is_ok_and(|o| o.allowed()));
    // 第二个请求：并发已满 ⇒ 拒绝
    let second = service.check(tenant, Some(agent), "s-1", &one()).await;
    assert!(second.is_ok());
    let Some(second) = second.ok() else { return };
    assert!(!second.allowed(), "在飞请求应占用并发额度");
    assert_eq!(second.check.dimension, Some(QuotaDimension::Concurrency));
    // 第一个请求完成：释放并发
    let done = service.complete(tenant, Some(agent), "s-1", &one()).await;
    assert!(done.is_ok(), "{done:?}");
    // 现在又能进一个
    let third = service.check(tenant, Some(agent), "s-1", &one()).await;
    assert!(third.is_ok_and(|o| o.allowed()), "请求完成后并发额度应被释放");
}

#[tokio::test]
pub(crate) async fn complete_releases_concurrency_in_store() {
    let store = std::sync::Arc::new(InMemoryQuotaStore::new());
    let tenant = TenantId::default_tenant();
    let service = QuotaService::new(
        vec![quota(QuotaScope::Tenant, QuotaDimension::Concurrency, 10, PolicyAction::Deny)],
        store.clone(),
    );
    assert!(service.check(tenant, None, "s", &one()).await.is_ok());
    let key = key_of(QuotaScope::Tenant, QuotaDimension::Concurrency, None);
    assert_eq!(store.value(&key), 1);
    assert!(service.complete(tenant, None, "s", &one()).await.is_ok());
    assert_eq!(store.value(&key), 0, "完成后并发放回 0");
}

#[tokio::test]
pub(crate) async fn complete_records_post_hoc_token_usage() {
    let store = std::sync::Arc::new(InMemoryQuotaStore::new());
    let tenant = TenantId::default_tenant();
    let service = QuotaService::new(
        vec![quota(QuotaScope::Tenant, QuotaDimension::Tokens, 1000, PolicyAction::Deny)],
        store.clone(),
    );
    let usage = QuotaConsumption { tokens: 400, requests: 0, concurrency: 0, cost_micro: 0 };
    assert!(service.complete(tenant, None, "s", &usage).await.is_ok());
    let key = key_of(QuotaScope::Tenant, QuotaDimension::Tokens, None);
    assert_eq!(store.value(&key), 400);
    // 再补记 700 ⇒ 1100 超过上限
    let usage2 = QuotaConsumption { tokens: 700, requests: 0, concurrency: 0, cost_micro: 0 };
    assert!(service.complete(tenant, None, "s", &usage2).await.is_ok());
    assert_eq!(store.value(&key), 1100);
    // 下一次带 token 的检查应被拒
    let next = service
        .check(tenant, None, "s", &QuotaConsumption { tokens: 1, requests: 0, concurrency: 0, cost_micro: 0 })
        .await;
    assert!(next.is_ok());
    let Some(next) = next.ok() else { return };
    assert!(!next.allowed(), "后置计量的 token 也应参与超限判定");
    assert_eq!(next.check.dimension, Some(QuotaDimension::Tokens));
}

#[tokio::test]
pub(crate) async fn fail_closed_denies_when_store_is_down() {
    let store = std::sync::Arc::new(FailingStore {
        fail_consume: true,
        fail_peek: false,
        closed: true,
        releases: Mutex::new(BTreeMap::new()),
    });
    let service =
        QuotaService::new(vec![quota(QuotaScope::Tenant, QuotaDimension::Requests, 100, PolicyAction::Deny)], store);
    let r = service.check(TenantId::default_tenant(), None, "s", &one()).await;
    assert!(r.is_ok());
    let Some(r) = r.ok() else { return };
    assert!(!r.allowed(), "Deny 维度的配额必须 fail-closed");
    assert!(r.degraded);
    assert!(r.blocked_by_degradation());
    assert_eq!(r.check.action, PolicyAction::Deny);
    assert!(r.reason.as_deref().unwrap_or_default().contains("fail-closed"));
}

#[tokio::test]
pub(crate) async fn fail_open_allows_when_store_is_down_for_metering_dimensions() {
    let store = std::sync::Arc::new(FailingStore {
        fail_consume: true,
        fail_peek: false,
        closed: true,
        releases: Mutex::new(BTreeMap::new()),
    });
    let service =
        QuotaService::new(vec![quota(QuotaScope::Tenant, QuotaDimension::Requests, 100, PolicyAction::Audit)], store);
    let r = service.check(TenantId::default_tenant(), None, "s", &one()).await;
    assert!(r.is_ok());
    let Some(r) = r.ok() else { return };
    assert!(r.allowed(), "Audit 维度的配额应 fail-open");
    assert!(r.degraded, "但仍必须标记降级");
    assert!(r.reason.as_deref().unwrap_or_default().contains("fail-open"));
}

#[tokio::test]
pub(crate) async fn fail_mode_can_be_overridden_per_dimension() {
    let store = std::sync::Arc::new(FailingStore {
        fail_consume: true,
        fail_peek: false,
        closed: true,
        releases: Mutex::new(BTreeMap::new()),
    });
    // 配额本身是 Throttle（默认 fail-open），此处强制 fail-closed
    let service =
        QuotaService::new(vec![quota(QuotaScope::Tenant, QuotaDimension::Requests, 10, PolicyAction::Throttle)], store)
            .with_fail_mode(QuotaDimension::Requests, FailMode::FailClosed);
    let r = service.check(TenantId::default_tenant(), None, "s", &one()).await;
    assert!(r.is_ok());
    assert!(r.is_ok_and(|o| !o.allowed()), "覆盖后的 fail-closed 必须生效");
}

#[tokio::test]
pub(crate) async fn fail_mode_mapping_by_action() {
    assert_eq!(FailMode::for_action(PolicyAction::Deny), FailMode::FailClosed);
    assert_eq!(FailMode::for_action(PolicyAction::Isolate), FailMode::FailClosed);
    assert_eq!(FailMode::for_action(PolicyAction::CircuitBreak), FailMode::FailClosed);
    assert_eq!(FailMode::for_action(PolicyAction::Audit), FailMode::FailOpen);
    assert_eq!(FailMode::for_action(PolicyAction::Quota), FailMode::FailOpen);
    assert_eq!(FailMode::for_action(PolicyAction::Throttle), FailMode::FailOpen);
    assert_eq!(FailMode::for_action(PolicyAction::Degrade), FailMode::FailOpen);
    assert_eq!(FailMode::for_action(PolicyAction::Allow), FailMode::FailOpen);
    assert_eq!(FailMode::FailClosed.as_str(), "fail-closed");
}

#[tokio::test]
pub(crate) async fn fail_open_on_peek_failure_for_metering_dimension() {
    let store = std::sync::Arc::new(FailingStore {
        fail_consume: false,
        fail_peek: true,
        closed: true,
        releases: Mutex::new(BTreeMap::new()),
    });
    // 本次请求不消费 tokens ⇒ 走 peek 路径
    let service =
        QuotaService::new(vec![quota(QuotaScope::Tenant, QuotaDimension::Tokens, 100, PolicyAction::Quota)], store);
    let r = service.check(TenantId::default_tenant(), None, "s", &one()).await;
    assert!(r.is_ok());
    let Some(r) = r.ok() else { return };
    assert!(r.allowed());
    assert!(r.degraded);
}

#[tokio::test]
pub(crate) async fn soft_threshold_is_reported_but_allowed() {
    let mut q = quota(QuotaScope::Tenant, QuotaDimension::Requests, 10, PolicyAction::Deny);
    q.soft_threshold = 3;
    let service = QuotaService::in_memory(vec![q]);
    for _ in 0..3 {
        let r = service.check(TenantId::default_tenant(), None, "s", &one()).await;
        assert!(r.is_ok_and(|o| o.allowed()));
    }
    let r = service.check(TenantId::default_tenant(), None, "s", &one()).await;
    assert!(r.is_ok());
    let Some(r) = r.ok() else { return };
    assert!(r.allowed(), "软阈值只告警不拦截");
    assert!(r.soft_breached());
    assert_eq!(r.check.soft_breached.len(), 1);
}

#[tokio::test]
pub(crate) async fn snapshot_reports_used_and_limits() {
    let service = QuotaService::in_memory(vec![
        quota(QuotaScope::Tenant, QuotaDimension::Requests, 10, PolicyAction::Deny),
        quota(QuotaScope::Session, QuotaDimension::Tokens, 100, PolicyAction::Audit),
    ]);
    let tenant = TenantId::default_tenant();
    for _ in 0..4 {
        assert!(service.check(tenant, None, "s-1", &one()).await.is_ok());
    }
    let snap = service.snapshot(tenant, None, "s-1").await;
    assert!(snap.is_ok());
    let Some(snap) = snap.ok() else { return };
    assert_eq!(snap.entries.len(), 2);
    assert!(!snap.degraded);
    let requests = snap.entries.iter().find(|e| e.dimension == QuotaDimension::Requests);
    assert_eq!(requests.map(|e| e.used), Some(4));
    assert_eq!(requests.map(|e| e.limit), Some(10));
    assert!(requests.is_some_and(|e| (e.ratio - 0.4).abs() < 1e-6));
    assert_eq!(snap.by_scope(QuotaScope::Tenant).len(), 1);
    assert_eq!(snap.by_scope(QuotaScope::Session).len(), 1);
    assert_eq!(snap.breached_count(), 0);
}

#[tokio::test]
pub(crate) async fn snapshot_flags_degradation_and_breach() {
    let store = std::sync::Arc::new(FailingStore {
        fail_consume: false,
        fail_peek: true,
        closed: true,
        releases: Mutex::new(BTreeMap::new()),
    });
    let service =
        QuotaService::new(vec![quota(QuotaScope::Tenant, QuotaDimension::Requests, 10, PolicyAction::Deny)], store);
    let snap = service.snapshot(TenantId::default_tenant(), None, "s").await;
    assert!(snap.is_ok());
    let Some(snap) = snap.ok() else { return };
    assert!(snap.degraded);
    assert_eq!(snap.entries[0].used, -1);
    assert!(snap.entries[0].degraded);
    assert!((snap.entries[0].ratio + 1.0).abs() < 1e-6);
}

#[tokio::test]
pub(crate) async fn disabled_and_foreign_tenant_quotas_are_ignored() {
    let mut disabled = quota(QuotaScope::Tenant, QuotaDimension::Requests, 1, PolicyAction::Deny);
    disabled.enabled = false;
    let mut foreign = quota(QuotaScope::Tenant, QuotaDimension::Requests, 1, PolicyAction::Deny);
    foreign.tenant_id = TenantId::new();
    let service = QuotaService::in_memory(vec![disabled, foreign]);
    for _ in 0..5 {
        let r = service.check(TenantId::default_tenant(), None, "s", &one()).await;
        assert!(r.is_ok_and(|o| o.allowed()), "停用与其它租户的配额不得生效");
    }
}

#[tokio::test]
pub(crate) async fn check_only_does_not_consume() {
    let store = std::sync::Arc::new(InMemoryQuotaStore::new());
    let service = QuotaService::new(
        vec![quota(QuotaScope::Tenant, QuotaDimension::Requests, 10, PolicyAction::Deny)],
        store.clone(),
    );
    for _ in 0..5 {
        let r = service.check_only(TenantId::default_tenant(), None, "s", &one()).await;
        assert!(r.is_ok_and(|o| o.allowed()));
    }
    assert_eq!(store.value(&key_of(QuotaScope::Tenant, QuotaDimension::Requests, None)), 0, "只读预检不得消费");
}

#[tokio::test]
pub(crate) async fn check_only_reports_exceeded_when_usage_is_high() {
    let store = std::sync::Arc::new(InMemoryQuotaStore::new());
    let service = QuotaService::new(
        vec![quota(QuotaScope::Tenant, QuotaDimension::Requests, 5, PolicyAction::Deny)],
        store.clone(),
    );
    let tenant = TenantId::default_tenant();
    for _ in 0..5 {
        assert!(service.check(tenant, None, "s", &one()).await.is_ok());
    }
    let r = service.check_only(tenant, None, "s", &one()).await;
    assert!(r.is_ok());
    let Some(r) = r.ok() else { return };
    assert!(!r.allowed());
    assert_eq!(r.check.used, 6);
}

#[tokio::test]
pub(crate) async fn quota_service_skips_dimensions_with_zero_consumption() {
    let service = QuotaService::in_memory(vec![
        quota(QuotaScope::Tenant, QuotaDimension::Tokens, 100, PolicyAction::Deny),
        quota(QuotaScope::Tenant, QuotaDimension::Cost, 100, PolicyAction::Deny),
    ]);
    // one_request 的 tokens=0 / cost=0 ⇒ 均走 peek 分支，不消费
    for _ in 0..10 {
        assert!(service.check(TenantId::default_tenant(), None, "s", &one()).await.is_ok_and(|o| o.allowed()));
    }
}
