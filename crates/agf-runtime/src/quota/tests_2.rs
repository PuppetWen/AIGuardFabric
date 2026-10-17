//! 由 `quota.rs` 拆分：`explicit_target_id_takes_precedence_in_key` 等 7 个函数（纯搬移，逻辑不变）。
use super::*;
use agf_core::time::Timestamp;

#[tokio::test]
pub(crate) async fn explicit_target_id_takes_precedence_in_key() {
    let agent = Id::new();
    let mut q = quota(QuotaScope::Tenant, QuotaDimension::Requests, 1, PolicyAction::Deny);
    q.target_id = Some(agent);
    let service = QuotaService::in_memory(vec![q]);
    let key = QuotaService::quota_key(&service.quotas()[0].clone(), None, "s-1");
    assert_eq!(
        key.as_ref().and_then(|k| k.target.clone()),
        Some(agent.to_string()),
        "显式 target_id 必须优先于作用域默认目标"
    );
    // 显式 target_id 时：session 级目标被覆盖，两个会话共用同一计数器 ⇒ 第二次应超限
    assert!(service.check(TenantId::default_tenant(), None, "s-1", &one()).await.is_ok());
    let second = service.check(TenantId::default_tenant(), None, "s-2", &one()).await;
    assert!(second.is_ok());
    let Some(second) = second.ok() else { return };
    assert!(!second.allowed(), "同一个 target_id 应共用计数器");
}

#[tokio::test]
pub(crate) async fn window_bucket_is_part_of_key() {
    let q = quota(QuotaScope::Tenant, QuotaDimension::Requests, 10, PolicyAction::Deny);
    let service = QuotaService::in_memory(vec![q]);
    let key = QuotaService::quota_key(&service.quotas()[0].clone(), None, "s");
    assert!(key.is_some());
    let Some(key) = key else { return };
    assert_eq!(key.bucket, QuotaWindow::Day.bucket_key(Timestamp::now()));
    assert_eq!(key.scope, "tenant");
    assert_eq!(key.dimension, "requests");
    assert_eq!(key.target, None);
    // 定位串以租户开头（Redis 键布局），随后是 scope/dimension/bucket/target
    assert!(
        key.describe().starts_with(&format!("{}|tenant|requests|", TenantId::default_tenant())),
        "{}",
        key.describe()
    );
}

#[tokio::test]
pub(crate) async fn outcome_helpers() {
    let pass = QuotaCheckOutcome::pass();
    assert!(pass.allowed());
    assert!(!pass.degraded);
    assert!(!pass.soft_breached());
    assert!(!pass.blocked_by_degradation());
    let o = QuotaCheckOutcome { check: QuotaCheck::pass(), degraded: true, reason: Some("x".into()) };
    assert!(!o.blocked_by_degradation(), "降级但放行不算被拒");
}

#[tokio::test]
pub(crate) async fn in_memory_store_semantics() {
    let store = InMemoryQuotaStore::new();
    let k = key_of(QuotaScope::Session, QuotaDimension::Requests, Some("s-1"));
    let unlimited = key_of(QuotaScope::Tenant, QuotaDimension::Concurrency, None);
    let missing = key_of(QuotaScope::Agent, QuotaDimension::Tokens, Some("a-1"));
    let ok = store.check_and_consume(&k, 2, 1, 0).await;
    assert_eq!(ok, Ok(ConsumeOutcome { allowed: true, used: 1 }));
    let ok = store.check_and_consume(&k, 2, 1, 0).await;
    assert_eq!(ok, Ok(ConsumeOutcome { allowed: true, used: 2 }));
    let over = store.check_and_consume(&k, 2, 1, 0).await;
    assert_eq!(over, Ok(ConsumeOutcome { allowed: false, used: 2 }));
    assert_eq!(store.value(&k), 2, "超限请求不得污染计数");
    let released = store.release(&k, 1).await;
    assert_eq!(released, Ok(1));
    // limit <= 0 视为不限量
    for _ in 0..5 {
        assert_eq!(store.check_and_consume(&unlimited, 0, 10, 0).await.map(|o| o.allowed), Ok(true));
    }
    // 负消费被拒
    assert!(store.check_and_consume(&k, 1, -1, 0).await.is_err());
    // 归还不会变成负数
    let _ = store.release(&k, 100).await;
    assert_eq!(store.value(&k), 0);
    assert!(store.peek(&missing).await.is_ok_and(|v| v == 0));
    assert!(!store.is_degraded());
    assert_eq!(store.key_count(), 2);
}

#[tokio::test]
pub(crate) async fn store_error_helpers() {
    let closed = QuotaStoreError::unavailable("x");
    assert!(closed.closed);
    let invalid = QuotaStoreError::invalid("y");
    assert!(!invalid.closed);
    assert!(closed.to_string().contains("closed=true"));
}

#[tokio::test]
pub(crate) async fn complete_reports_store_failure() {
    let store = std::sync::Arc::new(FailingStore {
        fail_consume: false,
        fail_peek: false,
        closed: false,
        releases: Mutex::new(BTreeMap::new()),
    });
    // release 永远成功；这里让补记失败 → 用 fail_consume 模拟
    let store2 = std::sync::Arc::new(FailingStore {
        fail_consume: true,
        fail_peek: false,
        closed: false,
        releases: Mutex::new(BTreeMap::new()),
    });
    let service =
        QuotaService::new(vec![quota(QuotaScope::Tenant, QuotaDimension::Tokens, 100, PolicyAction::Deny)], store2);
    let usage = QuotaConsumption { tokens: 10, requests: 0, concurrency: 0, cost_micro: 0 };
    let r = service.complete(TenantId::default_tenant(), None, "s", &usage).await;
    assert!(r.is_err());
    assert_eq!(r.err().map(|e| e.code()), Some("dependency_unavailable"));
    // 释放路径不受补记失败影响
    let service_ok =
        QuotaService::new(vec![quota(QuotaScope::Tenant, QuotaDimension::Concurrency, 5, PolicyAction::Deny)], store);
    assert!(service_ok.complete(TenantId::default_tenant(), None, "s", &one()).await.is_ok());
}

#[tokio::test]
pub(crate) async fn replace_quotas_hot_swap() {
    let mut service =
        QuotaService::in_memory(vec![quota(QuotaScope::Tenant, QuotaDimension::Requests, 1, PolicyAction::Deny)]);
    assert!(service.check(TenantId::default_tenant(), None, "s", &one()).await.is_ok_and(|o| o.allowed()));
    let second = service.check(TenantId::default_tenant(), None, "s", &one()).await;
    assert!(second.is_ok_and(|o| !o.allowed()));
    service.replace_quotas(vec![quota(QuotaScope::Tenant, QuotaDimension::Requests, 100, PolicyAction::Deny)]);
    let after = service.check(TenantId::default_tenant(), None, "s", &one()).await;
    assert!(after.is_ok_and(|o| o.allowed()), "热替换配额后应按新上限判定");
    assert_eq!(service.quotas().len(), 1);
}
