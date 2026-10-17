//! 由 `quota.rs` 拆分：`quota` 等 11 个函数（纯搬移，逻辑不变）。

use crate::enums::{QuotaDimension, QuotaScope};
use crate::ids::{Id, TenantId};
use crate::time::Timestamp;

use super::*;

pub(crate) fn quota(
    scope: QuotaScope,
    dim: QuotaDimension,
    window: QuotaWindow,
    limit: i64,
    action: crate::enums::PolicyAction,
) -> Quota {
    let now = Timestamp::now();
    Quota {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "q".into(),
        scope,
        dimension: dim,
        window,
        limit,
        soft_threshold: limit / 2,
        on_exceed: action,
        enabled: true,
        target_id: None,
        created_at: now,
        updated_at: now,
    }
}

#[test]
pub(crate) fn window_buckets_are_stable() {
    let ts = Timestamp::parse_rfc3339("2026-03-01T10:05:30Z").unwrap_or_else(|_| Timestamp::now());
    assert_eq!(QuotaWindow::Minute.bucket_key(ts), "202603011005");
    assert_eq!(QuotaWindow::Hour.bucket_key(ts), "2026030110");
    assert_eq!(QuotaWindow::Day.bucket_key(ts), "20260301");
    assert_eq!(QuotaWindow::Session.bucket_key(ts), "session");
    assert_eq!(QuotaWindow::Total.bucket_key(ts), "total");
}

#[test]
pub(crate) fn window_seconds_and_parse() {
    assert_eq!(QuotaWindow::Minute.seconds(), Some(60));
    assert_eq!(QuotaWindow::Month.seconds(), Some(2_592_000));
    assert_eq!(QuotaWindow::Session.seconds(), None);
    assert_eq!(QuotaWindow::parse("1d"), Ok(QuotaWindow::Day));
    assert!(QuotaWindow::parse("fortnight").is_err());
    assert_eq!(QuotaWindow::all().len(), 6);
}

#[test]
pub(crate) fn exceeded_and_soft_threshold() {
    let q = quota(QuotaScope::Tenant, QuotaDimension::Tokens, QuotaWindow::Day, 100, crate::enums::PolicyAction::Deny);
    assert!(!q.is_exceeded(99));
    // 恰好用满不算超限（limit 是允许消耗的额度），超过 1 个才算
    assert!(!q.is_exceeded(100));
    assert!(q.is_exceeded(101));
    assert!(q.is_soft_breached(60));
    assert!(!q.is_soft_breached(100), "超限后不再算软阈值");
    assert_eq!(q.remaining(40), 60);
    assert!((q.usage_ratio(50) - 0.5).abs() < 1e-6);
}

#[test]
pub(crate) fn check_passes_when_under_limits() {
    let q = quota(QuotaScope::Tenant, QuotaDimension::Tokens, QuotaWindow::Day, 1000, crate::enums::PolicyAction::Deny);
    let c = QuotaConsumption { tokens: 100, requests: 1, concurrency: 1, cost_micro: 0 };
    let r = check_quotas(&[(q, 0)], &c);
    assert!(r.allowed);
    assert_eq!(r.action, crate::enums::PolicyAction::Allow);
}

#[test]
pub(crate) fn check_denies_on_exceed_with_projection() {
    let q = quota(QuotaScope::Agent, QuotaDimension::Tokens, QuotaWindow::Day, 100, crate::enums::PolicyAction::Deny);
    let c = QuotaConsumption { tokens: 20, requests: 1, concurrency: 1, cost_micro: 0 };
    let r = check_quotas(&[(q, 90)], &c);
    assert!(!r.allowed);
    assert_eq!(r.used, 110);
    assert_eq!(r.limit, 100);
    assert_eq!(r.scope, Some(QuotaScope::Agent));
    assert_eq!(r.action, crate::enums::PolicyAction::Deny);
    assert_eq!(r.retry_after_secs, Some(86_400));
}

#[test]
pub(crate) fn deny_outranks_throttle_and_degrade() {
    let deny =
        quota(QuotaScope::Tenant, QuotaDimension::Tokens, QuotaWindow::Day, 10, crate::enums::PolicyAction::Deny);
    let throttle = quota(
        QuotaScope::Agent,
        QuotaDimension::Requests,
        QuotaWindow::Minute,
        1,
        crate::enums::PolicyAction::Throttle,
    );
    let degrade =
        quota(QuotaScope::Session, QuotaDimension::Cost, QuotaWindow::Session, 5, crate::enums::PolicyAction::Degrade);
    let c = QuotaConsumption { tokens: 100, requests: 100, concurrency: 1, cost_micro: 100 };
    let r = check_quotas(&[(throttle, 0), (degrade, 0), (deny, 0)], &c);
    assert_eq!(r.action, crate::enums::PolicyAction::Deny);
    assert_eq!(r.dimension, Some(QuotaDimension::Tokens));
    // 去掉 deny 后应落到 throttle
    let deny2 =
        quota(QuotaScope::Tenant, QuotaDimension::Tokens, QuotaWindow::Day, 10, crate::enums::PolicyAction::Deny);
    let _ = deny2;
    let r2 = check_quotas(
        &[
            (
                quota(
                    QuotaScope::Agent,
                    QuotaDimension::Requests,
                    QuotaWindow::Minute,
                    1,
                    crate::enums::PolicyAction::Throttle,
                ),
                0,
            ),
            (
                quota(
                    QuotaScope::Session,
                    QuotaDimension::Cost,
                    QuotaWindow::Session,
                    5,
                    crate::enums::PolicyAction::Degrade,
                ),
                0,
            ),
        ],
        &c,
    );
    assert_eq!(r2.action, crate::enums::PolicyAction::Throttle);
}

#[test]
pub(crate) fn disabled_quota_is_ignored() {
    let mut q =
        quota(QuotaScope::Tenant, QuotaDimension::Tokens, QuotaWindow::Day, 1, crate::enums::PolicyAction::Deny);
    q.enabled = false;
    let c = QuotaConsumption { tokens: 1000, requests: 1, concurrency: 1, cost_micro: 0 };
    assert!(check_quotas(&[(q, 0)], &c).allowed);
}

#[test]
pub(crate) fn soft_breach_collected_but_still_allowed() {
    let q = quota(QuotaScope::Tenant, QuotaDimension::Tokens, QuotaWindow::Day, 1000, crate::enums::PolicyAction::Deny);
    let c = QuotaConsumption { tokens: 600, requests: 1, concurrency: 1, cost_micro: 0 };
    let r = check_quotas(&[(q.clone(), 0)], &c);
    assert!(r.allowed);
    assert_eq!(r.soft_breached, vec![q.id]);
}

#[test]
pub(crate) fn tenant_default_quota_shape() {
    let q = Quota::tenant_default(TenantId::default_tenant(), QuotaDimension::Tokens, 1_000_000);
    assert_eq!(q.scope, QuotaScope::Tenant);
    assert_eq!(q.window, QuotaWindow::Day);
    assert_eq!(q.soft_threshold, 800_000);
}

#[test]
pub(crate) fn consumption_dimension_lookup() {
    let c = QuotaConsumption { tokens: 1, requests: 2, concurrency: 3, cost_micro: 4 };
    assert_eq!(c.value(QuotaDimension::Tokens), 1);
    assert_eq!(c.value(QuotaDimension::Requests), 2);
    assert_eq!(c.value(QuotaDimension::Concurrency), 3);
    assert_eq!(c.value(QuotaDimension::Cost), 4);
    assert_eq!(QuotaConsumption::one_request().requests, 1);
}
