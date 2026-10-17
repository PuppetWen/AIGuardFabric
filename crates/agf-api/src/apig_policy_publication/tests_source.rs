//! 条件和计量语义必须拒绝，不可默默转成更宽的云 API 全局规则。
use super::*;
use crate::quota_definitions::VersionedQuota;
use agf_alicloud::apig::policy_driver::ManagedLimit;
use agf_core::{
    enums::{PolicyAction, QuotaDimension, QuotaScope},
    ids::{Id, TenantId},
    policy::Policy,
    quota::QuotaWindow,
    time::Timestamp,
};
use agf_runtime::signature::PolicySigner;
use serde_json::json;

fn fixture() -> (TenantId, Policy, VersionedQuota, PolicySigner) {
    let tenant = TenantId::default_tenant();
    let now = Timestamp::now();
    let quota_id = Id::new();
    let signer = PolicySigner::new(vec![91; 32], "owned-apig-source").unwrap();
    let mut policy: Policy = serde_json::from_value(json!({
        "id":Id::new(),"tenant_id":tenant,"name":"owned quota blueprint",
        "language":"structured","source":"","action":"quota","priority":1,
        "enabled":true,"dry_run":false,"quota_id":quota_id,
        "content_hash":"","signature":"","version":1,"created_at":now,"updated_at":now,
        "intercept_points":["ai-gateway"]
    }))
    .unwrap();
    sign(&mut policy, &signer);
    let quota = serde_json::from_value(json!({
        "id":quota_id,"tenant_id":tenant,"name":"owned minute quota","scope":"tenant",
        "dimension":"requests","window":"minute","limit":100,"soft_threshold":0,
        "on_exceed":"deny","enabled":true,"created_at":now,"updated_at":now
    }))
    .unwrap();
    (tenant, policy, VersionedQuota { quota, version: 1 }, signer)
}
fn sign(policy: &mut Policy, signer: &PolicySigner) {
    policy.content_hash = policy.compute_hash();
    policy.signature = signer.sign(policy);
}

#[test]
fn source_projection_keeps_real_revisions_and_both_supported_dimensions() {
    let (tenant, policy, mut quota, signer) = fixture();
    let requests = derive_source_limit(tenant, &policy, &quota, &signer).unwrap();
    assert_eq!(requests.policy_id, policy.id);
    assert_eq!(requests.quota_id, quota.quota.id);
    assert_eq!((requests.policy_version, requests.quota_version, requests.limit), (1, 1, 100));
    assert_eq!(requests.managed_limit, ManagedLimit::RequestPerMinute);
    quota.quota.dimension = QuotaDimension::Tokens;
    quota.version = 2;
    let tokens = derive_source_limit(tenant, &policy, &quota, &signer).unwrap();
    assert_eq!(tokens.managed_limit, ManagedLimit::TokenPerMinute);
    assert_ne!(requests.quota_fingerprint, tokens.quota_fingerprint);
}

#[test]
fn signed_conditions_or_dry_run_cannot_become_api_global_enforcement() {
    let (tenant, original, quota, signer) = fixture();
    for change in ["dry-run", "agent", "department", "condition", "source", "point", "action"] {
        let mut policy = original.clone();
        match change {
            "dry-run" => policy.dry_run = true,
            "agent" => policy.scope_agent_ids.push(Id::new()),
            "department" => policy.scope_departments.push("研发".into()),
            "condition" => policy.structured.max_payload_bytes = Some(1024),
            "source" => policy.source = "true".into(),
            "point" => policy.intercept_points.clear(),
            "action" => policy.action = PolicyAction::Throttle,
            _ => unreachable!(),
        }
        sign(&mut policy, &signer);
        assert!(derive_source_limit(tenant, &policy, &quota, &signer).is_err(), "{change}");
    }
}

#[test]
fn cloud_profile_cannot_silently_drop_other_quota_semantics() {
    let (tenant, policy, original, signer) = fixture();
    for change in ["agent", "target", "hour", "throttle", "soft", "cost", "concurrency"] {
        let mut quota = original.clone();
        match change {
            "agent" => quota.quota.scope = QuotaScope::Agent,
            "target" => quota.quota.target_id = Some(Id::new()),
            "hour" => quota.quota.window = QuotaWindow::Hour,
            "throttle" => quota.quota.on_exceed = PolicyAction::Throttle,
            "soft" => quota.quota.soft_threshold = 80,
            "cost" => quota.quota.dimension = QuotaDimension::Cost,
            "concurrency" => quota.quota.dimension = QuotaDimension::Concurrency,
            _ => unreachable!(),
        }
        assert!(derive_source_limit(tenant, &policy, &quota, &signer).is_err(), "{change}");
    }
}

#[test]
fn int32_positive_limits_are_exact_and_never_clamped() {
    let (tenant, policy, mut quota, signer) = fixture();
    for limit in [1, i64::from(i32::MAX)] {
        quota.quota.limit = limit;
        assert_eq!(i64::from(derive_source_limit(tenant, &policy, &quota, &signer).unwrap().limit), limit);
    }
    for limit in [i64::MIN, -1, 0, i64::from(i32::MAX) + 1, i64::MAX] {
        quota.quota.limit = limit;
        assert!(derive_source_limit(tenant, &policy, &quota, &signer).is_err());
    }
}

#[test]
fn stale_unsigned_foreign_or_disabled_sources_are_rejected() {
    let (tenant, original, original_quota, signer) = fixture();
    for change in ["unsigned", "tamper", "disabled", "deleted", "version", "foreign", "quota-id"] {
        let mut policy = original.clone();
        match change {
            "unsigned" => policy.signature.clear(),
            "tamper" => policy.name = "tampered".into(),
            "disabled" => policy.enabled = false,
            "deleted" => policy.deleted_at = Some(Timestamp::now()),
            "version" => policy.version = 0,
            "foreign" => policy.tenant_id = TenantId::new(),
            "quota-id" => policy.quota_id = Some(Id::new()),
            _ => unreachable!(),
        }
        assert!(derive_source_limit(tenant, &policy, &original_quota, &signer).is_err(), "{change}");
    }
    for change in ["disabled", "version", "foreign", "id"] {
        let mut quota = original_quota.clone();
        match change {
            "disabled" => quota.quota.enabled = false,
            "version" => quota.version = 0,
            "foreign" => quota.quota.tenant_id = TenantId::new(),
            "id" => quota.quota.id = Id::new(),
            _ => unreachable!(),
        }
        assert!(derive_source_limit(tenant, &original, &quota, &signer).is_err(), "{change}");
    }
}
