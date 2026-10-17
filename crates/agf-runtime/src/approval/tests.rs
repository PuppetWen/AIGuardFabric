//! 由 `approval.rs` 拆分：`rec` 等 18 个函数（纯搬移，逻辑不变）。
use super::*;
use pretty_assertions::assert_eq;

pub(crate) fn rec(ttl_secs: i64) -> ApprovalRecord {
    build_request(
        TenantId::default_tenant(),
        "s-1",
        Some(Id::new()),
        InterceptPoint::McpProxy,
        "execute_shell",
        "approval",
        "大载荷 shell 调用需人工审批",
        "command=rm -rf /tmp/agf-sandbox",
        ttl_secs,
    )
}

#[tokio::test]
pub(crate) async fn pending_denies_then_approve_then_consume_once() {
    let store = InMemoryApprovalStore::new();
    let created = store.create(rec(300)).await;
    assert!(created.is_ok());
    let Some(created) = created.ok() else { return };
    let id = created.request.id;
    let tenant = created.request.tenant_id;
    // 待审批 ⇒ 判定为 Pending，不允许放行
    let got = store.get(tenant, id).await;
    assert!(got.is_ok());
    let Some(got) = got.ok() else { return };
    assert_eq!(got.effective_state(Timestamp::now()), Decision::Pending);
    assert!(!got.effective_state(Timestamp::now()).allows());
    // 待审批期间消费必须失败（绝不静默放行）
    let early = store.consume(tenant, id, "mcp-proxy").await;
    assert_eq!(early, Err(ApprovalError::NotConsumable { id, state: Decision::Pending }));
    // 批准
    let approved = store.approve(tenant, id, Id::new(), "同意，仅限沙箱路径").await;
    assert!(approved.is_ok());
    let Some(approved) = approved.ok() else { return };
    assert_eq!(approved.effective_state(Timestamp::now()), Decision::Approved);
    assert!(approved.effective_state(Timestamp::now()).allows());
    assert!(approved.request.approver_id.is_some());
    assert_eq!(approved.request.decision_note.as_deref(), Some("同意，仅限沙箱路径"));
    // 首次消费成功
    let used = store.consume(tenant, id, "mcp-proxy").await;
    assert!(used.is_ok());
    let Some(used) = used.ok() else { return };
    assert!(used.used_at.is_some());
    assert_eq!(used.consumed_by.as_deref(), Some("mcp-proxy"));
    assert_eq!(used.effective_state(Timestamp::now()), Decision::Used);
    // 再次消费必须失败（单次语义）
    let again = store.consume(tenant, id, "mcp-proxy").await;
    assert_eq!(again, Err(ApprovalError::AlreadyUsed(id)));
}

#[tokio::test]
pub(crate) async fn approval_expires_after_ttl() {
    let store = InMemoryApprovalStore::new();
    // TTL = -1 会走默认值，这里显式构造一个"已过期"的记录
    let mut record = rec(300);
    record.expires_at = Timestamp::now().offset_secs(-1);
    let created = store.create(record).await;
    assert!(created.is_ok());
    let Some(created) = created.ok() else { return };
    let id = created.request.id;
    let tenant = created.request.tenant_id;
    assert_eq!(created.effective_state(Timestamp::now()), Decision::Expired);
    // 过期后批准应失败
    let err = store.approve(tenant, id, Id::new(), "来晚了").await;
    assert_eq!(err, Err(ApprovalError::NotConsumable { id, state: Decision::Expired }));
    // 过期后消费应失败
    let err = store.consume(tenant, id, "mcp-proxy").await;
    assert_eq!(err, Err(ApprovalError::NotConsumable { id, state: Decision::Expired }));
    // 惰性标记
    let marked = store.expire_due(tenant, Timestamp::now()).await;
    assert_eq!(marked, Ok(1));
    let after = store.get(tenant, id).await;
    assert!(after.is_ok());
    assert_eq!(after.ok().map(|r| r.request.state), Some(ApprovalState::Expired), "expire_due 应把状态落为 Expired");
}

#[tokio::test]
pub(crate) async fn ttl_is_computed_from_now() {
    let store = InMemoryApprovalStore::new();
    let before = Timestamp::now();
    let created = store.create(rec(60)).await;
    assert!(created.is_ok());
    let Some(created) = created.ok() else { return };
    let remaining = created.remaining_secs(Timestamp::now());
    assert!((55..=60).contains(&remaining), "剩余有效期应接近 60 秒，实际 {remaining}");
    assert!(created.expires_at.is_at_or_after(&before));
    assert_eq!(created.request.ttl_secs, 60);
}

#[tokio::test]
pub(crate) async fn non_positive_ttl_falls_back_to_default() {
    let store = InMemoryApprovalStore::new();
    let created = store.create(rec(0)).await;
    assert!(created.is_ok());
    let Some(created) = created.ok() else { return };
    assert_eq!(created.request.ttl_secs, DEFAULT_TTL_SECS);
    assert!(!created.is_expired(Timestamp::now()));
}

#[tokio::test]
pub(crate) async fn reject_flow_blocks_consumption() {
    let store = InMemoryApprovalStore::new();
    let created = store.create(rec(300)).await;
    assert!(created.is_ok());
    let Some(created) = created.ok() else { return };
    let (id, tenant) = (created.request.id, created.request.tenant_id);
    let rejected = store.reject(tenant, id, Id::new(), "生产环境禁止").await;
    assert!(rejected.is_ok());
    assert_eq!(rejected.ok().map(|r| r.effective_state(Timestamp::now())), Some(Decision::Rejected));
    let err = store.consume(tenant, id, "mcp-proxy").await;
    assert_eq!(err, Err(ApprovalError::NotConsumable { id, state: Decision::Rejected }));
}

#[tokio::test]
pub(crate) async fn revoke_flow_blocks_consumption() {
    let store = InMemoryApprovalStore::new();
    let created = store.create(rec(300)).await;
    assert!(created.is_ok());
    let Some(created) = created.ok() else { return };
    let (id, tenant) = (created.request.id, created.request.tenant_id);
    assert!(store.approve(tenant, id, Id::new(), "ok").await.is_ok());
    assert!(store.revoke(tenant, id, "发现策略配置错误，撤回").await.is_ok());
    let err = store.consume(tenant, id, "mcp-proxy").await;
    assert_eq!(err, Err(ApprovalError::NotConsumable { id, state: Decision::Revoked }));
}

#[tokio::test]
pub(crate) async fn cannot_approve_twice() {
    let store = InMemoryApprovalStore::new();
    let created = store.create(rec(300)).await;
    assert!(created.is_ok());
    let Some(created) = created.ok() else { return };
    let (id, tenant) = (created.request.id, created.request.tenant_id);
    assert!(store.approve(tenant, id, Id::new(), "第一次").await.is_ok());
    let second = store.approve(tenant, id, Id::new(), "第二次").await;
    assert_eq!(second, Err(ApprovalError::NotConsumable { id, state: Decision::Approved }));
}

#[tokio::test]
pub(crate) async fn cannot_consume_after_used_even_if_state_is_approved() {
    let store = InMemoryApprovalStore::new();
    let created = store.create(rec(300)).await;
    assert!(created.is_ok());
    let Some(created) = created.ok() else { return };
    let (id, tenant) = (created.request.id, created.request.tenant_id);
    assert!(store.approve(tenant, id, Id::new(), "ok").await.is_ok());
    assert!(store.consume(tenant, id, "agent-a").await.is_ok());
    // 底层 state 仍是 Approved，但 used_at 已置 ⇒ 必须拒绝
    let record = store.get(tenant, id).await;
    assert_eq!(record.ok().map(|r| r.request.state), Some(ApprovalState::Approved));
    assert_eq!(store.consume(tenant, id, "agent-b").await, Err(ApprovalError::AlreadyUsed(id)));
}

#[tokio::test]
pub(crate) async fn missing_approval_is_reported() {
    let store = InMemoryApprovalStore::new();
    let id = Id::new();
    assert_eq!(store.get(TenantId::default_tenant(), id).await, Err(ApprovalError::NotFound(id)));
    assert_eq!(store.consume(TenantId::default_tenant(), id, "x").await, Err(ApprovalError::NotFound(id)));
    assert_eq!(store.approve(TenantId::default_tenant(), id, Id::new(), "x").await, Err(ApprovalError::NotFound(id)));
}

#[tokio::test]
pub(crate) async fn tenant_isolation_is_enforced() {
    let store = InMemoryApprovalStore::new();
    let created = store.create(rec(300)).await;
    assert!(created.is_ok());
    let Some(created) = created.ok() else { return };
    let id = created.request.id;
    // 另一个租户看不到、也不能批准
    let other = TenantId::new();
    assert_eq!(store.get(other, id).await, Err(ApprovalError::NotFound(id)));
    assert!(store.approve(other, id, Id::new(), "x").await.is_err());
    assert_eq!(store.list(other, None).await, Ok(vec![]));
    assert_eq!(store.list(TenantId::default_tenant(), None).await.map(|v| v.len()), Ok(1));
}

#[tokio::test]
pub(crate) async fn list_filters_by_decision() {
    let store = InMemoryApprovalStore::new();
    let a = store.create(rec(300)).await;
    let b = store.create(rec(300)).await;
    assert!(a.is_ok() && b.is_ok());
    let (Some(a), Some(b)) = (a.ok(), b.ok()) else { return };
    assert!(store.approve(a.request.tenant_id, a.request.id, Id::new(), "ok").await.is_ok());
    assert!(store.reject(b.request.tenant_id, b.request.id, Id::new(), "no").await.is_ok());
    let tenant = a.request.tenant_id;
    assert_eq!(store.list(tenant, Some(Decision::Approved)).await.map(|v| v.len()), Ok(1));
    assert_eq!(store.list(tenant, Some(Decision::Rejected)).await.map(|v| v.len()), Ok(1));
    assert_eq!(store.list(tenant, Some(Decision::Pending)).await.map(|v| v.len()), Ok(0));
    assert_eq!(store.list(tenant, None).await.map(|v| v.len()), Ok(2));
    assert_eq!(store.len(), 2);
    assert!(!store.is_empty());
}

#[tokio::test]
pub(crate) async fn duplicate_id_is_rejected() {
    let store = InMemoryApprovalStore::new();
    let record = rec(300);
    assert!(store.create(record.clone()).await.is_ok());
    let dup = store.create(record).await;
    assert!(dup.is_err());
    assert!(matches!(dup, Err(ApprovalError::Invalid(_))));
}

#[tokio::test]
pub(crate) async fn expiration_never_resurrects_a_used_approval() {
    let store = InMemoryApprovalStore::new();
    let mut record = rec(1);
    record.expires_at = Timestamp::now().offset_secs(-10);
    let created = store.create(record).await;
    assert!(created.is_ok());
    let Some(created) = created.ok() else { return };
    let (id, tenant) = (created.request.id, created.request.tenant_id);
    // 已过期的待审批单不会被 expire_due 之外的路径改写
    assert_eq!(store.expire_due(tenant, Timestamp::now()).await, Ok(1));
    // 二次 expire_due 不应重复计数
    assert_eq!(store.expire_due(tenant, Timestamp::now()).await, Ok(0));
    assert_eq!(store.get(tenant, id).await.map(|r| r.effective_state(Timestamp::now())), Ok(Decision::Expired));
}

#[tokio::test]
pub(crate) async fn decision_helpers() {
    assert!(Decision::Approved.allows());
    for d in [Decision::Pending, Decision::Rejected, Decision::Expired, Decision::Revoked, Decision::Used] {
        assert!(!d.allows(), "{d:?} 不应允许放行");
        assert!(!d.display_zh().is_empty());
        assert!(!d.as_str().is_empty());
    }
    assert_eq!(Decision::Pending.is_actionable(), true);
    assert!(!Decision::Approved.is_actionable());
    assert_eq!(Decision::Pending.display_zh(), "待审批");
    assert_eq!(Decision::Used.as_str(), "used");
}

#[tokio::test]
pub(crate) async fn console_link_and_context_are_recorded() {
    let record = rec(300);
    assert_eq!(record.console_link(), format!("approval/{}", record.request.id));
    assert_eq!(record.session_id, "s-1");
    assert_eq!(record.intercept_point, InterceptPoint::McpProxy);
    assert!(record.excerpt.contains("rm -rf"));
    assert!(record.agent_id.is_some());
    assert_eq!(record.request.action, "approval");
    assert_eq!(record.request.target, "execute_shell");
    assert!(record.request.reason.contains("人工审批"));
}

#[tokio::test]
pub(crate) async fn state_label_and_error_display() {
    assert_eq!(Decision::Expired.as_str(), "expired");
    let err = ApprovalError::AlreadyUsed(Id::nil());
    assert!(err.to_string().contains("已被使用过"));
    let domain: agf_core::error::DomainError = ApprovalError::StoreUnavailable("redis down".into()).into();
    assert_eq!(domain.code(), "dependency_unavailable");
    let domain: agf_core::error::DomainError = ApprovalError::NotFound(Id::nil()).into();
    assert_eq!(domain.code(), "not_found");
    let domain: agf_core::error::DomainError =
        ApprovalError::NotConsumable { id: Id::nil(), state: Decision::Pending }.into();
    assert_eq!(domain.code(), "precondition_failed");
}

#[test]
pub(crate) fn record_is_serializable() {
    let record = rec(120);
    let json = serde_json::to_string(&record);
    assert!(json.is_ok());
    let Some(json) = json.ok() else { return };
    let back: Result<ApprovalRecord, _> = serde_json::from_str(&json);
    assert!(back.is_ok());
    assert_eq!(back.ok().map(|r| r.session_id), Some("s-1".to_string()));
}
