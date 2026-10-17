//! 由 `approval.rs` 拆分：`build_request` 函数（纯搬移，逻辑不变）。
use super::*;

/// 构造审批单（运行时拦截路径使用）。
///
/// `ttl_secs <= 0` 时取 [`DEFAULT_TTL_SECS`]（避免"永不过期"的审批单）。
#[must_use]
pub fn build_request(
    tenant: TenantId,
    session_id: &str,
    agent_id: Option<Id>,
    intercept_point: InterceptPoint,
    target: &str,
    action: &str,
    reason: &str,
    excerpt: &str,
    ttl_secs: i64,
) -> ApprovalRecord {
    let now = Timestamp::now();
    let ttl = if ttl_secs > 0 { ttl_secs } else { DEFAULT_TTL_SECS };
    ApprovalRecord {
        request: ApprovalRequest {
            id: Id::new(),
            tenant_id: tenant,
            requester_id: agent_id.unwrap_or_else(Id::nil),
            target: target.to_string(),
            action: action.to_string(),
            reason: reason.to_string(),
            ttl_secs: ttl,
            state: ApprovalState::Pending,
            approver_id: None,
            decision_note: None,
            created_at: now,
            decided_at: None,
        },
        session_id: session_id.to_string(),
        agent_id,
        policy_id: None,
        policy_name: None,
        intercept_point,
        excerpt: excerpt.to_string(),
        expires_at: now.offset_secs(ttl),
        used_at: None,
        consumed_by: None,
    }
}
