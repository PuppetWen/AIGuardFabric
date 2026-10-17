//! 枚举解析辅助（parse_ 系列），路由与外部共用。

use super::*;

/// 解析告警状态。
///
/// # Errors
/// 未知状态。
pub fn parse_alert_state(raw: &str) -> Result<AlertState, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "open" => Ok(AlertState::Open),
        "acknowledged" => Ok(AlertState::Acknowledged),
        "suppressed" => Ok(AlertState::Suppressed),
        "escalated" => Ok(AlertState::Escalated),
        "closed" => Ok(AlertState::Closed),
        other => Err(ApiError::new(DomainError::Validation(format!("未知告警状态: {other}")))),
    }
}

/// 解析案件状态。
///
/// # Errors
/// 未知状态。
pub fn parse_case_state(raw: &str) -> Result<CaseState, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "new" => Ok(CaseState::New),
        "investigating" => Ok(CaseState::Investigating),
        "containing" => Ok(CaseState::Containing),
        "resolved" => Ok(CaseState::Resolved),
        "closed" => Ok(CaseState::Closed),
        other => Err(ApiError::new(DomainError::Validation(format!("未知案件状态: {other}")))),
    }
}

/// 解析案件事件类型。
///
/// # Errors
/// 未知类型。
pub fn parse_case_event_kind(raw: &str) -> Result<CaseEventKind, ApiError> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "created" => Ok(CaseEventKind::Created),
        "state-changed" => Ok(CaseEventKind::StateChanged),
        "assigned" => Ok(CaseEventKind::Assigned),
        "evidence-added" => Ok(CaseEventKind::EvidenceAdded),
        "comment" => Ok(CaseEventKind::Comment),
        "containment" => Ok(CaseEventKind::Containment),
        "isolation" => Ok(CaseEventKind::Isolation),
        "credential-revoked" => Ok(CaseEventKind::CredentialRevoked),
        "blocklisted" => Ok(CaseEventKind::Blocklisted),
        "escalated" => Ok(CaseEventKind::Escalated),
        "closed" => Ok(CaseEventKind::Closed),
        other => Err(ApiError::new(DomainError::Validation(format!("未知案件事件类型: {other}")))),
    }
}

/// 解析配额作用域。
///
/// # Errors
/// 未知作用域。
pub fn parse_quota_scope(raw: &str) -> Result<QuotaScope, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tenant" => Ok(QuotaScope::Tenant),
        "agent" => Ok(QuotaScope::Agent),
        "session" => Ok(QuotaScope::Session),
        other => Err(ApiError::new(DomainError::Validation(format!("未知配额作用域: {other}")))),
    }
}

/// 解析配额维度。
///
/// # Errors
/// 未知维度。
pub fn parse_quota_dimension(raw: &str) -> Result<QuotaDimension, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tokens" => Ok(QuotaDimension::Tokens),
        "requests" => Ok(QuotaDimension::Requests),
        "concurrency" => Ok(QuotaDimension::Concurrency),
        "cost" => Ok(QuotaDimension::Cost),
        other => Err(ApiError::new(DomainError::Validation(format!("未知配额维度: {other}")))),
    }
}
