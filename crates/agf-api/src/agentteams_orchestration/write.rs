use super::*;
use crate::policy_store::{AccessLease, AuthorizedSubmission, Grant, PublicationAuthorization, authorize_publication};
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    rbac::SubjectKind,
};

pub(super) static AUTHORIZATION: PublicationAuthorization = PublicationAuthorization {
    resource: "platform",
    action: "admin",
    additional: &[Grant { resource: "alicloud", action: "read" }, Grant { resource: "alicloud", action: "write" }],
};
pub(super) fn audit(principal: &Principal, fact: &model::Intent) -> AuditLog {
    AuditLog {
        id: Id::new(),
        tenant_id: principal.tenant,
        sequence: 0,
        action: AuditAction::Update,
        outcome: AuditOutcome::Success,
        actor: AppState::audit_actor(principal, "application-orchestration"),
        target: AuditTarget::new(KIND, None, None),
        before: None,
        after: Some(json!({"version":fact.version,"action":fact.action,"direction":fact.direction,
            "localHash":fact.local_hash,"receiverHash":fact.receiver_hash,
            "localNodeCount":fact.local_node_count,"receiverNodeCount":fact.receiver_node_count,"providerCalled":false})),
        changed_fields: vec!["application_owned_definition".into()],
        request_id: Some(fact.request_id.to_string()),
        error: None,
        note: "明确应用声明/独立 Mock 接收侧同步；不执行业务或修改云端，consumer 未知".into(),
        prev_hash: String::new(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    }
}
pub(super) async fn submit(
    state: &AppState,
    principal: &Principal,
    lease: Option<&AccessLease>,
    team: &str,
    input: model::Input,
) -> DomainResult<model::Intent> {
    if principal.subject_kind != SubjectKind::User || principal.subject_id.is_none_or(|id| id.is_nil()) {
        return Err(DomainError::Forbidden("编排定义需管理员用户会话明确确认；Key 或 CloudRole 不提供发布权限".into()));
    }
    if input.request_id.is_nil() || serde_json::to_vec(&input)?.len() > 300 * 1024 {
        return Err(invalid());
    }
    let submission =
        AuthorizedSubmission { principal, submitted_at: Timestamp::now(), lease, authorization: &AUTHORIZATION };
    authorize_publication(state, &submission).await?;
    if state.store.database().is_some() {
        sql::publish(state, &submission, team, &input).await
    } else {
        offline::publish(state, &submission, team, &input).await
    }
}
