//! Audit bodies are deliberately limited to safe immutable identities and outcome phases.
use super::{
    authority::Submission,
    records::{Fact, Operation, Status},
};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    ids::{Id, deterministic_id},
};
use serde_json::Value;

pub(super) fn entry(submission: &Submission, request: Id, kind: &str, action: AuditAction, after: Value) -> AuditLog {
    let mut audit = AppState::audit_entry(
        submission.principal.tenant,
        action,
        AuditOutcome::Success,
        AppState::audit_actor(&submission.principal, &submission.principal.display()),
        AuditTarget::new(kind, Some(request.to_string()), None),
        "专用Nacos配置工作流；内容MD5 upsert不证明外部消费者已加载或执行政策",
    );
    audit.request_id = Some(request.to_string());
    audit.after = Some(after);
    audit
}

pub(super) fn terminal(fact: &Fact, receipt: &Operation) -> AuditLog {
    let mut audit = AppState::audit_entry(
        fact.tenant,
        AuditAction::Execute,
        if receipt.status == Status::Verified { AuditOutcome::Success } else { AuditOutcome::Failure },
        fact.actor.clone(),
        AuditTarget::new("mse-config-publication", Some(fact.request_id.to_string()), None),
        "原调用事实与本地审计原子发布；未知远端结果不可重发，消费者加载状态未知",
    );
    audit.id =
        deterministic_id("agf.mse.config-publication.terminal-audit", &format!("{}:{}", fact.tenant, fact.request_id));
    audit.request_id = Some(fact.request_id.to_string());
    audit.after = Some(serde_json::json!({
        "requestId": fact.request_id, "previewId": receipt.preview_id,
        "targetScopeId": fact.scope.target.target_scope_id,
        "configurationId": fact.scope.target.configuration_id,
        "configurationVersion": fact.scope.target.configuration_version,
        "mocked": fact.scope.target.mocked, "transportMode": fact.scope.target.transport_mode,
        "status": receipt.status, "cloudWrite": receipt.cloud_write,
        "readback": receipt.readback, "contentHash": receipt.desired_hash,
        "contentBytes": receipt.desired_bytes, "consumerApplied": Value::Null
    }));
    audit
}
