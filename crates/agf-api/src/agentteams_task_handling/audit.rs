//! Human annotations are local success audits; they never claim a cloud execution outcome.
use super::{authority::Submission, model::AuditSummary};
use crate::state::AppState;
use agf_core::{
    audit::{AuditLog, AuditOutcome, AuditTarget},
    ids::deterministic_id,
};
use serde_json::json;

pub(super) fn entry(submission: &Submission, summary: &AuditSummary) -> AuditLog {
    let tenant = submission.principal.tenant;
    let mut entry = AppState::audit_entry(
        tenant,
        summary.action,
        AuditOutcome::Success,
        AppState::audit_actor(&submission.principal, "agentteams-task-handling"),
        AuditTarget::new(&summary.target_kind, Some(summary.request_id.to_string()), None),
        "",
    );
    entry.id = deterministic_id("agf.agentteams.task-handling.audit.v1", &format!("{tenant}:{}", summary.request_id));
    entry.request_id = Some(summary.request_id.to_string());
    entry.after = Some(json!({"requestId":summary.request_id,"eventId":summary.event_id,
        "fromVersion":summary.from_version,"toVersion":summary.to_version,"decision":summary.decision,
        "changedCount":summary.archived_count,"evidenceCategory":"collector_reported_error",
        "operatorAnnotation":true,"cloudExecutionConfirmed":false,"businessReplay":false}));
    entry
}
