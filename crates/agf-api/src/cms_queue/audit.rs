use super::{
    authority::Submission,
    model::{Attempt, Delivery, Outcome},
};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget},
    ids::{Id, deterministic_id},
};
use serde_json::json;

pub(super) fn change(
    submission: &Submission,
    id: Id,
    action: AuditAction,
    target: &str,
    summary: serde_json::Value,
) -> AuditLog {
    let mut row = AppState::audit_entry(
        submission.principal.tenant,
        action,
        AuditOutcome::Success,
        AppState::audit_actor(&submission.principal, "cms-queue"),
        AuditTarget::new(target, Some(id.to_string()), None),
        "CMS local queue intent committed; no cloud acknowledgement is implied",
    );
    row.request_id = Some(id.to_string());
    row.after = Some(summary);
    row
}
pub(super) fn terminal(submission: &Submission, attempt: &Attempt, outcome: &Outcome) -> AuditLog {
    let mut row = change(
        submission,
        attempt.id,
        AuditAction::Execute,
        super::ATTEMPT,
        json!({"itemId":attempt.item_id,"requestId":attempt.request_id,"delivery":outcome.delivery,"mocked":attempt.source.mode=="mock","providerRequestId":outcome.provider_request_id}),
    );
    row.id = deterministic_id("agf.cms.queue.terminal.audit.v1", &format!("{}:{}", attempt.tenant, attempt.id));
    row.request_id = Some(attempt.request_id.to_string());
    row.outcome = if outcome.delivery == Delivery::Accepted { AuditOutcome::Success } else { AuditOutcome::Failure };
    row.note = "Original CMS delivery outcome published locally; unknown is never automatically resent".into();
    row
}
