use super::{
    authority::Submission,
    model::{Delivery, Fact, ResultData},
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
        AppState::audit_actor(&submission.principal, "privatelink-provisioning"),
        AuditTarget::new(target, Some(id.to_string()), None),
        "PrivateLink local intent committed; network connectivity and RAM ownership are unverified",
    );
    row.request_id = Some(id.to_string());
    row.after = Some(summary);
    row
}
pub(super) fn terminal(submission: &Submission, row: &Fact) -> AuditLog {
    let mut audit = change(
        submission,
        row.id,
        if row.purpose == super::model::Purpose::Observe { AuditAction::Read } else { AuditAction::Execute },
        super::FACT,
        json!({"purpose":row.purpose,"mocked":row.source.as_ref().is_some_and(|s|s.mode=="mock"),"result":row.result.as_ref().map(super::views::safe_result),"connectivityVerified":false}),
    );
    audit.id =
        deterministic_id("agf.privatelink.provisioning.terminal.audit.v1", &format!("{}:{}", row.tenant, row.id));
    audit.outcome = if matches!(
        row.result,
        Some(
            ResultData::Write { outcome: super::model::Write { delivery: Delivery::Acknowledged, .. } }
                | ResultData::Observed { .. }
        )
    ) {
        AuditOutcome::Success
    } else {
        AuditOutcome::Failure
    };
    audit
}
