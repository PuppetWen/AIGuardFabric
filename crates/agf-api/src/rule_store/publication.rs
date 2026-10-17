//! Rule revisions and their success audit have one commit boundary.
use super::*;
use agf_core::audit::{AuditAction, AuditLog, AuditOutcome, AuditTarget};
mod authority;
mod offline;
mod sql;
#[cfg(test)]
mod tests;
pub(crate) use authority::{Grant, Submission};

pub(crate) async fn change<F>(
    state: &AppState,
    submission: &Submission,
    key: &str,
    apply: F,
) -> DomainResult<RuleDefinition>
where
    F: FnOnce(Option<RuleDefinition>) -> DomainResult<RuleDefinition> + Send,
{
    tokio::time::timeout_at(submission.deadline, async {
        submission.authorize(state).await?;
        if state.store.database().is_some() {
            Box::pin(sql::change(state, submission, key, apply)).await
        } else {
            offline::change(state, submission, key, apply).await
        }
    })
    .await
    .map_err(|_| expired())?
}

fn audit(submission: &Submission, rule: &RuleDefinition) -> AuditLog {
    AppState::audit_entry(
        submission.principal.tenant,
        AuditAction::Update,
        AuditOutcome::Success,
        AppState::audit_actor(&submission.principal, "rule-publish"),
        AuditTarget::new("rule", Some(rule.key.clone()), Some(rule.name.clone())),
        &format!("发布规则版本 {}，灰度 {}%，启用 {}", rule.version, rule.rollout_percent, rule.enabled),
    )
}

pub(crate) fn expired() -> DomainError {
    DomainError::Conflict("治理提交已超过原时限，请重新加载后确认".into())
}
