use super::*;
use crate::policy_store::OfflinePublicationProof;
use agf_storage::configuration::OfflineGuardedMutation;

pub(super) async fn change<F>(
    state: &AppState,
    submission: &Submission,
    key: &str,
    apply: F,
) -> DomainResult<RuleDefinition>
where
    F: FnOnce(Option<RuleDefinition>) -> DomainResult<RuleDefinition> + Send,
{
    let authorization = submission.borrowed();
    let proof = OfflinePublicationProof::prepare(state, &authorization).await?;
    let identity = state.store.governance_identity(&submission.principal)?;
    let tenant = submission.principal.tenant;
    let builtin = state.rules.rules.iter().find(|rule| rule.key == key).cloned();
    let (_, rule, _) = state.configurations.mutate_offline_guarded_audited(
        tenant,
        OfflineGuardedMutation {
            kind: KIND,
            id: record(tenant),
            guards: &[],
            security: Some(OfflinePublicationProof::security(&authorization)?),
        },
        |_, registry: &mut Registry| {
            let rule = revise(registry, key, builtin, submission.principal.display(), apply)?;
            let log = audit(submission, &rule);
            Ok((rule, log))
        },
        |log, locked| {
            proof.check(state, &authorization, locked)?;
            submission.budget()?;
            state.store.governance_audit_append(log, &identity, || submission.budget())
        },
    )?;
    Ok(rule)
}
