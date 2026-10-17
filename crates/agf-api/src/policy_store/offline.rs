//! One ConfigStore mutex holds dependencies, authority prerequisites, candidate and audit publication.
use super::*;
use agf_storage::configuration::OfflineGuardedMutation;

pub(super) async fn execute(
    state: &AppState,
    submission: mutation::Submission<'_>,
    change: change::Change,
) -> DomainResult<Policy> {
    let action = change.action();
    let proof = offline_authority::prepare(state, &submission, action).await?;
    let guards = validation::guards(change.candidate(), submission.tenant);
    let security = submission.principal.map(offline_authority::security).transpose()?;
    let candidate = change.candidate().cloned();
    let original = state.store.policy_list(submission.tenant)?;
    let signer = signer(state)?;
    let (_, saved, _) = state.configurations.mutate_offline_guarded_audited(
        submission.tenant,
        OfflineGuardedMutation { kind: KIND, id: tenant_record_id(submission.tenant), guards: &guards, security },
        |snapshot, rows: &mut registry::Registry| {
            rows.initialize(submission.tenant, original, &signer)?;
            if let Some(policy) = &candidate {
                validation::dependencies(policy, submission.tenant, &snapshot.guards)?;
            }
            change.apply(rows, submission.tenant, &signer, submission.actor())
        },
        |audit, snapshot| {
            offline_authority::tenant_enabled(submission.tenant, snapshot.tenant_directory.as_ref())?;
            if let Some(proof) = &proof {
                proof.check(state, &submission, action, snapshot)?;
            }
            if let Some(policy) = &candidate {
                for id in &policy.scope_agent_ids {
                    validation::agent(submission.tenant, *id, state.store.asset_get(submission.tenant, *id)?.as_ref())?;
                }
            }
            // Trusted synchronous ApiStore audit_append either seals/appends once, or changes nothing.
            // After this succeeds, ConfigStore only inserts the already serialized candidate.
            state.store.audit_append(audit)
        },
    )?;
    Ok(saved)
}
