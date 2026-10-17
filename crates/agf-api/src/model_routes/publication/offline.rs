use super::*;
use crate::policy_store::OfflinePublicationProof;
use agf_storage::configuration::{ConfigurationGuard, GuardedBatchDecision, OfflineGuardedBatch};

pub(super) async fn save(
    state: &AppState,
    submission: &Submission,
    policy: &ModelRoutePolicy,
    expected: u64,
    seed: Option<&ModelRoutePolicy>,
) -> DomainResult<()> {
    let authorization = submission.borrowed();
    let proof = OfflinePublicationProof::prepare(state, &authorization).await?;
    let keys = validation::keys(policy)?;
    // Read-only related originals support all 33 permitted endpoints without expanding the guard limit.
    let related = keys.iter().map(|(kind, id)| ConfigurationGuard { kind, id: *id }).collect::<Vec<_>>();
    state.configurations.mutate_offline_guarded_batch_audited(
        policy.tenant_id,
        OfflineGuardedBatch {
            kind: super::super::KIND,
            id: policy.id,
            guards: &[],
            security: Some(OfflinePublicationProof::security(&authorization)?),
            related: &related,
            max_main_bytes: MAX_POLICY_BYTES,
            max_related_bytes: 1024 * 1024,
            max_total_write_bytes: MAX_BATCH_BYTES,
        },
        |_, current: &mut Option<Value>, originals| {
            let stored: Option<ModelRoutePolicy> =
                current.clone().map(serde_json::from_value).transpose().map_err(|_| corrupt())?;
            if let Some(row) = stored.as_ref() {
                validation::identity(row, policy.tenant_id, policy.id)?;
            }
            compare(stored.as_ref(), seed, expected)?;
            validation::references(policy, originals)?;
            let log = audit(submission, policy);
            serialized_budget(policy, &log)?;
            *current = Some(serde_json::to_value(policy)?);
            Ok(GuardedBatchDecision::Write { related: BTreeMap::new(), audit: Box::new(log) })
        },
        |log, locked| {
            proof.check(state, &authorization, locked)?;
            submission.budget()?;
            state.store.audit_append(log)
        },
    )?;
    Ok(())
}
