use super::*;
use crate::policy_store::OfflinePublicationProof;
use agf_storage::configuration::{GuardedBatchDecision, OfflineGuardedBatch};
use serde_json::Value;

pub(super) async fn save<F>(
    state: &AppState,
    submission: &Submission,
    id: Id,
    action: &'static str,
    apply: F,
) -> DomainResult<Asset>
where
    F: FnOnce(Option<Asset>) -> DomainResult<(Asset, Option<AssetChange>)> + Send,
{
    let authorization = submission.borrowed();
    let proof = OfflinePublicationProof::prepare(state, &authorization).await?;
    let identity = state.store.governance_identity(&submission.principal)?;
    let mut saved = None;
    // Use the existing fixed security snapshot as a read-only guard, without an asset mirror record.
    // ConfigStore stays locked while Memory commits. Unchanged + Option<Value> leaves no fallible
    // post-commit serialization and never creates or updates a console_configuration row.
    state.configurations.mutate_offline_guarded_batch_audited::<Option<Value>, _, _>(
        submission.principal.tenant,
        OfflineGuardedBatch {
            kind: "asset",
            id,
            guards: &[],
            related: &[],
            security: Some(OfflinePublicationProof::security(&authorization)?),
            max_main_bytes: 1,
            max_related_bytes: 1,
            max_total_write_bytes: 1,
        },
        |locked, _, _| {
            proof.check(state, &authorization, locked)?;
            submission.budget()?;
            saved = Some(state.store.publish_skill_offline(
                submission.principal.tenant,
                id,
                &identity,
                apply,
                |asset| audit(submission, asset, action),
                || submission.budget(),
            )?);
            Ok(GuardedBatchDecision::Unchanged)
        },
        |_, _| Err(DomainError::Internal("Read-only Skill guard cannot publish configuration".into())),
    )?;
    saved.ok_or_else(|| DomainError::Internal("Skill mutation did not run".into()))
}
