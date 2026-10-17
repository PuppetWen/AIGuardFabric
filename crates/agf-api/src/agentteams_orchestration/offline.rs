use super::*;
use crate::{
    integration_store::Stored,
    policy_store::{AuthorizedSubmission, OfflinePublicationProof, authorize_publication},
};
use agf_storage::configuration::{ConfigurationGuard, OfflineGuardedMutation};
use std::cell::RefCell;

pub(super) async fn publish(
    state: &AppState,
    submission: &AuthorizedSubmission<'_>,
    team: &str,
    input: &model::Input,
) -> DomainResult<model::Intent> {
    let principal = submission.principal;
    let actor = principal.subject_id.ok_or_else(denied)?;
    let proof = OfflinePublicationProof::prepare(state, submission).await?;
    let cloud_id = crate::integration_store::id(principal.tenant, crate::cloud_inventory::NAME);
    let guards = [
        ConfigurationGuard { kind: crate::cloud_store::KIND, id: cloud_id },
        ConfigurationGuard { kind: "cloud-inventory", id: cloud_id },
    ];
    let replay = RefCell::new(None);
    let result = state.configurations.mutate_offline_guarded_audited(
        principal.tenant,
        OfflineGuardedMutation {
            kind: KIND,
            id: record_id(principal.tenant),
            guards: &guards,
            security: Some(OfflinePublicationProof::security(submission)?),
        },
        |locked, slot: &mut model::Slot| {
            let mut rows = codec::open(state, principal.tenant, slot.0.as_ref())?;
            if let Some(fact) = reducer::replay(&rows, actor, team, input)? {
                // Abort the candidate before any audit/counter mutation. No sentinel is exposed to the caller.
                *replay.borrow_mut() = Some(fact);
                return Err(DomainError::Conflict("immutable_intent_already_completed".into()));
            }
            let value = |kind: &str| -> DomainResult<Stored> {
                serde_json::from_value(
                    locked.guards.get(&(kind.into(), cloud_id)).and_then(Clone::clone).ok_or_else(denied)?,
                )
                .map_err(Into::into)
            };
            let current = source::capture(
                state,
                principal.tenant,
                team,
                &value(crate::cloud_store::KIND)?,
                &value("cloud-inventory")?,
            )?;
            for id in &current.assets {
                source::live_asset(principal.tenant, *id, state.store.asset_get(principal.tenant, *id)?.as_ref())?;
            }
            let fact = reducer::commit(&mut rows, &current, actor, input)?;
            slot.0 = Some(codec::seal(state, principal.tenant, &rows)?);
            Ok((fact.clone(), write::audit(principal, &fact)))
        },
        |audit, locked| {
            proof.check(state, submission, locked)?;
            // This callback never calls ConfigStore; the guarded source/inventory values are stable.
            let cfg: Stored = serde_json::from_value(
                locked
                    .guards
                    .get(&(crate::cloud_store::KIND.into(), cloud_id))
                    .and_then(Clone::clone)
                    .ok_or_else(denied)?,
            )?;
            let inventory: Stored = serde_json::from_value(
                locked.guards.get(&("cloud-inventory".into(), cloud_id)).and_then(Clone::clone).ok_or_else(denied)?,
            )?;
            let current = source::capture(state, principal.tenant, team, &cfg, &inventory)?;
            for id in &current.assets {
                source::live_asset(principal.tenant, *id, state.store.asset_get(principal.tenant, *id)?.as_ref())?;
            }
            state.store.audit_append(audit)
        },
    );
    if let Some(fact) = replay.into_inner() {
        authorize_publication(state, submission).await?;
        return Ok(fact);
    }
    result.map(|(_, fact, _)| fact)
}
