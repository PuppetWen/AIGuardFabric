use super::super::{scope, tests_proof_support, util};
use super::{
    evidence, identity,
    input::Artifact,
    model::{Pending, State},
    staging, tests_support as support,
};
use agf_core::{error::DomainResult, ids::Id, time::Timestamp};
use agf_storage::crypto::FieldCipher;
use secrecy::SecretString;
use serde_json::json;

#[test]
fn fact_seal_authenticates_actor_kind_claim_source_revisions_and_lease() -> DomainResult<()> {
    let cipher = tests_proof_support::cipher()?;
    let mut row = support::running()?;
    evidence::seal_fact_with_cipher(&cipher, &mut row)?;
    evidence::verify_fact_with_cipher(&cipher, &row)?;
    let mut mutations = Vec::new();
    let mut changed = row.clone();
    changed.context.owner.key_id = Id::new();
    mutations.push(changed);
    let mut changed = row.clone();
    changed.claim_id = Id::new();
    mutations.push(changed);
    let mut changed = row.clone();
    changed.context.adoption_version = 2;
    mutations.push(changed);
    let mut changed = row.clone();
    changed.context.kind = "report".into();
    changed.input_hash = identity::input_hash(&changed.context.input(changed.request_id, changed.partition_index))?;
    mutations.push(changed);
    let mut changed = row.clone();
    changed.context.target.configured_account_id = Some("unverified-text".into());
    changed.context.target.scope_id = scope::identity(&changed.context.target)?;
    mutations.push(changed);
    let mut changed = row.clone();
    changed.started_at = changed.started_at.map(|at| at.offset_secs(1));
    changed.execution_expires_at = changed.execution_expires_at.map(|at| at.offset_secs(1));
    mutations.push(changed);
    let mut changed = row.clone();
    changed.request_id = Id::new();
    mutations.push(changed);
    for changed in mutations {
        // These remain structurally valid: AEAD is what rejects plausible substituted provenance.
        changed.validate(changed.context.tenant, changed.id)?;
        assert!(evidence::verify_fact_with_cipher(&cipher, &changed).is_err());
    }
    let mut wrong_aad = row.clone();
    wrong_aad.seal.as_mut().ok_or_else(util::corrupt)?.secret.aad = Some("foreign-tenant".into());
    assert!(evidence::verify_fact_with_cipher(&cipher, &wrong_aad).is_err());
    Ok(())
}

#[test]
fn a_full_256_partition_progress_fits_the_real_clear_cipher_and_record_bounds() -> DomainResult<()> {
    let cipher = tests_proof_support::cipher()?;
    let batch = support::batch(256, Timestamp::now().offset_secs(-1))?;
    let tenant = batch.context.tenant;
    let kind = batch.context.kind.clone();
    let clear = json!({"domain":"agf.scheduler.callback.progress.v1","tenant":tenant,"kind":kind,"batch":batch});
    assert!(serde_json::to_vec(&clear)?.len() <= 90 * 1024);
    let progress = evidence::seal_with_cipher(&cipher, tenant, &kind, batch)?;
    assert!(serde_json::to_vec(&progress.seal)?.len() <= 128 * 1024);
    assert!(serde_json::to_vec(&progress)?.len() <= 256 * 1024);
    evidence::verify_with_cipher(&cipher, &progress)?;
    let mut changed = progress.clone();
    changed
        .batch
        .partitions
        .get_mut(&7)
        .ok_or_else(util::corrupt)?
        .terminal
        .as_mut()
        .ok_or_else(util::corrupt)?
        .skipped = true;
    changed.batch.validate(tenant)?;
    assert!(evidence::verify_with_cipher(&cipher, &changed).is_err());
    let mut moved = progress;
    moved.kind = "report".into();
    moved.batch.context.kind = "report".into();
    assert!(evidence::verify_with_cipher(&cipher, &moved).is_err());
    Ok(())
}

#[test]
fn known_results_are_aad_bound_and_remain_valid_after_terminal_fact_resealing() -> DomainResult<()> {
    let cipher = tests_proof_support::cipher()?;
    let mut row = support::running()?;
    evidence::seal_fact_with_cipher(&cipher, &mut row)?;
    let known = staging::Known {
        domain: "agf.scheduler.callback.known-outcome.v1".into(),
        original: staging::original(&row),
        outcome: support::outcome(),
        staged_at: Timestamp::now(),
    };
    staging::validate(&known, &row)?;
    let clear = serde_json::to_string(&known)?;
    let key = identity::pending_key(row.id);
    let pending = Pending {
        tenant: row.context.tenant,
        fact_id: row.id,
        claim_id: row.claim_id,
        hash: util::hash(clear.as_bytes()),
        secret: cipher.encrypt(&SecretString::from(clear), &FieldCipher::make_aad(&row.context.tenant, &key.1))?,
    };
    assert!(staging::decode_with_cipher(&cipher, &row, &pending)?.outcome == known.outcome);
    row.state = State::Succeeded;
    row.finished_at = Some(known.staged_at);
    row.outcome = Some(known.outcome.clone());
    row.outcome_hash = Some(identity::outcome_hash(&known.outcome)?);
    evidence::seal_fact_with_cipher(&cipher, &mut row)?;
    evidence::verify_fact_with_cipher(&cipher, &row)?;
    assert!(staging::decode_with_cipher(&cipher, &row, &pending)?.outcome == known.outcome);
    let mut wrong = pending.clone();
    wrong.secret.aad = Some(FieldCipher::make_aad(&support::other_tenant(), &key.1));
    assert!(staging::decode_with_cipher(&cipher, &row, &wrong).is_err());
    let mut wrong = pending;
    wrong.claim_id = Id::new();
    assert!(staging::decode_with_cipher(&cipher, &row, &wrong).is_err());
    Ok(())
}

#[test]
fn maximum_known_artifacts_are_prebudgeted_and_stage_domain_cannot_be_substituted() -> DomainResult<()> {
    let cipher = tests_proof_support::cipher()?;
    let row = support::running()?;
    let mut outcome = support::outcome();
    outcome.artifacts = vec![Artifact { sha256: "f".repeat(64), bytes: u64::MAX }; 64];
    let mut known = staging::Known {
        domain: "agf.scheduler.callback.known-outcome.v1".into(),
        original: staging::original(&row),
        outcome,
        staged_at: Timestamp::now(),
    };
    staging::validate(&known, &row)?;
    let clear = serde_json::to_string(&known)?;
    assert!(clear.len() <= 32 * 1024);
    let key = identity::pending_key(row.id);
    let pending = Pending {
        tenant: row.context.tenant,
        fact_id: row.id,
        claim_id: row.claim_id,
        hash: util::hash(clear.as_bytes()),
        secret: cipher.encrypt(&SecretString::from(clear), &FieldCipher::make_aad(&row.context.tenant, &key.1))?,
    };
    assert!(serde_json::to_vec(&pending)?.len() <= 64 * 1024);
    staging::decode_with_cipher(&cipher, &row, &pending)?;
    known.domain = "agf.scheduler.callback.progress.v1".into();
    assert!(staging::validate(&known, &row).is_err());
    Ok(())
}
