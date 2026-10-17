use super::{
    eligibility::{self, Eligibility, Reason},
    input::Assignment,
    proof, tests_proof_support as support, util,
};
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde_json::{Value, json};

#[test]
fn adoption_is_self_contained_bounded_and_remains_qualified_after_three_hundred_seconds() -> DomainResult<()> {
    let (target, _, row) = support::setup()?;
    let proofs = proof::restore_with_cipher(&support::cipher()?, &row, target.tenant)?;
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].assignment.kind, "report");
    assert_eq!(proofs[0].assignment.job_id, "9007199254741002");
    assert!(row.verified_at.is_some_and(|at| at.offset_secs(300) < Timestamp::now()));
    assert!(eligibility::all_eligible(&row));
    assert!(proofs[0].http_job && proofs[0].enabled);
    assert_eq!(proofs[0].adoption_version, 3);
    assert!(util::bound(&row, 1024 * 1024)? < 16 * 1024);
    // No observation body, latest pointer or provider call is needed for restoration.
    Ok(())
}
#[test]
fn proof_restoration_rejects_tenant_revision_job_source_and_aad_tampering() -> DomainResult<()> {
    let (target, _, original) = support::setup()?;
    let mut revisions = Vec::new();
    let mut adoption = original.clone();
    adoption.adoption_version = 2;
    revisions.push(adoption);
    let mut job = original.clone();
    job.items[0].job_id = "7".into();
    revisions.push(job);
    let mut source = original.clone();
    source.target.as_mut().ok_or_else(util::corrupt)?.fingerprint = "1".repeat(64);
    revisions.push(source);
    let mut moved = original.clone();
    moved.adopted_proofs[0].secret.aad = Some("foreign-aad".into());
    revisions.push(moved);
    let mut hash = original.clone();
    hash.adopted_proofs[0].hash = "2".repeat(64);
    revisions.push(hash);
    let mut ciphertext = original.clone();
    ciphertext.adopted_proofs[0].secret.ciphertext_b64 = "not-an-authenticated-ciphertext".into();
    revisions.push(ciphertext);
    for candidate in revisions {
        assert!(proof::restore_with_cipher(&support::cipher()?, &candidate, target.tenant).is_err());
    }
    let foreign = TenantId::from_id(Id::new());
    assert!(proof::restore_with_cipher(&support::cipher()?, &original, foreign).is_err());
    Ok(())
}
#[test]
fn current_qualification_seal_rejects_clear_enabled_cas_and_status_edits() -> DomainResult<()> {
    let (target, _, original) = support::setup()?;
    let mut disabled = original.clone();
    disabled.enabled = false;
    let mut changed_version = original.clone();
    changed_version.version += 1;
    let mut changed_status = original.clone();
    changed_status.eligibility[0].status = Eligibility::Revoked;
    changed_status.eligibility[0].reason = Some(Reason::JobDisabled);
    for candidate in [disabled, changed_version, changed_status] {
        assert!(proof::restore_with_cipher(&support::cipher()?, &candidate, target.tenant).is_err());
    }
    Ok(())
}
#[test]
fn complete_unrelated_and_schedule_only_edits_refresh_evidence_without_changing_adoption_or_cas() -> DomainResult<()> {
    let (target, data, mut row) = support::setup()?;
    let original_proofs = serde_json::to_value(&row.adopted_proofs)?;
    let mut value = data.value().clone();
    value["jobs"][0]["name"] = json!("unrelated renamed job");
    value["jobs"][1]["schedule"]["expression"] = json!("0 0/20 * * * ?");
    let current = support::parse(&target, value)?;
    assert_ne!(current.fingerprint(), data.fingerprint());
    let request = Id::new();
    assert!(eligibility::refresh(&mut row, &current, &target, request, Timestamp::now())?.is_empty());
    assert_eq!(row.version, 3);
    assert_eq!(row.adoption_version, 3);
    assert_eq!(serde_json::to_value(&row.adopted_proofs)?, original_proofs);
    assert_eq!(row.eligibility[0].evidence.observation_id, request);
    support::reseal(&mut row)?;
    assert!(proof::restore_with_cipher(&support::cipher()?, &row, target.tenant).is_ok());
    Ok(())
}
#[test]
fn complete_negative_evidence_revokes_exact_intent_and_increments_only_current_revision() -> DomainResult<()> {
    let (target, data, original) = support::setup()?;
    for reason in [Reason::JobMissing, Reason::JobDisabled, Reason::JobNotHttp, Reason::AppChanged] {
        let mut value = data.value().clone();
        match reason {
            Reason::JobMissing => {
                value["jobs"].as_array_mut().ok_or_else(util::corrupt)?.remove(1);
            }
            Reason::JobDisabled => {
                value["jobs"][1]["status"] = json!(0);
                value["jobs"][1]["enabled"] = json!(false);
            }
            Reason::JobNotHttp => {
                value["jobs"][1]["kind"] = json!("script_shell");
                value["jobs"][1]["httpJob"] = json!(false);
            }
            Reason::AppChanged => {
                value["app"]["id"] = json!("5");
                for job in value["jobs"].as_array_mut().ok_or_else(util::corrupt)? {
                    if !job["appId"].is_null() {
                        job["appId"] = json!("5");
                    }
                }
            }
            Reason::JobTypeUnknown | Reason::JobStatusUnknown => return Err(util::corrupt()),
        }
        let current = support::parse(&target, value)?;
        let mut row = original.clone();
        assert_eq!(eligibility::refresh(&mut row, &current, &target, Id::new(), Timestamp::now())?, vec!["report"]);
        assert_eq!(row.eligibility[0].status, Eligibility::Revoked);
        assert_eq!(row.eligibility[0].reason, Some(reason));
        assert_eq!(row.items, original.items);
        assert_eq!((row.version, row.adoption_version), (4, 3));
        assert_eq!(serde_json::to_value(&row.adopted_proofs)?, serde_json::to_value(&original.adopted_proofs)?);
        support::reseal(&mut row)?;
        proof::restore_with_cipher(&support::cipher()?, &row, target.tenant)?;
    }
    Ok(())
}
#[test]
fn unknown_status_or_unknown_type_is_unverified_and_cannot_be_automatically_reactivated() -> DomainResult<()> {
    let (target, data, original) = support::setup()?;
    for reason in [Reason::JobTypeUnknown, Reason::JobStatusUnknown] {
        let mut value = data.value().clone();
        if reason == Reason::JobTypeUnknown {
            value["jobs"][1]["kind"] = json!("future_unknown_type");
            value["jobs"][1]["httpJob"] = json!(false);
        } else {
            value["jobs"][1]["status"] = Value::Null;
            value["jobs"][1]["enabled"] = Value::Null;
        }
        let current = support::parse(&target, value)?;
        let mut row = original.clone();
        let request = Id::new();
        eligibility::refresh(&mut row, &current, &target, request, Timestamp::now())?;
        assert_eq!(row.eligibility[0].status, Eligibility::Unverified);
        assert_eq!(row.eligibility[0].reason, Some(reason));
        assert!(eligibility::refresh(&mut row, &data, &target, Id::new(), Timestamp::now())?.is_empty());
        assert_eq!(row.version, 4);
        assert_eq!(row.eligibility[0].decision_observation_id, request);
        assert!(!eligibility::all_eligible(&row));
        support::reseal(&mut row)?;
        proof::restore_with_cipher(&support::cipher()?, &row, target.tenant)?;
    }
    Ok(())
}
#[test]
fn revoked_jobs_stay_revoked_after_reappearance_and_archive_does_not_delete_adoption_proofs() -> DomainResult<()> {
    let (target, data, mut row) = support::setup()?;
    let mut value = data.value().clone();
    value["jobs"].as_array_mut().ok_or_else(util::corrupt)?.remove(1);
    let missing = support::parse(&target, value)?;
    eligibility::refresh(&mut row, &missing, &target, Id::new(), Timestamp::now())?;
    let decision = row.eligibility[0].decision_observation_id;
    assert!(eligibility::refresh(&mut row, &data, &target, Id::new(), Timestamp::now())?.is_empty());
    assert_eq!(row.eligibility[0].status, Eligibility::Revoked);
    assert_eq!(row.eligibility[0].decision_observation_id, decision);
    assert!(row.eligibility[0].evidence.job_present);
    support::reseal(&mut row)?;
    // Restoration never consults a BodyRecord, so an archive marker cannot erase or revive qualification.
    assert_eq!(proof::restore_with_cipher(&support::cipher()?, &row, target.tenant)?.len(), 1);
    assert!(!eligibility::all_eligible(&row));
    Ok(())
}
#[test]
fn local_disable_changes_current_seal_without_replacing_original_adoption() -> DomainResult<()> {
    let (target, _, mut row) = support::setup()?;
    let original = serde_json::to_value(&row.adopted_proofs)?;
    row.enabled = false;
    row.version += 1;
    support::reseal(&mut row)?;
    assert_eq!(row.adoption_version, 3);
    assert_eq!(serde_json::to_value(&row.adopted_proofs)?, original);
    assert!(eligibility::all_eligible(&row));
    proof::restore_with_cipher(&support::cipher()?, &row, target.tenant)?;
    Ok(())
}
#[test]
fn another_source_or_incomplete_data_does_not_supply_negative_qualification_evidence() -> DomainResult<()> {
    let (target, data, mut row) = support::setup()?;
    let original = serde_json::to_value(&row)?;
    let mut changed = target.clone();
    changed.configuration_version += 1;
    assert!(eligibility::refresh(&mut row, &data, &changed, Id::new(), Timestamp::now())?.is_empty());
    assert_eq!(serde_json::to_value(&row)?, original);
    let mut partial = data.value().clone();
    partial["pagination"]["listingComplete"] = json!(false);
    assert!(super::safe::SafeSnapshot::parse(&target, partial).is_err());
    assert_eq!(serde_json::to_value(&row)?, original);
    Ok(())
}
#[test]
fn legacy_records_without_authenticated_proofs_are_readable_but_never_eligible() -> DomainResult<()> {
    let (target, data, mut row) = support::setup()?;
    row.adoption_version = 0;
    row.adopted_proofs.clear();
    row.eligibility.clear();
    row.qualification_seal = None;
    super::binding::validate(&row, target.tenant)?;
    assert!(proof::restore_with_cipher(&support::cipher()?, &row, target.tenant)?.is_empty());
    assert!(eligibility::refresh(&mut row, &data, &target, Id::new(), Timestamp::now())?.is_empty());
    assert!(!eligibility::all_eligible(&row));
    Ok(())
}
#[test]
fn six_unique_adoptions_and_current_seal_fit_actual_encoded_related_record_budget() -> DomainResult<()> {
    let target = support::target()?;
    let mut value = support::fixture(&target)?.value().clone();
    let mut items = Vec::new();
    for (job, kind) in value["jobs"].as_array_mut().ok_or_else(util::corrupt)?.iter_mut().zip(super::KINDS) {
        job["kind"] = json!("http");
        job["httpJob"] = json!(true);
        job["status"] = json!(1);
        job["enabled"] = json!(true);
        items.push(Assignment { kind: kind.into(), job_id: job["id"].as_str().ok_or_else(util::corrupt)?.into() });
    }
    items.sort_by(|a, b| a.kind.cmp(&b.kind));
    let data = support::parse(&target, value)?;
    let row = support::adopt(&target, &data, items)?;
    assert_eq!(proof::restore_with_cipher(&support::cipher()?, &row, target.tenant)?.len(), 6);
    for proof in &row.adopted_proofs {
        util::bound(proof, 16 * 1024)?;
    }
    util::bound(row.qualification_seal.as_ref().ok_or_else(util::corrupt)?, 16 * 1024)?;
    util::bound(&row, 1024 * 1024)?;
    let mut duplicate = row.clone();
    duplicate.adopted_proofs[1] = duplicate.adopted_proofs[0].clone();
    assert!(proof::restore_with_cipher(&support::cipher()?, &duplicate, target.tenant).is_err());
    Ok(())
}
#[test]
fn public_projection_uses_authenticated_local_qualification_and_does_not_expose_ciphertext() -> DomainResult<()> {
    let (target, _, row) = support::setup()?;
    let proofs = proof::restore_with_cipher(&support::cipher()?, &row, target.tenant)?;
    let dto = super::views::binding_projection(&row, &proofs, true);
    assert_eq!(dto["current"], true);
    assert_eq!(dto["evidenceFresh"], false);
    assert_eq!(dto["adoptionVersion"], 3);
    assert_eq!(dto["items"][0]["adoptedProof"]["jobId"], "9007199254741002");
    assert_eq!(dto["items"][0]["eligibility"], "eligible");
    assert_eq!(dto["callbackBindingEnforced"], false);
    assert!(!serde_json::to_string(&dto)?.contains("ciphertext_b64"));
    assert_eq!(super::views::binding_projection(&row, &proofs, false)["status"], "stale");
    assert!(eligibility::qualified(&row, "report", "9007199254741002"));
    assert!(!eligibility::qualified(&row, "archive", "9007199254741002"));
    Ok(())
}
