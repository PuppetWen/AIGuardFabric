//! Defined pure negative cases; these are not HTTP, PostgreSQL or business replay tests.
use super::{tests_support::Fixture, *};
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde_json::{Value, json};

fn write(plan: ResolutionPlan) -> DomainResult<Box<model::ResolutionChange>> {
    match plan {
        ResolutionPlan::Write(change) => Ok(change),
        ResolutionPlan::Replay(_) => Err(util::corrupt()),
    }
}

#[test]
fn only_original_task_error_rows_are_evidence_and_identity_cannot_be_reassigned() -> DomainResult<()> {
    let f = Fixture::new()?;
    let row = f.record("owned-event")?;
    let evidence = FailureEvidence::derive(f.tenant, &row)?;
    assert_eq!(evidence.event_id, row.id);
    assert!(FailureEvidence::derive(TenantId::new(), &row).is_err());
    for (kind, status) in [("task", "success"), ("invocation", "error"), ("task", "failed")] {
        let mut other = row.clone();
        other.kind = kind.into();
        other.status = status.into();
        assert!(FailureEvidence::derive(f.tenant, &other).is_err());
    }
    let mut other = row;
    other.id = Id::new();
    assert!(matches!(FailureEvidence::derive(f.tenant, &other), Err(DomainError::Crypto(_))));
    let mut stored = evidence;
    stored.source_id = Id::nil();
    assert!(stored.validate().is_err());
    Ok(())
}

#[test]
fn strict_body_has_no_actor_status_note_or_business_replay_override() -> DomainResult<()> {
    let f = Fixture::new()?;
    let input = f.input(0)?;
    let body = serde_json::to_value(&input)?;
    for field in ["tenant", "actor", "status", "note", "retry", "task_id"] {
        let mut bad = body.clone();
        bad[field] = json!("untrusted");
        assert!(serde_json::from_value::<ResolutionInput>(bad).is_err());
    }
    for decision in ["cloud_succeeded", "retry", "failed", "resolved"] {
        let mut bad = body.clone();
        bad["decision"] = json!(decision);
        assert!(serde_json::from_value::<ResolutionInput>(bad).is_err());
    }
    Ok(())
}

#[test]
fn exact_uuid_replay_is_local_even_when_source_is_gone_but_changed_body_conflicts() -> DomainResult<()> {
    let f = Fixture::new()?;
    let input = f.input(0)?;
    let verified = f.verified(&input)?;
    let evidence = f.evidence("owned-replay")?;
    let journal = Journal::new(f.tenant);
    let change = write(f.resolve(&journal, &evidence, None, None, Some(&verified), &input)?)?;
    assert_eq!(change.audit.action, AuditAction::Update);
    assert_eq!(change.request_fact.resolution()?.decision, Decision::Acknowledged);
    let replay =
        f.resolve(&change.journal, &evidence, Some(&change.handling), Some(&change.request_fact), None, &input)?;
    assert!(matches!(replay, ResolutionPlan::Replay(receipt) if receipt == *change.request_fact.resolution()?));
    let mut different = input.clone();
    different.decision = Decision::ResolvedByOperator;
    assert!(matches!(
        f.resolve(&change.journal, &evidence, Some(&change.handling), Some(&change.request_fact), None, &different),
        Err(DomainError::Conflict(_))
    ));
    let mut wrong_purpose = change.request_fact.clone();
    wrong_purpose.purpose = "business-replay".into();
    assert!(matches!(
        f.resolve(&change.journal, &evidence, Some(&change.handling), Some(&wrong_purpose), None, &input),
        Err(DomainError::Conflict(_))
    ));
    assert!(journal.active_event_ids.is_empty());
    Ok(())
}

#[test]
fn source_aead_rejects_move_and_config_change_but_ignores_live_counters() -> DomainResult<()> {
    let mut f = Fixture::new()?;
    let input = f.input(0)?;
    let token = &input.expected_source_fingerprint;
    assert!(source_proof::authenticate(&f.cipher, TenantId::new(), f.source_id()?, token).is_err());
    assert!(source_proof::authenticate(&f.cipher, f.tenant, Id::new(), token).is_err());
    let proof = source_proof::authenticate(&f.cipher, f.tenant, f.source_id()?, token)?;
    f.source.received = 999;
    f.source.failed = 7;
    f.source.cursor = Some("dynamic-watermark".into());
    let source = f.source.source.as_mut().ok_or_else(util::corrupt)?;
    source.total_events = 999;
    source.last_error = Some("operational error".into());
    source.last_event_at = Some(f.now);
    source.connection.cursor_value = Some("cursor".into());
    assert!(source_proof::check_current(&proof, &f.cloud, &f.source).is_ok());
    f.source.source.as_mut().ok_or_else(util::corrupt)?.name = "changed config".into();
    assert!(matches!(source_proof::check_current(&proof, &f.cloud, &f.source), Err(DomainError::Conflict(_))));
    assert!(!format!("{:?}", input.expected_source_fingerprint).contains("private-test-only"));
    Ok(())
}

#[test]
fn disabled_existing_source_allows_explicit_human_annotation_and_no_handler_claim() -> DomainResult<()> {
    let mut f = Fixture::new()?;
    f.source.source.as_mut().ok_or_else(util::corrupt)?.enabled = false;
    f.cloud.enabled = false;
    let input = f.input(0)?;
    let verified = f.verified(&input)?;
    let evidence = f.evidence("disabled-source")?;
    let change = write(f.resolve(&Journal::new(f.tenant), &evidence, None, None, Some(&verified), &input)?)?;
    let receipt = serde_json::to_value(&change.request_fact.receipt)?;
    assert!(receipt.get("mayExecute").is_none());
    assert!(receipt.get("cloudStatus").is_none());
    assert_eq!(change.audit.target_kind, "agentteams-task-handling");
    Ok(())
}

#[test]
fn stale_version_and_different_verified_token_reject_before_any_candidate() -> DomainResult<()> {
    let f = Fixture::new()?;
    let input = f.input(0)?;
    let verified = f.verified(&input)?;
    let journal = Journal::new(f.tenant);
    let evidence = f.evidence("owned-cas")?;
    let change = write(f.resolve(&journal, &evidence, None, None, Some(&verified), &input)?)?;
    let stale = f.input(0)?;
    let stale_verified = f.verified(&stale)?;
    assert!(matches!(
        f.resolve(&change.journal, &evidence, Some(&change.handling), None, Some(&stale_verified), &stale),
        Err(DomainError::Conflict(_))
    ));
    let new_input = f.input(1)?;
    assert!(matches!(
        f.resolve(&change.journal, &evidence, Some(&change.handling), None, Some(&verified), &new_input),
        Err(DomainError::Conflict(_))
    ));
    assert_eq!(change.handling.current.version, 1);
    Ok(())
}

#[test]
fn tampered_stored_history_and_excess_archive_guards_are_rejected() -> DomainResult<()> {
    let f = Fixture::new()?;
    let input = f.input(0)?;
    let verified = f.verified(&input)?;
    let evidence = f.evidence("owned-bounds")?;
    let change = write(f.resolve(&Journal::new(f.tenant), &evidence, None, None, Some(&verified), &input)?)?;
    let mut bad = change.handling;
    bad.history[0].request_id = Id::new();
    assert!(bad.validate(&evidence).is_err());
    let too_many = json!({"request_id":Id::new(),"expected_generation":0,"expected_cloud_configuration_version":1,
        "event_ids":[Id::new()],"sources":(0..32).map(|_| json!({"source_id":Id::new(),
            "fingerprint":serde_json::to_value(&input.expected_source_fingerprint).ok()})).collect::<Vec<Value>>()});
    let input: ArchiveInput = serde_json::from_value(too_many)?;
    assert!(input.validate().is_err());
    Ok(())
}

#[test]
fn maximum_valid_safe_evidence_and_json_escaping_fit_the_first_annotation() -> DomainResult<()> {
    let f = Fixture::new()?;
    let mut row = f.record("maximum-safe-preview")?;
    row.message_preview = "\u{0001}".repeat(8192);
    row.from_team = Some("\u{0002}".repeat(8192));
    row.from_worker = Some("w".repeat(512));
    let evidence = FailureEvidence::derive(f.tenant, &row)?;
    let input = f.input(0)?;
    let verified = f.verified(&input)?;
    let change = write(f.resolve(&Journal::new(f.tenant), &evidence, None, None, Some(&verified), &input)?)?;
    change.handling.validate(&evidence)?;
    let encoded = serde_json::to_vec(&change.handling)?;
    assert!(encoded.len() > 16 * 1024);
    assert!(encoded.len() <= 128 * 1024);
    assert_eq!(change.handling.current.version, 1);
    assert_eq!(change.handling.evidence.message_preview, row.message_preview);
    assert_eq!(change.handling.evidence.from_team, row.from_team);
    assert_eq!(change.handling.evidence.from_worker, row.from_worker);
    row.message_preview.push('x');
    assert!(FailureEvidence::derive(f.tenant, &row).is_err());
    Ok(())
}
