use super::{tests_support::Fixture, *};
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    ids::Id,
};
use std::collections::BTreeMap;

fn resolve_new(f: &Fixture, journal: &Journal, label: &str) -> DomainResult<Box<model::ResolutionChange>> {
    let input = f.input(0)?;
    let source = f.verified(&input)?;
    let evidence = f.evidence(label)?;
    match f.resolve(journal, &evidence, None, None, Some(&source), &input)? {
        ResolutionPlan::Write(change) => Ok(change),
        ResolutionPlan::Replay(_) => Err(util::corrupt()),
    }
}
fn archive_input(f: &Fixture, journal: &Journal, event_ids: Vec<Id>) -> DomainResult<ArchiveInput> {
    Ok(ArchiveInput {
        request_id: Id::new(),
        expected_generation: journal.generation,
        expected_cloud_configuration_version: Some(f.cloud.version),
        event_ids,
        sources: vec![input::SourceExpectation {
            source_id: f.source_id()?,
            fingerprint: Some(f.input(0)?.expected_source_fingerprint),
        }],
    })
}
fn verified(f: &Fixture, input: &ArchiveInput) -> DomainResult<BTreeMap<Id, ArchiveSource>> {
    let token = input.sources[0].fingerprint.as_ref().ok_or_else(util::corrupt)?;
    let proof = source_proof::authenticate(&f.cipher, f.tenant, f.source_id()?, token)?;
    let source = source_proof::check_current(&proof, &f.cloud, &f.source)?;
    Ok(BTreeMap::from([(f.source_id()?, ArchiveSource::current(source))]))
}
fn archive_call(
    f: &Fixture,
    journal: &Journal,
    rows: &BTreeMap<Id, Handling>,
    sources: &BTreeMap<Id, ArchiveSource>,
    previous: Option<&RequestFact>,
    input: &ArchiveInput,
) -> DomainResult<ArchivePlan> {
    archive(
        reducer::ArchiveContext {
            tenant: f.tenant,
            actor: &f.actor,
            now: f.now,
            journal,
            rows,
            sources,
            previous_request: previous,
        },
        input,
    )
}
fn changed(plan: ArchivePlan) -> DomainResult<Box<model::ArchiveChange>> {
    match plan {
        ArchivePlan::Write(change) => Ok(change),
        ArchivePlan::Replay(_) => Err(util::corrupt()),
    }
}

#[test]
fn archive_has_its_own_permanent_uuid_and_exact_replay_is_pure() -> DomainResult<()> {
    let f = Fixture::new()?;
    let resolution = resolve_new(&f, &Journal::new(f.tenant), "archive-uuid")?;
    let event = resolution.handling.evidence.event_id;
    let rows = BTreeMap::from([(event, resolution.handling.clone())]);
    let input = archive_input(&f, &resolution.journal, vec![event])?;
    let archived = changed(archive_call(&f, &resolution.journal, &rows, &verified(&f, &input)?, None, &input)?)?;
    let tombstone = &archived.tombstones[0];
    assert!(tombstone.history.is_empty());
    assert_eq!(tombstone.current, resolution.handling.current);
    assert_eq!(tombstone.request_ids, resolution.handling.request_ids);
    assert_eq!(archived.audit.action, AuditAction::Configure);
    assert_eq!(archived.request_fact.archive()?.changed_count, 1);
    let rows = BTreeMap::from([(event, tombstone.clone())]);
    // Old expected generation is intentionally stale. The exact UUID fact remains replayable.
    assert!(matches!(archive_call(&f, &archived.journal, &rows, &BTreeMap::new(),
        Some(&archived.request_fact), &input)?, ArchivePlan::Replay(receipt)
        if receipt == *archived.request_fact.archive()?));
    let mut new = archive_input(&f, &archived.journal, vec![event])?;
    let zero_change = changed(archive_call(&f, &archived.journal, &rows, &verified(&f, &new)?, None, &new)?)?;
    assert!(zero_change.tombstones.is_empty());
    assert_eq!(zero_change.journal, archived.journal);
    assert_eq!(zero_change.request_fact.archive()?.changed_count, 0);
    assert_eq!(zero_change.audit.action, AuditAction::Create);
    assert_eq!(zero_change.audit.target_kind, "agentteams-task-handling-archive-request");
    assert_eq!(zero_change.audit.request_id, new.request_id);
    new.expected_generation -= 1;
    assert!(matches!(
        archive_call(&f, &archived.journal, &rows, &verified(&f, &new)?, None, &new),
        Err(DomainError::Conflict(_))
    ));
    Ok(())
}

#[test]
fn archive99_frees_capacity_and_keeps_all_original_receipt_facts() -> DomainResult<()> {
    let f = Fixture::new()?;
    let mut journal = Journal::new(f.tenant);
    let mut all = BTreeMap::new();
    let mut facts = Vec::new();
    for n in 0..MAX_ACTIVE {
        let change = resolve_new(&f, &journal, &format!("capacity-{n}"))?;
        journal = change.journal;
        all.insert(change.handling.evidence.event_id, change.handling);
        facts.push(change.request_fact);
    }
    let extra = f.evidence("capacity-extra")?;
    let input = f.input(0)?;
    let source = f.verified(&input)?;
    assert!(matches!(f.resolve(&journal, &extra, None, None, Some(&source), &input), Err(DomainError::Conflict(_))));
    let ids: Vec<_> = all.keys().take(MAX_ARCHIVE).copied().collect();
    let rows: BTreeMap<_, _> = ids.iter().map(|id| (*id, all[id].clone())).collect();
    let input = archive_input(&f, &journal, ids)?;
    let archived = changed(archive_call(&f, &journal, &rows, &verified(&f, &input)?, None, &input)?)?;
    assert_eq!(archived.tombstones.len(), 99);
    assert_eq!(archived.journal.active_event_ids.len(), 29);
    assert_eq!(archived.journal.archived_count, 99);
    assert_eq!(facts.len(), 128);
    for fact in facts {
        assert_eq!(fact.resolution()?.version, 1);
    }
    assert_eq!(archived.request_fact.archive()?.event_ids.len(), 99);
    Ok(())
}

#[test]
fn gone_source_archive_requires_original_identity_and_no_fake_current_version() -> DomainResult<()> {
    let f = Fixture::new()?;
    let resolution = resolve_new(&f, &Journal::new(f.tenant), "source-gone")?;
    let evidence = &resolution.handling.evidence;
    assert!(ArchiveSource::gone(evidence, Some(&f.source)).is_err());
    let sources = BTreeMap::from([(evidence.source_id, ArchiveSource::gone(evidence, None)?)]);
    let rows = BTreeMap::from([(evidence.event_id, resolution.handling.clone())]);
    let input = ArchiveInput {
        request_id: Id::new(),
        expected_generation: resolution.journal.generation,
        expected_cloud_configuration_version: None,
        event_ids: vec![evidence.event_id],
        sources: vec![input::SourceExpectation { source_id: evidence.source_id, fingerprint: None }],
    };
    let archived = changed(archive_call(&f, &resolution.journal, &rows, &sources, None, &input)?)?;
    assert_eq!(archived.tombstones[0].evidence, *evidence);
    let mut fake_current = input;
    fake_current.expected_cloud_configuration_version = Some(1);
    assert!(archive_call(&f, &resolution.journal, &rows, &sources, None, &fake_current).is_err());
    Ok(())
}

#[test]
fn archive_and_resolution_cannot_reuse_uuid_purpose_or_change_original_payload() -> DomainResult<()> {
    let f = Fixture::new()?;
    let resolution = resolve_new(&f, &Journal::new(f.tenant), "purpose")?;
    let event = resolution.handling.evidence.event_id;
    let rows = BTreeMap::from([(event, resolution.handling.clone())]);
    let mut input = archive_input(&f, &resolution.journal, vec![event])?;
    input.request_id = resolution.request_fact.request_id;
    assert!(matches!(
        archive_call(&f, &resolution.journal, &rows, &BTreeMap::new(), Some(&resolution.request_fact), &input),
        Err(DomainError::Conflict(_))
    ));
    input.request_id = Id::new();
    let archived = changed(archive_call(&f, &resolution.journal, &rows, &verified(&f, &input)?, None, &input)?)?;
    let mut different = input.clone();
    different.expected_generation += 1;
    let rows = BTreeMap::from([(event, archived.tombstones[0].clone())]);
    assert!(matches!(
        archive_call(&f, &archived.journal, &rows, &BTreeMap::new(), Some(&archived.request_fact), &different),
        Err(DomainError::Conflict(_))
    ));
    let mut annotation = f.input(1)?;
    annotation.request_id = input.request_id;
    assert!(matches!(
        f.resolve(
            &archived.journal,
            &rows[&event].evidence,
            Some(&rows[&event]),
            Some(&archived.request_fact),
            None,
            &annotation
        ),
        Err(DomainError::Conflict(_))
    ));
    Ok(())
}
