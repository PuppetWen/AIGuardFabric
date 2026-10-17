//! Return complete candidates; no I/O, audit append, cloud writes, handler claim or retry.
use super::model::{
    ArchiveChange, ArchiveReceipt, AuditSummary, Receipt, ResolutionChange, ResolutionReceipt, Revision,
};
use super::{
    Actor, ArchiveInput, ArchivePlan, FailureEvidence, Handling, Journal, MAX_ACTIVE, MAX_HISTORY, RequestFact,
    ResolutionInput, ResolutionPlan, VerifiedSource, util,
};
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct ResolutionContext<'a> {
    pub(super) tenant: TenantId,
    pub(super) actor: &'a Actor,
    pub(super) now: Timestamp,
    pub(super) journal: &'a Journal,
    pub(super) evidence: &'a FailureEvidence,
    pub(super) current: Option<&'a Handling>,
    pub(super) previous_request: Option<&'a RequestFact>,
    pub(super) source: Option<&'a VerifiedSource>,
}
pub(super) fn resolve(context: ResolutionContext<'_>, input: &ResolutionInput) -> DomainResult<ResolutionPlan> {
    input.validate()?;
    context.actor.validate()?;
    context.journal.validate(context.tenant)?;
    context.evidence.validate()?;
    if context.evidence.tenant != context.tenant || context.now < context.evidence.received_at {
        return Err(util::corrupt());
    }
    let input_hash = util::hash(&json!({"purpose":"operator-resolution","tenant":context.tenant,
        "event_id":context.evidence.event_id,"actor":context.actor,"input":input}))?;
    if let Some(previous) = context.previous_request {
        if previous.purpose != "operator-resolution" {
            return Err(util::stale());
        }
        previous.validate(context.tenant, input.request_id)?;
        if previous.input_hash != input_hash {
            return Err(util::stale());
        }
        if previous.resolution()?.evidence_identity_hash != context.evidence.hash()? {
            return Err(util::corrupt());
        }
        return Ok(ResolutionPlan::Replay(previous.resolution()?.clone()));
    }
    let source = context.source.ok_or_else(|| DomainError::PreconditionFailed("缺少当前来源校验".into()))?;
    if source.tenant() != context.tenant
        || source.source_id() != context.evidence.source_id
        || source.cloud_version() != input.expected_cloud_configuration_version
        || !source.matches(&input.expected_source_fingerprint)?
    {
        return Err(util::stale());
    }
    if let Some(current) = context.current {
        current.validate(context.evidence)?;
        if current.archived_at.is_some() {
            return Err(DomainError::Conflict("该失败证据的人工处理已归档".into()));
        }
        if !context.journal.active_event_ids.contains(&context.evidence.event_id) {
            return Err(util::corrupt());
        }
    } else if context.journal.active_event_ids.contains(&context.evidence.event_id) {
        return Err(util::corrupt());
    }
    let old_version = context.current.map_or(0, |current| current.current.version);
    if old_version != input.expected_version {
        return Err(util::stale());
    }
    if context.current.is_none() && context.journal.active_event_ids.len() == MAX_ACTIVE {
        return Err(DomainError::Conflict("人工处理容量已满，请显式归档已标注记录".into()));
    }
    if context.current.is_some_and(|current| current.request_ids.len() == MAX_HISTORY) {
        return Err(DomainError::Conflict("此失败证据的人工修改已达20次，请显式归档".into()));
    }
    let version = old_version.checked_add(1).ok_or_else(util::corrupt)?;
    let revision = Revision {
        request_id: input.request_id,
        version,
        decision: input.decision,
        subject_id: context.actor.subject_id,
        subject_kind: context.actor.subject_kind.clone(),
        at: context.now,
    };
    let mut history = context.current.map_or_else(Vec::new, |current| current.history.clone());
    let mut request_ids = context.current.map_or_else(Vec::new, |current| current.request_ids.clone());
    history.push(revision.clone());
    request_ids.push(input.request_id);
    let handling =
        Handling { evidence: context.evidence.clone(), current: revision, history, request_ids, archived_at: None };
    handling.validate(context.evidence)?;
    let mut journal = context.journal.clone();
    journal.active_event_ids.insert(context.evidence.event_id);
    journal.generation = journal.generation.checked_add(1).ok_or_else(util::corrupt)?;
    let request_fact = RequestFact {
        tenant: context.tenant,
        request_id: input.request_id,
        purpose: "operator-resolution".into(),
        input_hash,
        receipt: Receipt::Resolution(Box::new(ResolutionReceipt {
            request_id: input.request_id,
            event_id: context.evidence.event_id,
            version,
            decision: input.decision,
            updated_at: context.now,
            evidence_identity_hash: context.evidence.hash()?,
        })),
    };
    request_fact.validate(context.tenant, input.request_id)?;
    let audit = AuditSummary {
        action: AuditAction::Update,
        target_kind: "agentteams-task-handling".into(),
        request_id: input.request_id,
        event_id: Some(context.evidence.event_id),
        from_version: Some(old_version),
        to_version: Some(version),
        decision: Some(input.decision),
        archived_count: None,
    };
    util::bounded(&json!({"journal":journal,"handling":handling,"request":request_fact,"audit":audit}), 1024 * 1024)?;
    Ok(ResolutionPlan::Write(Box::new(ResolutionChange { journal, handling, request_fact, audit })))
}

pub(super) struct ArchiveContext<'a> {
    pub(super) tenant: TenantId,
    pub(super) actor: &'a Actor,
    pub(super) now: Timestamp,
    pub(super) journal: &'a Journal,
    pub(super) rows: &'a BTreeMap<Id, Handling>,
    pub(super) previous_request: Option<&'a RequestFact>,
    pub(super) sources: &'a BTreeMap<Id, super::ArchiveSource>,
}
pub(super) fn archive(context: ArchiveContext<'_>, input: &ArchiveInput) -> DomainResult<ArchivePlan> {
    let ArchiveContext { tenant, actor, now, journal, rows, previous_request, sources } = context;
    input.validate()?;
    actor.validate()?;
    journal.validate(tenant)?;
    if rows.len() != input.event_ids.len() {
        return Err(util::corrupt());
    }
    let mut tombstones = Vec::new();
    let mut required_sources = BTreeSet::new();
    let mut evidence = Vec::new();
    for id in &input.event_ids {
        let row = rows.get(id).ok_or_else(|| DomainError::NotFound { entity: "task-handling", id: id.to_string() })?;
        row.validate(&row.evidence)?;
        if row.evidence.tenant != tenant || row.evidence.event_id != *id {
            return Err(util::corrupt());
        }
        if now < row.current.at {
            return Err(util::corrupt());
        }
        evidence.push(&row.evidence);
        required_sources.insert(row.evidence.source_id);
        if row.archived_at.is_some() {
            if journal.active_event_ids.contains(id) {
                return Err(util::corrupt());
            }
            continue;
        }
        if !journal.active_event_ids.contains(id) {
            return Err(util::corrupt());
        }
        let mut tombstone = row.clone();
        tombstone.history.clear();
        tombstone.archived_at = Some(now);
        tombstone.validate(&row.evidence)?;
        tombstones.push(tombstone);
    }
    evidence.sort_by_key(|row| row.event_id);
    let evidence_hash = util::hash(&evidence)?;
    let input_hash = util::hash(&json!({"purpose":"operator-archive","tenant":tenant,"actor":actor,"input":input}))?;
    if let Some(previous) = previous_request {
        if previous.purpose != "operator-archive" {
            return Err(util::stale());
        }
        previous.validate(tenant, input.request_id)?;
        if previous.input_hash != input_hash {
            return Err(util::stale());
        }
        if previous.archive()?.evidence_identity_hash != evidence_hash {
            return Err(util::corrupt());
        }
        return Ok(ArchivePlan::Replay(previous.archive()?.clone()));
    }
    if journal.generation != input.expected_generation {
        return Err(util::stale());
    }
    let input_sources = input.sources.iter().map(|source| source.source_id).collect::<BTreeSet<_>>();
    if required_sources != input_sources
        || required_sources.len() != sources.len()
        || sources.values().any(super::ArchiveSource::is_current)
            != input.expected_cloud_configuration_version.is_some()
    {
        return Err(util::invalid());
    }
    for source_id in required_sources {
        let source = sources.get(&source_id).ok_or_else(util::stale)?;
        let expected =
            input.sources.iter().find(|expected| expected.source_id == source_id).ok_or_else(util::invalid)?;
        source.verify(tenant, expected, input.expected_cloud_configuration_version)?;
    }
    let mut candidate = journal.clone();
    for tombstone in &tombstones {
        candidate.active_event_ids.remove(&tombstone.evidence.event_id);
    }
    if !tombstones.is_empty() {
        candidate.generation = candidate.generation.checked_add(1).ok_or_else(util::corrupt)?;
    }
    candidate.archived_count = candidate
        .archived_count
        .checked_add(u64::try_from(tombstones.len()).map_err(|_| util::corrupt())?)
        .ok_or_else(util::corrupt)?;
    let request_fact = RequestFact {
        tenant,
        request_id: input.request_id,
        purpose: "operator-archive".into(),
        input_hash,
        receipt: Receipt::Archive(Box::new(ArchiveReceipt {
            request_id: input.request_id,
            generation: candidate.generation,
            archived_count: candidate.archived_count,
            event_ids: input.event_ids.clone(),
            changed_count: tombstones.len(),
            evidence_identity_hash: evidence_hash,
        })),
    };
    request_fact.validate(tenant, input.request_id)?;
    let audit = AuditSummary {
        action: if tombstones.is_empty() { AuditAction::Create } else { AuditAction::Configure },
        target_kind: if tombstones.is_empty() {
            "agentteams-task-handling-archive-request"
        } else {
            "agentteams-task-handling-archive"
        }
        .into(),
        request_id: input.request_id,
        event_id: None,
        from_version: Some(journal.generation),
        to_version: Some(candidate.generation),
        decision: None,
        archived_count: Some(tombstones.len()),
    };
    util::bounded(
        &json!({"journal":candidate,"tombstones":tombstones,"request":request_fact,"audit":audit}),
        4 * 1024 * 1024,
    )?;
    Ok(ArchivePlan::Write(Box::new(ArchiveChange { journal: candidate, tombstones, request_fact, audit })))
}
