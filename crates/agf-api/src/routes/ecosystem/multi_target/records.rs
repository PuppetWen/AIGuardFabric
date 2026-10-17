use super::types::{ExecuteInput, Status, StepEvidence, Target, hash};
use crate::{AppState, Principal, soar_workflow::Actor};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Envelope {
    pub id: Id,
    pub tenant: TenantId,
    pub body: SecretMaterial,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Fact {
    pub purpose: String,
    pub tenant: TenantId,
    pub request_id: Id,
    pub owner: Actor,
    pub submitted_at: Timestamp,
    pub deadline_at: Timestamp,
    pub input: ExecuteInput,
    pub input_sha256: String,
    pub targets: Vec<Target>,
    pub evidence: Vec<StepEvidence>,
    pub status: Status,
    pub known_terminal: Option<Status>,
    pub source_current: Option<bool>,
    pub finished_at: Option<Timestamp>,
    pub finding_ids: Vec<Id>,
    pub audit_id: Option<Id>,
    #[serde(default = "initial_generation")]
    pub generation: u64,
    #[serde(default)]
    pub archived_at: Option<Timestamp>,
    #[serde(default)]
    pub archive_reviewed_generation: Option<u64>,
    #[serde(default)]
    pub archived_evidence_sha256: Option<String>,
    #[serde(default)]
    pub archive_audit_id: Option<Id>,
}
fn initial_generation() -> u64 {
    1
}
impl Fact {
    pub(super) fn new(
        principal: &Principal,
        input: ExecuteInput,
        targets: Vec<Target>,
        submitted_at: Timestamp,
    ) -> DomainResult<Self> {
        Ok(Self {
            purpose: super::VERSION.into(),
            tenant: principal.tenant,
            request_id: input.request_id,
            owner: Actor::from_principal(principal)?,
            submitted_at,
            deadline_at: submitted_at.offset_secs(110),
            input_sha256: hash(&input)?,
            input,
            targets,
            evidence: Vec::new(),
            status: Status::Running,
            known_terminal: None,
            source_current: None,
            finished_at: None,
            finding_ids: Vec::new(),
            audit_id: None,
            generation: 1,
            archived_at: None,
            archive_reviewed_generation: None,
            archived_evidence_sha256: None,
            archive_audit_id: None,
        })
    }
    pub(super) fn owns(&self, principal: &Principal) -> DomainResult<()> {
        let actor = Actor::from_principal(principal)?;
        if self.tenant != principal.tenant
            || (self.owner.id, self.owner.kind, self.owner.identity_tenant)
                != (actor.id, actor.kind, actor.identity_tenant)
        {
            return Err(DomainError::NotFound { entity: "redteam multi-target run", id: self.request_id.to_string() });
        }
        Ok(())
    }
    pub(super) fn view(&self) -> Value {
        let uncertain = self.status == Status::Running && self.deadline_at <= Timestamp::now();
        json!({"requestId":self.request_id,"campaignId":self.request_id,"playbookVersion":self.purpose,
            "targets":self.targets,"status":if self.archived_at.is_some() {json!("archived")} else if uncertain {json!("uncertain")} else {json!(self.status)},
            "completionState":if self.known_terminal.is_some() {"pending_audit"} else if self.status==Status::Running {"in_progress"} else {"complete"},
            "submittedAt":self.submitted_at,"deadlineAt":self.deadline_at,"finishedAt":self.finished_at,
            "evidence":self.evidence,"findingIds":self.finding_ids,"sourceCurrent":self.source_current,"auditId":self.audit_id,
            "localFixture":self.targets.iter().any(|target|target.transport_mode=="test-loopback"),
            "defensePassed":if self.archived_at.is_none() && self.status==Status::Completed && self.evidence.len()==3 && self.evidence.iter().all(|e|e.completed && e.protected_canary_observed.is_some()) {Some(self.evidence.iter().all(|e|e.protected_canary_observed==Some(false)))} else {None},
            "generation":self.generation,"archivedAt":self.archived_at,"originalStatus":if self.archived_at.is_some(){Some(self.status)}else{None},
            "archivedEvidenceSha256":self.archived_evidence_sha256,"archiveAuditId":self.archive_audit_id,
            "externalDefenseVerified":false,"canRetryDispatch":false,"rawBodiesStored":false})
    }
    pub(super) fn bump(&mut self) -> DomainResult<()> {
        self.generation = self.generation.checked_add(1).ok_or_else(corrupt)?;
        Ok(())
    }
    pub(super) fn archive(&mut self, reviewed: u64, audit: Id) -> DomainResult<bool> {
        if self.archived_at.is_some() {
            if self.archive_reviewed_generation == Some(reviewed) {
                return Ok(false);
            }
            return Err(DomainError::Conflict("Archive generation differs from the reviewed original run".into()));
        }
        if reviewed != self.generation {
            return Err(DomainError::Conflict("Run generation changed; read and review the current receipt".into()));
        }
        if self.status == Status::Running || self.known_terminal.is_some() {
            return Err(DomainError::PreconditionFailed(
                "Cancel or locally recover the original run before archiving".into(),
            ));
        }
        self.archived_evidence_sha256 = Some(hash(&self.evidence)?);
        self.evidence.clear();
        self.archived_at = Some(Timestamp::now());
        self.archive_reviewed_generation = Some(reviewed);
        self.archive_audit_id = Some(audit);
        self.bump()?;
        Ok(true)
    }
    pub(super) fn summary(&self) -> Value {
        let value = self.view();
        json!({"requestId":self.request_id,"status":value["status"],"completionState":value["completionState"],
            "submittedAt":self.submitted_at,"finishedAt":self.finished_at,"generation":self.generation,
            "archived":self.archived_at.is_some(),"originalStatus":value["originalStatus"]})
    }
}
pub(super) fn id(tenant: TenantId, request: Id) -> Id {
    deterministic_id("agf.redteam.multi-target.fact", &format!("{tenant}:{request}"))
}
pub(super) fn seal(state: &AppState, fact: &Fact) -> DomainResult<Envelope> {
    validate(fact)?;
    let id = id(fact.tenant, fact.request_id);
    let raw = serde_json::to_string(fact)?;
    if raw.len() > super::BUDGET {
        return Err(DomainError::PreconditionFailed("Multi-target fact exceeds 48 KiB".into()));
    }
    Ok(Envelope { id, tenant: fact.tenant, body: crate::model_gateway::encrypt(state, fact.tenant, id, raw)? })
}
pub(super) fn restore(state: &AppState, tenant: TenantId, request: Id, envelope: Envelope) -> DomainResult<Fact> {
    let id = id(tenant, request);
    if envelope.id != id
        || envelope.tenant != tenant
        || envelope.body.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &id))
    {
        return Err(corrupt());
    }
    let raw = crate::model_gateway::cipher(state)?.decrypt(&envelope.body)?;
    if raw.expose_secret().len() > super::BUDGET {
        return Err(corrupt());
    }
    let fact: Fact = serde_json::from_str(raw.expose_secret()).map_err(|_| corrupt())?;
    if fact.tenant != tenant || fact.request_id != request {
        return Err(corrupt());
    }
    validate(&fact)?;
    Ok(fact)
}
fn validate(fact: &Fact) -> DomainResult<()> {
    if fact.purpose != super::VERSION
        || fact.generation == 0
        || fact.request_id.is_nil()
        || fact.input.request_id != fact.request_id
        || hash(&fact.input)? != fact.input_sha256
        || fact.targets.len() != 3
        || fact.evidence.len() > 3
        || fact.deadline_at != fact.submitted_at.offset_secs(110)
        || fact.finding_ids.len() > 3
        || (fact.status == Status::Running && (fact.finished_at.is_some() || fact.audit_id.is_some()))
        || (fact.status != Status::Running
            && (fact.finished_at.is_none() || fact.audit_id.is_none() || fact.known_terminal.is_some()))
        || fact.known_terminal.is_some_and(|status| !matches!(status, Status::Completed | Status::Failed))
        || fact.evidence.iter().any(|step| {
            step.response_bytes.is_some_and(|size| size > 64 * 1024)
                || [&step.request_sha256, &step.response_sha256, &step.relay_sha256, &step.transport_proof_sha256]
                    .into_iter()
                    .flatten()
                    .any(|hash| !digest(hash))
                || !matches!(step.dispatch.as_str(), "known_response" | "not_confirmed")
                || step.reason.as_ref().is_some_and(|reason| reason.len() > 64)
                || step.completed
                    && (step.response_sha256.is_none()
                        || step.request_sha256.is_none()
                        || step.protected_canary_observed.is_none())
        })
        || fact.targets.iter().any(|target| {
            target.asset_id.is_nil()
                || !digest(&target.profile_sha256)
                || !digest(&target.registry_sha256)
                || target.managed_profile_sha256.as_ref().is_some_and(|value| !digest(value))
                || target.managed_profile_version.is_some() != target.managed_profile_sha256.is_some()
        })
        || fact
            .evidence
            .iter()
            .enumerate()
            .any(|(i, e)| usize::from(e.step) != i || e.profile_id != fact.targets[i].profile_id)
        || fact.targets.iter().zip(&fact.input.targets).any(|(target, input)| {
            let expected_version = input.expected_version;
            target.profile_id != input.profile_id || target.kind != input.kind || target.version != expected_version
        })
    {
        return Err(corrupt());
    }
    if fact.archived_at.is_some() {
        if fact.status == Status::Running
            || !fact.evidence.is_empty()
            || fact.archive_audit_id.is_none()
            || fact.archive_reviewed_generation.and_then(|version| version.checked_add(1)) != Some(fact.generation)
            || !fact.archived_evidence_sha256.as_deref().is_some_and(digest)
        {
            return Err(corrupt());
        }
    } else if fact.archive_audit_id.is_some()
        || fact.archive_reviewed_generation.is_some()
        || fact.archived_evidence_sha256.is_some()
    {
        return Err(corrupt());
    }
    super::types::validate(&fact.input.targets)?;
    Ok(())
}
fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn corrupt() -> DomainError {
    DomainError::Crypto("Multi-target fact identity/evidence is invalid".into())
}
