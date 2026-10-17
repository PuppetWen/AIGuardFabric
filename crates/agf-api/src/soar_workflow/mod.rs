//! Durable linear SOAR runs. Waiting never holds an HTTP request or a database transaction.
use crate::{middleware::Principal, state::AppState};
use agf_core::{
    case::Playbook,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_correlate::playbook::{RunContext, StepOutcome, StepTrace};
use serde::{Deserialize, Serialize};

mod authority;
mod decisions;
mod execute;
mod prepare;
mod queries;
mod worker;
pub use authority::Actor;
pub use decisions::{Decision, decide};
pub use prepare::{Submission, matches, prepare, validate};
pub use queries::page;
pub use worker::{advance, run_loop, tick};

pub const KIND: &str = "soar-workflow";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Queued,
    Approval,
    Waiting,
    Running,
    Review,
    Completed,
    Aborted,
    Cancelled,
    NotStarted,
}
impl Status {
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted | Self::Cancelled | Self::NotStarted)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct History {
    pub at: Timestamp,
    pub actor: String,
    pub action: String,
    pub note: String,
    pub step: usize,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: Id,
    pub tenant_id: TenantId,
    pub case_id: Id,
    pub playbook: Playbook,
    pub context: RunContext,
    pub requested_by: Actor,
    pub execute_as: Actor,
    pub separate_approver: bool,
    #[serde(default)]
    pub mock_mode: bool,
    pub initial_approval: bool,
    pub status: Status,
    pub version: u64,
    pub next_step: usize,
    pub trace: Vec<StepTrace>,
    pub history: Vec<History>,
    pub reason: Option<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub deadline_at: Option<Timestamp>,
    pub wake_at: Option<Timestamp>,
    pub lease_until: Option<Timestamp>,
    pub lease_token: Option<Id>,
    pub finished_at: Option<Timestamp>,
    pub projected_version: u64,
}

impl Run {
    pub(super) fn record(&mut self, now: Timestamp, actor: &str, action: &str, note: &str) {
        self.version += 1;
        self.updated_at = now;
        self.history.push(History {
            at: now,
            actor: actor.into(),
            action: action.into(),
            note: note.into(),
            step: self.next_step,
            version: self.version,
        });
    }

    pub(super) fn finish(&mut self, status: Status, now: Timestamp, reason: &str) {
        self.status = status;
        self.reason = Some(reason.into());
        self.finished_at = Some(now);
        self.wake_at = None;
        self.lease_token = None;
        self.lease_until = None;
    }

    pub(super) fn complete_step(&mut self, now: Timestamp, note: &str) {
        let step = &self.playbook.steps[self.next_step];
        self.trace.push(StepTrace {
            index: self.next_step,
            name: step.name.clone(),
            kind: agf_correlate::playbook::derive_step_kind(step).as_str().into(),
            outcome: StepOutcome::Succeeded,
            attempts: 1,
            error: None,
            note: note.into(),
            automated: true,
        });
        self.next_step += 1;
        self.wake_at = None;
        self.status = Status::Queued;
        if self.next_step == self.playbook.steps.len() {
            self.finish(Status::Completed, now, "所有步骤已结束，请以逐步结果核对处置");
        }
    }
}

pub async fn get(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Run> {
    state
        .configurations
        .get(tenant, KIND, id)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "soar-run", id: id.to_string() })
}

pub(super) async fn change<F>(state: &AppState, tenant: TenantId, id: Id, apply: F) -> DomainResult<Run>
where
    F: FnOnce(&mut Run) -> DomainResult<()> + Send,
{
    state
        .configurations
        .mutate::<Option<Run>, _>(tenant, KIND, id, |slot| {
            let run = slot.as_mut().ok_or_else(|| DomainError::NotFound { entity: "soar-run", id: id.to_string() })?;
            apply(run)
        })
        .await?
        .ok_or_else(|| DomainError::Internal("SOAR run disappeared".into()))
}

pub fn can_approve(state: &AppState, principal: &Principal) -> bool {
    principal.subject_kind == agf_core::rbac::SubjectKind::User && principal.require(state, "cases", "admin").is_ok()
}
