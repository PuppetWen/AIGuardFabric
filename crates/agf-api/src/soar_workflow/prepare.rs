//! A single submission contract for manual and alert-triggered execution.
use super::*;
use agf_correlate::playbook::{PlaybookEngine, TriggerInput};

pub fn validate(book: &Playbook) -> DomainResult<()> {
    PlaybookEngine::new()
        .validate_with_timeout_limit(book, 604_800)
        .map_err(|error| DomainError::Validation(error.to_string()))?;
    if serde_json::to_vec(book)?.len() > 256 * 1024 {
        return Err(DomainError::Validation("单个剧本最多 256 KiB".into()));
    }
    Ok(())
}

pub fn matches(book: &Playbook, trigger: &TriggerInput, context: &RunContext) -> DomainResult<bool> {
    if !trigger.matches(book) {
        return Ok(false);
    }
    book.trigger.condition.as_ref().map_or(Ok(true), |condition| {
        PlaybookEngine::new()
            .evaluate_condition(condition, context)
            .map_err(|error| DomainError::Validation(error.to_string()))
    })
}

#[derive(Debug)]
pub struct Submission {
    pub id: Id,
    pub case_id: Id,
    pub actor: Actor,
    pub book: Playbook,
    pub context: RunContext,
    pub separate_approver: bool,
    pub matches: bool,
    pub mock_mode: bool,
}

pub fn prepare(input: Submission) -> DomainResult<Run> {
    validate(&input.book)?;
    let now = Timestamp::now();
    let approval = input.book.needs_human_approval() || input.separate_approver;
    let actor = input.actor.display();
    Ok(Run {
        id: input.id,
        tenant_id: input.context.tenant_id,
        case_id: input.case_id,
        requested_by: input.actor.clone(),
        execute_as: input.actor,
        separate_approver: input.separate_approver,
        mock_mode: input.mock_mode,
        status: if !input.matches {
            Status::NotStarted
        } else if approval {
            Status::Approval
        } else {
            Status::Queued
        },
        initial_approval: approval,
        version: 1,
        next_step: 0,
        trace: Vec::new(),
        history: vec![History {
            at: now,
            actor,
            action: "submitted".into(),
            note: "已保存剧本与目标快照；提交不代表执行完成".into(),
            step: 0,
            version: 1,
        }],
        reason: (!input.matches).then(|| "剧本已禁用或触发条件不匹配".into()),
        created_at: now,
        updated_at: now,
        deadline_at: (!approval).then(|| now.offset_secs(input.book.timeout_secs)),
        wake_at: approval.then(|| now.offset_secs(86400)),
        lease_until: None,
        lease_token: None,
        finished_at: (!input.matches).then_some(now),
        projected_version: 0,
        playbook: input.book,
        context: input.context,
    })
}
