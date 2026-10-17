//! Strict collector contract: resource identities are resolved from the frozen inventory.
use super::binding::Binding;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindInput {
    pub expected_version: u64,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub binding_id: Id,
    pub events: Vec<Input>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub event_id: String,
    pub event_time: Timestamp,
    pub kind: Kind,
    pub from_team: Option<String>,
    pub from_worker: Option<String>,
    pub to_team: Option<String>,
    pub to_worker: Option<String>,
    pub task_id: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    #[serde(default)]
    pub status: Status,
    pub duration_ms: Option<u64>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Call,
    Message,
    Task,
    Heartbeat,
}
impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Message => "message",
            Self::Task => "task",
            Self::Heartbeat => "heartbeat",
        }
    }
}
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Success,
    Error,
    #[default]
    Unknown,
}
impl Status {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Unknown => "unknown",
        }
    }
}

pub fn validate(input: &mut Input, binding: &Binding, now: Timestamp) -> DomainResult<(Option<Id>, Option<Id>)> {
    identifier(&input.event_id, 256)?;
    for value in [&input.task_id, &input.trace_id, &input.span_id, &input.parent_span_id].into_iter().flatten() {
        identifier(value, 128)?;
    }
    // Normalize to milliseconds once: SQL precision and cursor identity then agree with Event.time.
    input.event_time = Timestamp::from_unix_millis(input.event_time.unix_millis()).map_err(|_| invalid())?;
    if input.event_time > now.offset_secs(300)
        || input.event_time < now.offset_secs(-30 * 86_400)
        || input.event_time.unix_millis() < binding.bound_at.unix_millis()
        || input.duration_ms.is_some_and(|n| n > 7 * 86_400_000)
        || input.message.as_ref().is_some_and(|s| s.len() > 16_384 || s.contains('\0'))
    {
        return Err(invalid());
    }
    let from = participant(&mut input.from_team, input.from_worker.as_deref(), binding)?;
    let to = participant(&mut input.to_team, input.to_worker.as_deref(), binding)?;
    match input.kind {
        Kind::Call if from.is_none() || to.is_none() => return Err(invalid()),
        Kind::Message if from.is_none() => return Err(invalid()),
        Kind::Task if from.is_none() && to.is_none() => return Err(invalid()),
        Kind::Heartbeat
            if from.is_some()
                || to.is_some()
                || input.from_team.is_some()
                || input.to_team.is_some()
                || input.message.is_some()
                || input.task_id.is_some() =>
        {
            return Err(invalid());
        }
        _ => {}
    }
    Ok((from, to))
}

fn participant(team: &mut Option<String>, worker: Option<&str>, binding: &Binding) -> DomainResult<Option<Id>> {
    let Some(worker) = worker else {
        if team.is_some() {
            return Err(invalid());
        }
        return Ok(None);
    };
    if worker.len() > 512 || worker.chars().any(char::is_control) {
        return Err(invalid());
    }
    let member = binding.members.get(worker).ok_or_else(invalid)?;
    if let Some(name) = team {
        if !binding.teams.contains(name) || !member.teams.contains(name) {
            return Err(invalid());
        }
    } else if member.teams.len() == 1 {
        *team = member.teams.first().cloned();
    } else if member.teams.len() > 1 {
        return Err(DomainError::Validation("Worker 属于多个团队，请明确填入其盘点成员团队".into()));
    }
    Ok(Some(member.asset_id))
}

fn identifier(value: &str, maximum: usize) -> DomainResult<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
    {
        return Err(invalid());
    }
    let redacted = agf_core::redact::redact_text(
        value,
        agf_core::redact::RedactionMode::CredentialsOnly,
        &mut agf_core::redact::RedactionMap::default(),
    );
    if !redacted.redactions.is_empty() {
        return Err(invalid());
    }
    Ok(())
}
pub fn invalid() -> DomainError {
    DomainError::Validation("审计事件格式、时间或盘点成员身份无效；请按接入指南检查整批事件".into())
}
