use super::{MockDeclaration, SchedulePatch};
use agf_core::error::{DomainError, DomainResult};

pub(super) fn invalid() -> DomainError {
    DomainError::Validation("Scheduler managed job selection or schedule is invalid".into())
}
pub(super) fn precondition() -> DomainError {
    DomainError::PreconditionFailed("Scheduler current HTTP job/source differs; observe and review a new intent".into())
}
pub(super) fn identifier(value: &str) -> DomainResult<i64> {
    value.parse::<i64>().ok().filter(|id| *id > 0 && id.to_string() == value).ok_or_else(invalid)
}
pub(super) fn text(value: &str, max: usize, empty: bool) -> bool {
    (empty || !value.is_empty()) && value.len() <= max && value.trim() == value && !value.chars().any(char::is_control)
}
pub(super) fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
impl SchedulePatch {
    /// Reject unknown time kinds, oversized text, negative retries and an empty change.
    ///
    /// These conservative management bounds are not claims about every vendor limit.
    /// # Errors
    /// Invalid, empty or internally inconsistent scheduling fields.
    pub fn validate(&self) -> DomainResult<()> {
        if self == &Self::default()
            || self.time_type.is_some_and(|kind| !matches!(kind, -1 | 1 | 3 | 5 | 100))
            || self.time_expression.as_ref().is_some_and(|value| !text(value, 256, true))
            || self.calendar.as_ref().is_some_and(|value| !text(value, 256, true))
            || self.timezone.as_ref().is_some_and(|value| !text(value, 64, true))
            || self.max_attempt.is_some_and(|value| !(0..=1_000).contains(&value))
            || self.attempt_interval.is_some_and(|value| !(0..=86_400).contains(&value))
            || (self.time_type.is_some_and(|kind| matches!(kind, -1 | 100))
                && self.time_expression.as_ref().is_some_and(|value| !value.is_empty()))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl MockDeclaration {
    /// Validate a single-worker explicit Mock creation declaration.
    ///
    /// This method does not seed a provider, create a cloud job or authorize a callback.
    /// # Errors
    /// Name, single-worker total or required scheduling declarations are invalid.
    pub fn validate(&self) -> DomainResult<()> {
        self.schedule.validate()?;
        if !text(&self.name, 200, false)
            || self.total != 1
            || self.schedule.time_type.is_none()
            || self.schedule.timezone.as_ref().is_none_or(|zone| !text(zone, 64, false))
            || self.schedule.max_attempt.is_none()
            || self.schedule.attempt_interval.is_none()
            || (self.schedule.time_type.is_some_and(|kind| matches!(kind, 1 | 3 | 5))
                && self.schedule.time_expression.as_ref().is_none_or(|value| !text(value, 256, false)))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
