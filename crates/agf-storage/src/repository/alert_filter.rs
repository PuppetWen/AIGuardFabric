//! Shared alert selection for SQL and offline stores.
use agf_core::{
    alert::Alert,
    enums::{AlertState, RiskDomain, Severity},
};

#[derive(Debug, Clone, Default)]
/// OR within each field, AND between fields; empty selections accept every value.
pub struct AlertFilter {
    /// Exact workflow states.
    pub states: Vec<AlertState>,
    /// Exact severity levels.
    pub severities: Vec<Severity>,
    /// Canonical risk domains.
    pub domains: Vec<RiskDomain>,
    /// Exclude closed and suppressed alerts.
    pub active_only: bool,
}
impl AlertFilter {
    /// Evaluate the same predicates as the SQL repository.
    pub fn matches(&self, alert: &Alert) -> bool {
        (self.states.is_empty() || self.states.contains(&alert.state))
            && (self.severities.is_empty() || self.severities.contains(&alert.severity))
            && (self.domains.is_empty() || alert.domain.is_some_and(|d| self.domains.contains(&d)))
            && (!self.active_only || alert.is_active())
    }
}
