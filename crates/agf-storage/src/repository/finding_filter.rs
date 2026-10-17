//! Shared finding filter semantics for SQL and offline stores.
use agf_core::{
    enums::{RiskDomain, Severity},
    risk::{Finding, FindingState},
};

/// Values within one field are alternatives; different fields are combined with AND.
#[derive(Debug, Clone, Default)]
pub struct FindingFilter {
    /// Exact risk domains; empty accepts every domain.
    pub domains: Vec<RiskDomain>,
    /// Exact severities; empty accepts every severity.
    pub severities: Vec<Severity>,
    /// Workflow states; empty accepts every state.
    pub states: Vec<FindingState>,
    /// Optional minimum severity, independent of the exact severity selection.
    pub minimum: Option<Severity>,
}
impl FindingFilter {
    /// Evaluate the same predicates used by the SQL repository.
    pub fn matches(&self, finding: &Finding) -> bool {
        (self.domains.is_empty() || self.domains.contains(&finding.domain))
            && (self.severities.is_empty() || self.severities.contains(&finding.severity))
            && (self.states.is_empty() || self.states.contains(&finding.state))
            && self.minimum.is_none_or(|minimum| finding.severity >= minimum)
    }
}
