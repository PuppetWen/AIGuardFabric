//! The explicit SLA endpoints use the same response target as the automatic worker.
use super::*;
use agf_core::{alert::Alert, enums::AlertState};
use agf_correlate::sla::{EscalationStep, SlaClock};

pub(crate) async fn clock(state: &AppState, tenant: TenantId, alert: &Alert) -> DomainResult<SlaClock> {
    let config = get(state, tenant).await?;
    clock_from_config(&config, tenant, alert)
}

pub(crate) fn sla_policy(config: &Configuration, severity: Severity) -> SlaPolicy {
    let mut sla = SlaPolicy::for_severity(severity);
    if config.version > 0 {
        if let Some(policy) = config.policies.iter().find(|p| p.route.severity == severity) {
            sla.first_response_secs = i64::from(policy.route.response_minutes) * 60;
            sla.containment_secs = sla.containment_secs.max(sla.first_response_secs);
            sla.resolution_secs = sla.resolution_secs.max(sla.containment_secs);
            sla.escalation = if policy.route.enabled {
                policy
                    .route
                    .tiers
                    .iter()
                    .map(|tier| EscalationStep {
                        level: tier.level,
                        overdue_secs: i64::from(tier.overdue_minutes) * 60,
                        target: tier.target,
                    })
                    .collect()
            } else {
                vec![]
            };
        }
    }
    sla
}

pub(crate) fn clock_from_config(config: &Configuration, tenant: TenantId, alert: &Alert) -> DomainResult<SlaClock> {
    let mut sla = sla_policy(config, alert.severity);
    if !matches!(alert.state, AlertState::Open | AlertState::Escalated)
        || config.policies.iter().any(|policy| {
            policy.route.severity == alert.severity && policy.since.is_some_and(|since| alert.first_seen_at < since)
        })
    {
        sla.escalation.clear();
    }
    SlaClock::new(tenant, alert.id, alert.first_seen_at, sla).map_err(|e| DomainError::Internal(e.to_string()))
}
