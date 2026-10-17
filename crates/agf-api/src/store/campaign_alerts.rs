//! One reviewable alert per live campaign, asset and risk domain.
use super::*;
use agf_core::{alert::Alert, enums::RiskDomain};
use std::collections::BTreeMap;

pub(super) struct CampaignAlert {
    pub dedup_key: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub domain: RiskDomain,
    pub asset_id: Id,
    pub finding_ids: Vec<Id>,
}

pub(super) fn prepare(campaign_id: Id, findings: &[Finding]) -> DomainResult<Vec<CampaignAlert>> {
    let mut grouped = BTreeMap::<(Id, String), CampaignAlert>::new();
    for finding in findings {
        let asset_id =
            finding.asset_id.ok_or_else(|| DomainError::Validation("Red-team finding lacks an asset".into()))?;
        let domain = finding.domain.as_str().to_string();
        let alert = grouped.entry((asset_id, domain.clone())).or_insert_with(|| CampaignAlert {
            dedup_key: format!("redteam:{campaign_id}:{asset_id}:{domain}"),
            title: finding.title.clone(),
            description: String::new(),
            severity: finding.severity,
            domain: finding.domain,
            asset_id,
            finding_ids: Vec::new(),
        });
        alert.severity = alert.severity.max(finding.severity);
        alert.finding_ids.push(finding.id);
    }
    for alert in grouped.values_mut() {
        alert.description = format!(
            "真实目标战役 {campaign_id} 在该资产与风险域命中 {} 项。请从关联发现和战役证据核对脱敏摘要后处置。",
            alert.finding_ids.len()
        );
    }
    Ok(grouped.into_values().collect())
}

pub(super) fn insert_memory(mem: &mut Memory, tenant: TenantId, draft: CampaignAlert) {
    let now = Timestamp::now();
    let alert = Alert {
        id: Id::new(),
        tenant_id: tenant,
        title: draft.title,
        description: draft.description,
        severity: draft.severity,
        domain: Some(draft.domain),
        state: AlertState::Open,
        finding_ids: draft.finding_ids,
        dedup_count: 1,
        dedup_key: draft.dedup_key,
        asset_ids: vec![draft.asset_id],
        event_ids: Vec::new(),
        affected_hosts: Vec::new(),
        first_seen_at: now,
        last_seen_at: now,
        assignee: None,
        case_id: None,
        escalation_level: 0,
        sla_due_at: Some(now.offset_secs(Alert::sla_secs(draft.severity))),
        sla_breached: false,
        tags: Vec::new(),
        created_at: now,
        updated_at: now,
    };
    mem.alerts.insert((tenant, alert.id), alert);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_one_campaign_asset_domain_without_losing_finding_ids_or_severity() {
        let tenant = TenantId::new();
        let asset = Id::new();
        let mut low = Finding::new(tenant, RiskDomain::PromptAttack, Severity::Low, "asset", "low", "summary", "fix");
        low.asset_id = Some(asset);
        let mut high =
            Finding::new(tenant, RiskDomain::PromptAttack, Severity::Critical, "asset", "high", "summary", "fix");
        high.asset_id = Some(asset);
        let alerts = prepare(Id::new(), &[low.clone(), high.clone()]).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert_eq!(alerts[0].finding_ids, vec![low.id, high.id]);
        assert!(alerts[0].description.contains("2 项"));
    }
}
