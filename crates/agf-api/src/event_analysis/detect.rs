//! Use the same published tenant rule pack as manual scans; attach immutable event references.
use crate::state::AppState;
use agf_core::{
    error::DomainResult,
    event::{Event, EventCategory},
    ids::deterministic_id,
    risk::{Evidence, Finding},
};
use agf_scan::{
    engine::{ScanRequest, ScanTarget, ScanTargetKind},
    loader::RulePack,
};

pub(super) async fn scan(state: &AppState, event: &Event, pack: &RulePack) -> DomainResult<Vec<Finding>> {
    let kind = match event.category {
        EventCategory::AiSession => ScanTargetKind::Prompt,
        EventCategory::AiToolCall => ScanTargetKind::ToolArguments,
        EventCategory::AiModel => ScanTargetKind::ModelOutput,
        EventCategory::Configuration => ScanTargetKind::Config,
        _ => ScanTargetKind::LogPayload,
    };
    let label = format!("event:{}:{}", event.tenant_id, event.id);
    // Stable source scope preserves gradual rollout across repeated events from the same source.
    let target = ScanTarget::new(format!("source:{}", event.source_id), kind, event.message.clone());
    let request = ScanRequest::new("automatic-event-analysis").with_target(target);
    let mut findings = state.scan_engine.scan(event.tenant_id, pack, &request).await?.findings;
    for finding in &mut findings {
        finding.id = deterministic_id(
            "agf.event-finding",
            &format!("{label}:{}:{}:{}", finding.domain.as_str(), finding.title, finding.rule_keys.join(",")),
        );
        finding.target = label.clone();
        finding.source_origin = "event-analysis".into();
        finding.first_seen_at = event.time;
        finding.last_seen_at = event.time;
        let mut evidence = Evidence::new("EV-EVENT", "event", "Committed normalized event", event.raw_hash.clone());
        evidence.artifact_ref = Some(label.clone());
        evidence.collected_at = event.ingested_at;
        finding.evidence.push(evidence);
        finding.evidence_refs.push("EV-EVENT".into());
    }
    findings.sort_by_key(|f| f.id);
    findings.dedup_by_key(|f| f.id);
    Ok(findings)
}
