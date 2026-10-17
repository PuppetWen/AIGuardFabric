//! 由 `case.rs` 拆分：`case` 等 11 个函数（纯搬移，逻辑不变）。

use crate::enums::{CaseState, Severity};
use crate::ids::{Id, TenantId};
use crate::time::Timestamp;

use super::*;

pub(crate) fn case() -> Case {
    let now = Timestamp::now();
    Case {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        code: Case::make_code(2026, 1),
        title: "疑似数据外传".into(),
        summary: String::new(),
        severity: Severity::High,
        state: CaseState::New,
        alert_ids: vec![],
        finding_ids: vec![],
        asset_ids: vec![],
        owner: None,
        collaborators: vec![],
        security_incident: false,
        resolution: None,
        root_cause: None,
        lessons: None,
        evidence_bundle_ref: None,
        sla_due_at: None,
        sla_breached: false,
        tags: vec![],
        created_at: now,
        closed_at: None,
        updated_at: now,
    }
}

#[test]
pub(crate) fn case_code_formatting() {
    assert_eq!(Case::make_code(2026, 42), "CASE-2026-0042");
    assert_eq!(Case::make_code(2026, 12_345), "CASE-2026-12345");
}

#[test]
pub(crate) fn case_transitions_are_constrained() {
    let mut c = case();
    assert!(c.can_transition_to(CaseState::Investigating));
    assert!(!c.can_transition_to(CaseState::Resolved), "必须先调查");
    c.state = CaseState::Investigating;
    assert!(c.can_transition_to(CaseState::Containing));
    assert!(c.can_transition_to(CaseState::Resolved));
    c.state = CaseState::Resolved;
    assert!(c.can_transition_to(CaseState::Closed));
    assert!(c.can_transition_to(CaseState::Investigating), "允许重新打开调查");
    assert!(!c.can_transition_to(CaseState::New));
    c.state = CaseState::Closed;
    assert!(!c.can_transition_to(CaseState::Investigating));
    assert!(c.is_closed());
}

#[test]
pub(crate) fn containment_action_safety_matrix() {
    assert!(ContainmentAction::IsolateAgent.auto_executable());
    assert!(!ContainmentAction::RevokeCredential.auto_executable());
    assert!(!ContainmentAction::RevokeCredential.reversible());
    assert!(ContainmentAction::BlockDomain.reversible());
}

pub(crate) fn playbook() -> Playbook {
    Playbook {
        key: "isolate-on-exfil".into(),
        name: "数据外传自动隔离".into(),
        description: String::new(),
        trigger: PlaybookTrigger {
            domains: vec![crate::enums::RiskDomain::ModelData],
            min_severity: Some(Severity::High),
            ..PlaybookTrigger::default()
        },
        steps: vec![
            PlaybookStep {
                name: "隔离 Agent".into(),
                action: Some(ContainmentAction::IsolateAgent),
                notify_channel: None,
                params: serde_json::Value::Null,
                continue_on_error: false,
                timeout_secs: None,
            },
            PlaybookStep {
                name: "通知责任人".into(),
                action: Some(ContainmentAction::NotifyOwner),
                notify_channel: Some("dingtalk".into()),
                params: serde_json::Value::Null,
                continue_on_error: true,
                timeout_secs: None,
            },
        ],
        enabled: true,
        require_approval: false,
        timeout_secs: 300,
        version: 1,
    }
}

#[test]
pub(crate) fn valid_playbook_passes() {
    assert!(playbook().validate().is_ok());
    assert!(!playbook().needs_human_approval());
}

#[test]
pub(crate) fn irreversible_step_requires_approval() {
    let mut p = playbook();
    p.steps.push(PlaybookStep {
        name: "吊销凭据".into(),
        action: Some(ContainmentAction::RevokeCredential),
        notify_channel: None,
        params: serde_json::Value::Null,
        continue_on_error: false,
        timeout_secs: None,
    });
    assert!(p.needs_human_approval());
}

#[test]
pub(crate) fn invalid_playbook_rejected() {
    let mut p = playbook();
    p.steps.clear();
    assert!(p.validate().is_err());
    let mut q = playbook();
    q.timeout_secs = 0;
    assert!(q.validate().is_err());
    let mut r = playbook();
    r.steps[0].name = "  ".into();
    assert!(r.validate().is_err());
}

#[test]
pub(crate) fn trigger_matching() {
    let t = PlaybookTrigger {
        domains: vec![crate::enums::RiskDomain::ModelData],
        min_severity: Some(Severity::High),
        rule_keys: vec!["MD-EXFIL-001".into()],
        asset_kinds: vec![crate::enums::AssetKind::Agent],
        condition: None,
    };
    assert!(t.matches(
        Some(crate::enums::RiskDomain::ModelData),
        Severity::Critical,
        &["MD-EXFIL-001".to_string()],
        Some(crate::enums::AssetKind::Agent)
    ));
    assert!(!t.matches(
        Some(crate::enums::RiskDomain::ModelData),
        Severity::Medium,
        &["MD-EXFIL-001".to_string()],
        Some(crate::enums::AssetKind::Agent)
    ));
    assert!(!t.matches(
        Some(crate::enums::RiskDomain::RagPoison),
        Severity::High,
        &["MD-EXFIL-001".to_string()],
        Some(crate::enums::AssetKind::Agent)
    ));
    assert!(!t.matches(
        Some(crate::enums::RiskDomain::ModelData),
        Severity::High,
        &["OTHER".to_string()],
        Some(crate::enums::AssetKind::Agent)
    ));
    assert!(!t.matches(
        Some(crate::enums::RiskDomain::ModelData),
        Severity::High,
        &["MD-EXFIL-001".to_string()],
        Some(crate::enums::AssetKind::McpServer)
    ));
}

#[test]
pub(crate) fn empty_trigger_matches_everything() {
    let t = PlaybookTrigger::default();
    assert!(t.matches(None, Severity::Info, &[], None));
}

#[test]
pub(crate) fn case_event_kind_str() {
    assert_eq!(CaseEventKind::CredentialRevoked.as_str(), "credential-revoked");
    assert_eq!(CaseEventKind::PlaybookRun.as_str(), "playbook-run");
}
