//! 由 `cloud.rs` 拆分：`cloud_provider_and_credential_kind_str` 等 10 个函数（纯搬移，逻辑不变）。

use crate::enums::HealthState;
use crate::ids::{Id, TenantId};
use crate::time::Timestamp;
use std::collections::BTreeMap;

use super::*;

#[test]
pub(crate) fn cloud_provider_and_credential_kind_str() {
    assert_eq!(CloudProvider::AliCloud.as_str(), "alicloud");
    assert!(CloudCredentialKind::LongTermAk.is_long_lived());
    assert!(CloudCredentialKind::StsToken.is_temporary());
    assert!(!CloudCredentialKind::InstanceRole.is_long_lived());
    assert_eq!(CloudCredentialKind::InstanceRole.as_str(), "instance-role");
}

pub(crate) fn integration(kind: CloudCredentialKind, arn: Option<&str>) -> CloudIntegration {
    let now = Timestamp::now();
    CloudIntegration {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        provider: CloudProvider::AliCloud,
        name: "生产账号".into(),
        account_id: "1234567890".into(),
        region_id: "cn-hangzhou".into(),
        credential_kind: kind,
        credential_ref: None,
        assume_role_arn: arn.map(ToString::to_string),
        role_session_name: None,
        sts_expires_at: None,
        endpoints: BTreeMap::new(),
        enabled: true,
        health: HealthState::Unconfigured,
        last_sync_at: None,
        last_error: None,
        permission_checks: vec![],
        created_at: now,
        updated_at: now,
    }
}

#[test]
pub(crate) fn cross_account_detection() {
    assert!(!integration(CloudCredentialKind::InstanceRole, None).is_cross_account());
    assert!(integration(CloudCredentialKind::AssumeRole, Some("acs:ram::1:role/agf")).is_cross_account());
}

#[test]
pub(crate) fn sts_expiry_warning() {
    let now = Timestamp::now();
    let mut i = integration(CloudCredentialKind::StsToken, None);
    assert!(!i.sts_expiring_soon(now));
    i.sts_expires_at = Some(now.offset_secs(600));
    assert!(i.sts_expiring_soon(now));
    i.sts_expires_at = Some(now.offset_secs(3_600));
    assert!(!i.sts_expiring_soon(now));
}

#[test]
pub(crate) fn long_lived_risk_flag() {
    assert!(integration(CloudCredentialKind::LongTermAk, None).has_long_lived_risk());
    assert!(!integration(CloudCredentialKind::AssumeRole, Some("arn")).has_long_lived_risk());
}

#[test]
pub(crate) fn permission_check_blocking() {
    let now = Timestamp::now();
    let ok = PermissionCheck {
        name: "cms:PutCustomEvent".into(),
        passed: true,
        note: String::new(),
        required: true,
        checked_at: now,
    };
    let bad = PermissionCheck {
        name: "apig:GetGateway".into(),
        passed: false,
        note: "缺少权限".into(),
        required: true,
        checked_at: now,
    };
    let optional = PermissionCheck {
        name: "oss:ListBuckets".into(),
        passed: false,
        note: String::new(),
        required: false,
        checked_at: now,
    };
    assert!(!ok.is_blocking());
    assert!(bad.is_blocking());
    assert!(!optional.is_blocking());
}

#[test]
pub(crate) fn team_managed_ratio() {
    let now = Timestamp::now();
    let mut team = AgentTeam {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        cloud_team_id: "team-1".into(),
        name: "分析团队".into(),
        description: String::new(),
        agents: vec![],
        roles: vec![],
        orchestration: vec![],
        onboarding: crate::agent::OnboardingMode::Sidecar,
        synced: false,
        cloud_updated_at: None,
        created_at: now,
        updated_at: now,
    };
    assert_eq!(team.managed_ratio(), 0.0);
    team.agents = vec![
        AgentTeamMember {
            cloud_agent_id: "a1".into(),
            name: "分析员".into(),
            models: vec![],
            tools: vec![],
            role_names: vec![],
            asset_id: Some(Id::new()),
            status: "running".into(),
        },
        AgentTeamMember {
            cloud_agent_id: "a2".into(),
            name: "检索员".into(),
            models: vec![],
            tools: vec![],
            role_names: vec![],
            asset_id: None,
            status: "running".into(),
        },
    ];
    assert!((team.managed_ratio() - 0.5).abs() < 1e-6);
}

#[test]
pub(crate) fn orchestration_scheduled_detection() {
    let n = OrchestrationNode {
        node_id: "n1".into(),
        name: "每日盘点".into(),
        agent_ids: vec![],
        depends_on: vec![],
        trigger: "cron".into(),
        cron: Some("0 2 * * *".into()),
    };
    assert!(n.is_scheduled());
    let m = OrchestrationNode { trigger: "manual".into(), cron: None, ..n };
    assert!(!m.is_scheduled());
}

#[test]
pub(crate) fn quota_sync_conflict_resolution_prefers_platform() {
    let mut s = QuotaSyncState {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        integration_id: Id::new(),
        dimension: crate::enums::QuotaDimension::Tokens,
        platform_value: 1_000_000,
        cloud_value: 500_000,
        conflict: false,
        effective_value: 0,
        conflict_alerted: false,
        synced_at: Timestamp::now(),
    };
    assert!(s.resolve(), "首次冲突应告警");
    assert_eq!(s.effective_value, 1_000_000, "以平台为准");
    assert!(!s.resolve(), "已告警过不再重复");
    s.cloud_value = 1_000_000;
    assert!(!s.resolve(), "一致则无冲突");
    assert!(!s.conflict);
    // 冲突消失后再出现，应重新告警
    s.cloud_value = 500_000;
    assert!(s.resolve(), "冲突复现应再次告警");
}

#[test]
pub(crate) fn schedule_backend_fallback() {
    assert_eq!(ScheduleBackend::SchedulerX3.fallback(), ScheduleBackend::LocalCron);
    assert_eq!(ScheduleBackend::LocalCron.fallback(), ScheduleBackend::LocalCron);
    assert_eq!(ScheduleBackend::SchedulerX3.as_str(), "schedulerx3");
}
