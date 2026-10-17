//! Tenant escalation policies with version checks and current publisher permissions.
use crate::{
    middleware::Principal,
    notification_config::{self, StoredChannel},
    soar_workflow::Actor,
    state::AppState,
};
use agf_core::{
    enums::Severity,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    notify::ChannelKind,
    rbac::SubjectKind,
    time::Timestamp,
};
use agf_correlate::sla::{EscalationTarget, SlaPolicy};
use serde::{Deserialize, Serialize};

mod clock;
mod worker;
pub(crate) use clock::{clock, clock_from_config, sla_policy};
pub(crate) use worker::{HEALTH, permit_delivery};
pub use worker::{run_loop, tick};
pub const KIND: &str = "alert-escalation-policy";
const SEVERITIES: [Severity; 5] = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tier {
    pub level: u8,
    pub overdue_minutes: u32,
    pub target: EscalationTarget,
    pub channels: Vec<ChannelKind>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Route {
    pub severity: Severity,
    pub response_minutes: u32,
    pub enabled: bool,
    pub tiers: Vec<Tier>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub route: Route,
    /// None deliberately includes existing alerts; Some applies from the activation time.
    pub since: Option<Timestamp>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Revision {
    pub version: u64,
    pub at: Timestamp,
    pub actor: String,
    pub reason: String,
    pub policies: Vec<Policy>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub version: u64,
    pub policies: Vec<Policy>,
    pub publisher: Option<Actor>,
    pub mock_mode: bool,
    pub history: Vec<Revision>,
}
impl Default for Configuration {
    fn default() -> Self {
        Self {
            version: 0,
            publisher: None,
            mock_mode: false,
            history: vec![],
            policies: SEVERITIES
                .iter()
                .map(|severity| {
                    let policy = SlaPolicy::for_severity(*severity);
                    Policy {
                        since: None,
                        route: Route {
                            severity: *severity,
                            response_minutes: u32::try_from(policy.first_response_secs / 60).unwrap_or(60),
                            enabled: false,
                            tiers: policy
                                .escalation
                                .iter()
                                .map(|step| Tier {
                                    level: step.level,
                                    overdue_minutes: u32::try_from(step.overdue_secs / 60).unwrap_or_default(),
                                    target: step.target,
                                    channels: vec![],
                                })
                                .collect(),
                        },
                    }
                })
                .collect(),
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Change {
    pub expected_version: u64,
    pub routes: Vec<Route>,
    pub reason: String,
    /// Applies only when a route transitions from disabled to enabled.
    #[serde(default)]
    pub include_existing: bool,
}
pub fn id(tenant: TenantId) -> Id {
    deterministic_id(KIND, &tenant.to_string())
}
pub fn can_write(state: &AppState, p: &Principal) -> bool {
    p.subject_kind == SubjectKind::User
        && p.require(state, "alerts", "write").is_ok()
        && p.require(state, "alerts", "read").is_ok()
}
pub async fn get(state: &AppState, tenant: TenantId) -> DomainResult<Configuration> {
    Ok(state.configurations.get(tenant, KIND, id(tenant)).await?.unwrap_or_default())
}
pub async fn channels(state: &AppState, tenant: TenantId) -> DomainResult<Vec<StoredChannel>> {
    state.configurations.list(tenant, notification_config::KIND).await
}
fn validate(routes: &[Route], rows: &[StoredChannel]) -> DomainResult<()> {
    if routes.len() != 5
        || SEVERITIES.iter().any(|severity| routes.iter().filter(|r| r.severity == *severity).count() != 1)
    {
        return Err(DomainError::Validation("须提供五个等级各一条升级策略".into()));
    }
    for route in routes {
        if !(1..=43_200).contains(&route.response_minutes)
            || route.tiers.len() > 3
            || (route.enabled && route.tiers.is_empty())
        {
            return Err(DomainError::Validation("响应目标须为 1..43200 分钟；每条启用策略需有 1..3 级升级".into()));
        }
        let mut previous = None;
        for (index, tier) in route.tiers.iter().enumerate() {
            if usize::from(tier.level) != index + 1
                || tier.overdue_minutes > 43_200
                || previous.is_some_and(|delay| tier.overdue_minutes <= delay)
            {
                return Err(DomainError::Validation(
                    "升级层级须从 1 连续编号，逾期分钟须严格递增且不超过 43200".into(),
                ));
            }
            previous = Some(tier.overdue_minutes);
            if tier.channels.len() > 9 || tier.channels.iter().enumerate().any(|(i, k)| tier.channels[..i].contains(k))
            {
                return Err(DomainError::Validation("通知渠道不能重复且最多九种".into()));
            }
            if route.enabled
                && (tier.channels.is_empty()
                    || tier.channels.iter().any(|kind| {
                        !rows.iter().any(|r| r.channel == *kind && r.enabled && route.severity >= r.min_severity)
                    }))
            {
                return Err(DomainError::PreconditionFailed(
                    "先配置并启用每级通知渠道，确保渠道最低等级不高于策略等级".into(),
                ));
            }
        }
    }
    Ok(())
}
pub async fn save(state: &AppState, p: &Principal, input: Change) -> DomainResult<Configuration> {
    if !can_write(state, p) {
        return Err(DomainError::Forbidden("升级配置需要具备 alerts:read/write 的个人账号".into()));
    }
    if !state.store.has_database() && input.routes.iter().any(|r| r.enabled) {
        return Err(DomainError::PreconditionFailed("自动升级需要 PostgreSQL；离线模式只能保存停用配置".into()));
    }
    if input.reason.trim().is_empty() || input.reason.len() > 2000 {
        return Err(DomainError::Validation("变更说明须为 1..2000 字节".into()));
    }
    validate(&input.routes, &channels(state, p.tenant).await?)?;
    let actor = Actor::from_principal(p)?;
    let now = Timestamp::now();
    state
        .configurations
        .mutate::<Configuration, _>(p.tenant, KIND, id(p.tenant), |config| {
            if config.version != input.expected_version {
                return Err(DomainError::Conflict("升级配置已更新；请刷新核对后重试，当前草稿未保存".into()));
            }
            let mut policies = vec![];
            for route in input.routes {
                let old = config.policies.iter().find(|policy| policy.route.severity == route.severity);
                let since = if route.enabled && old.is_none_or(|p| !p.route.enabled) {
                    if input.include_existing { None } else { Some(now) }
                } else {
                    old.and_then(|policy| policy.since)
                };
                policies.push(Policy { route, since });
            }
            config.version = config
                .version
                .checked_add(1)
                .filter(|v| i64::try_from(*v).is_ok())
                .ok_or_else(|| DomainError::Conflict("版本号溢出".into()))?;
            config.policies = policies;
            config.publisher = Some(actor.clone());
            config.mock_mode = state.config.mock_mode;
            config.history.push(Revision {
                version: config.version,
                at: now,
                actor: actor.display(),
                reason: input.reason.trim().into(),
                policies: config.policies.clone(),
            });
            if config.history.len() > 20 {
                config.history.remove(0);
            }
            Ok(())
        })
        .await
}
