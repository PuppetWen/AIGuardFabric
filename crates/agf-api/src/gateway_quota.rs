//! 网关租户配额与日预算：数据库原子预留，完成后按真实用量结算。
use crate::{config_store::ConfigStore, model_routes::tenant_record_id, state::AppState, store::ModelRoutePolicy};
use agf_aigw::{AiGateway, gateway::CallContext, meter::BudgetGuard, wire::ChatRequest};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    model::UsageRecord,
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

pub const QUOTAS: &str = "gateway-quotas";
pub const USAGE: &str = "model-usage";
const LEASE_SECS: i64 = 900;
pub(crate) mod settlement;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Limits {
    #[serde(default)]
    pub version: u64,
    pub tenant_tokens_per_day: u64,
    pub agent_tokens_per_hour: u64,
    pub session_tokens_per_turn: u64,
    pub max_concurrent_sessions: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Totals {
    tokens: u64,
    cost: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Reservation {
    expires: i64,
    tokens: u64,
    cost: u64,
    agent: String,
    route: String,
    // Atomic attempts are reclaimed only together with their authenticated attempt fact.
    #[serde(default)]
    atomic_day: Option<i64>,
    #[serde(default)]
    atomic_hour: Option<i64>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Ledger {
    day: i64,
    hour: i64,
    totals: Totals,
    agents: BTreeMap<String, u64>,
    routes: BTreeMap<String, u64>,
    reservations: BTreeMap<String, Reservation>,
}

#[derive(Debug)]
pub struct Lease {
    config: Arc<ConfigStore>,
    tenant: TenantId,
    id: String,
    completed: bool,
    runtime: Option<crate::runtime_quota::Lease>,
}

fn ensure(scope: &str, used: u64, add: u64, limit: u64) -> DomainResult<()> {
    if limit > 0 && used.saturating_add(add) > limit {
        return Err(DomainError::QuotaExceeded {
            scope: scope.into(),
            dimension: "gateway".into(),
            used: i64::try_from(used.saturating_add(add)).unwrap_or(i64::MAX),
            limit: i64::try_from(limit).unwrap_or(i64::MAX),
        });
    }
    Ok(())
}

impl Ledger {
    fn roll(&mut self, now: i64) {
        if self.day != now / 86400 {
            self.totals = Totals::default();
            self.routes.clear();
            self.day = now / 86400;
        }
        if self.hour != now / 3600 {
            self.agents.clear();
            self.hour = now / 3600;
        }
        // 崩溃或上游未返回 usage 时保守记账，不因重启释放已经可能消耗的预算。
        let expired: Vec<_> = self
            .reservations
            .iter()
            .filter(|(_, value)| value.atomic_day.is_none() && value.expires <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            self.settle(&id, None);
        }
    }

    fn settle(&mut self, id: &str, usage: Option<&UsageRecord>) {
        if let Some(reserved) = self.reservations.remove(id) {
            let tokens = usage.map_or(reserved.tokens, UsageRecord::total_tokens);
            let cost = usage.map_or(reserved.cost, |row| row.cost_micro);
            self.totals.tokens = self.totals.tokens.saturating_add(tokens);
            self.totals.cost = self.totals.cost.saturating_add(cost);
            *self.agents.entry(reserved.agent).or_default() += tokens;
            *self.routes.entry(reserved.route).or_default() += cost;
        }
    }
}

impl Lease {
    pub async fn acquire(
        state: &AppState,
        context: &CallContext,
        gateway: &AiGateway,
        request: &ChatRequest,
        policy: Option<&ModelRoutePolicy>,
    ) -> DomainResult<Self> {
        let tenant = context.tenant;
        let limits = limits(state, tenant).await?;
        let prompt = request.estimate_prompt_tokens();
        let completion = u64::from(request.max_tokens.unwrap_or(1024));
        let tokens = prompt.saturating_add(completion);
        let candidates = gateway.router().eligible(&context.routing_context(request))?;
        let cost = candidates
            .iter()
            .filter(|ep| {
                !gateway.endpoint_is_mock(ep)
                    && (request.anthropic_native.is_none() || ep.provider == agf_core::enums::LlmProvider::Anthropic)
            })
            .map(|ep| BudgetGuard::projected_micro_for_request(ep, request))
            .max()
            .unwrap_or(0);
        let route = policy.map_or_else(String::new, |p| p.id.to_string());
        // API 校验预算在 0..=1000000 元，转微元不会越界。
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let budget = policy.map_or(0, |p| (p.budget_cny_per_day * 1_000_000.0).round() as u64);
        let agent_id = context.agent_id;
        let agent = agent_id.map_or_else(|| "unassigned".into(), |id| id.to_string());
        let id = Id::new().to_string();
        let reservation = Reservation {
            expires: Timestamp::now().unix_secs() + LEASE_SECS,
            tokens,
            cost,
            agent: agent.clone(),
            route: route.clone(),
            atomic_day: None,
            atomic_hour: None,
        };
        state
            .configurations
            .mutate::<Ledger, _>(tenant, "gateway-ledger", tenant_record_id(tenant), |ledger| {
                ledger.roll(Timestamp::now().unix_secs());
                ensure("session-turn-tokens", 0, tokens, limits.session_tokens_per_turn)?;
                let pending_tokens = ledger
                    .reservations
                    .values()
                    .filter(|r| r.atomic_day.is_none_or(|day| day == ledger.day))
                    .map(|r| r.tokens)
                    .sum::<u64>();
                ensure(
                    "tenant-day-tokens",
                    ledger.totals.tokens.saturating_add(pending_tokens),
                    tokens,
                    limits.tenant_tokens_per_day,
                )?;
                let pending_agent = ledger
                    .reservations
                    .values()
                    .filter(|r| r.agent == agent && r.atomic_hour.is_none_or(|hour| hour == ledger.hour))
                    .map(|r| r.tokens)
                    .sum::<u64>();
                ensure(
                    "agent-hour-tokens",
                    ledger.agents.get(&agent).copied().unwrap_or(0).saturating_add(pending_agent),
                    tokens,
                    limits.agent_tokens_per_hour,
                )?;
                ensure(
                    "concurrent-sessions",
                    u64::try_from(ledger.reservations.len()).unwrap_or(u64::MAX),
                    1,
                    limits.max_concurrent_sessions,
                )?;
                let pending_cost = ledger
                    .reservations
                    .values()
                    .filter(|r| r.route == route && r.atomic_day.is_none_or(|day| day == ledger.day))
                    .map(|r| r.cost)
                    .sum::<u64>();
                ensure(
                    "route-day-budget",
                    ledger.routes.get(&route).copied().unwrap_or(0).saturating_add(pending_cost),
                    cost,
                    budget,
                )?;
                ledger.reservations.insert(id.clone(), reservation);
                Ok(())
            })
            .await?;
        let consumption = agf_core::quota::QuotaConsumption {
            tokens: i64::try_from(tokens).unwrap_or(i64::MAX),
            requests: 1,
            concurrency: 1,
            cost_micro: i64::try_from(cost).unwrap_or(i64::MAX),
        };
        let runtime = match crate::runtime_quota::Lease::acquire(
            state,
            tenant,
            agent_id,
            &context.session_id,
            "gateway",
            &consumption,
        )
        .await
        {
            Ok(lease) => lease,
            Err(error) => {
                state
                    .configurations
                    .mutate::<Ledger, _>(tenant, "gateway-ledger", tenant_record_id(tenant), |ledger| {
                        ledger.reservations.remove(&id);
                        Ok(())
                    })
                    .await?;
                return Err(error);
            }
        };
        Ok(Self { config: state.configurations.clone(), tenant, id, completed: false, runtime: Some(runtime) })
    }

    /// Keep both ledgers reserved while a live provider stream is idle or slow.
    pub async fn renew(&self) -> DomainResult<()> {
        let now = Timestamp::now().unix_secs();
        self.config
            .mutate::<Ledger, _>(self.tenant, "gateway-ledger", tenant_record_id(self.tenant), |ledger| {
                ledger.roll(now);
                let reservation = ledger
                    .reservations
                    .get_mut(&self.id)
                    .ok_or_else(|| DomainError::PreconditionFailed("模型网关配额租约已失效".into()))?;
                reservation.expires = now + LEASE_SECS;
                Ok(())
            })
            .await?;
        if let Some(runtime) = &self.runtime {
            runtime.renew().await?;
        }
        Ok(())
    }

    pub async fn finish(mut self, usage: Option<&UsageRecord>) -> DomainResult<()> {
        if let Some(record) = usage {
            self.config.put(self.tenant, USAGE, record.id, record).await?;
        }
        self.config
            .mutate::<Ledger, _>(self.tenant, "gateway-ledger", tenant_record_id(self.tenant), |ledger| {
                ledger.settle(&self.id, usage);
                Ok(())
            })
            .await?;
        if let Some(runtime) = self.runtime.take() {
            let actual = usage.map(|row| agf_core::quota::QuotaConsumption {
                tokens: i64::try_from(row.total_tokens()).unwrap_or(i64::MAX),
                requests: 1,
                concurrency: 0,
                cost_micro: i64::try_from(row.cost_micro).unwrap_or(i64::MAX),
            });
            runtime.finish(actual.as_ref()).await?;
        }
        self.completed = true;
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        // 中途取消也保守结算预留用量，避免通过断流规避配额。
        let config = self.config.clone();
        let tenant = self.tenant;
        let id = self.id.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = config
                    .mutate::<Ledger, _>(tenant, "gateway-ledger", tenant_record_id(tenant), |ledger| {
                        ledger.settle(&id, None);
                        Ok(())
                    })
                    .await
                {
                    tracing::error!(%error, "网关预留结算失败，待租约回收");
                }
            });
        }
    }
}

pub async fn usage(state: &AppState, tenant: TenantId) -> DomainResult<Vec<UsageRecord>> {
    let mut records: BTreeMap<Id, UsageRecord> =
        state.configurations.list::<UsageRecord>(tenant, USAGE).await?.into_iter().map(|row| (row.id, row)).collect();
    for row in state.meter.recent(agf_aigw::Meter::MAX_RECENT).into_iter().filter(|row| row.tenant_id == tenant) {
        records.insert(row.id, row);
    }
    let mut rows: Vec<_> = records.into_values().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.at));
    Ok(rows)
}

/// 与租户设置页相同的有效配额，未保存时使用现有配额与部署配置。
pub async fn limits(state: &AppState, tenant: TenantId) -> DomainResult<Limits> {
    if let Some(limits) = state.configurations.get(tenant, QUOTAS, tenant_record_id(tenant)).await? {
        return Ok(limits);
    }
    // 运行时配额按各自窗口独立执行，不能把月/总量配额复制成日/小时限制。
    Ok(Limits {
        tenant_tokens_per_day: u64::try_from(state.config.quota.tenant_tokens_per_day).unwrap_or(0),
        ..Limits::default()
    })
}
