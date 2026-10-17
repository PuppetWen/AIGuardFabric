//! 运行时三级配额：一个租户事务内预留全部维度，租约完成后结算并发和真实用量。
use crate::{config_store::ConfigStore, model_routes::tenant_record_id, state::AppState};
use agf_core::{
    enums::{QuotaDimension, QuotaScope},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    quota::{Quota, QuotaConsumption},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

const KIND: &str = "runtime-quota-ledger";
const LEASE_SECS: i64 = 900;
pub(crate) mod settlement;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Counter {
    used: i64,
    expires: Option<i64>,
    quota: Option<Id>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Charge {
    key: String,
    dimension: QuotaDimension,
    amount: i64,
}
#[derive(Debug, Serialize, Deserialize)]
struct Reservation {
    expires: i64,
    owner: String,
    charges: Vec<Charge>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
struct Ledger {
    counters: BTreeMap<String, Counter>,
    reservations: BTreeMap<Id, Reservation>,
}

impl Ledger {
    fn settle(&mut self, id: Id, actual: Option<&QuotaConsumption>) {
        let Some(reserved) = self.reservations.remove(&id) else { return };
        for charge in reserved.charges {
            if let Some(counter) = self.counters.get_mut(&charge.key) {
                let desired = if charge.dimension == QuotaDimension::Concurrency {
                    0
                } else {
                    actual.map_or(charge.amount, |value| value.value(charge.dimension))
                };
                counter.used = counter.used.saturating_sub(charge.amount).saturating_add(desired).max(0);
            }
        }
    }
    fn roll(&mut self, now: i64) {
        let expired: Vec<_> = self
            .reservations
            .iter()
            .filter(|(_, row)| row.owner != settlement::OWNER && row.expires <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.settle(id, None);
        }
        // Keep an old atomic bucket while its authenticated reservation is outstanding.
        // Expiry maintenance removes that reservation and charge in one transaction.
        let held = self
            .reservations
            .values()
            .filter(|row| row.owner == settlement::OWNER)
            .flat_map(|row| row.charges.iter().map(|charge| charge.key.clone()))
            .collect::<std::collections::BTreeSet<_>>();
        self.counters.retain(|key, value| held.contains(key) || value.expires.is_none_or(|expires| expires > now));
    }
}

fn counter_key(quota: &Quota, agent: Option<Id>, session: &str, now: Timestamp) -> Option<String> {
    let target = match quota.scope {
        QuotaScope::Tenant => String::new(),
        QuotaScope::Agent => {
            let agent = agent?;
            if quota.target_id.is_some_and(|target| target != agent) {
                return None;
            }
            agent.to_string()
        }
        QuotaScope::Session => {
            if quota.target_id.is_some_and(|target| target.to_string() != session) {
                return None;
            }
            session.to_string()
        }
    };
    // 并发是正在执行的请求数，不在分钟/小时边界重新计数。
    let bucket =
        if quota.dimension == QuotaDimension::Concurrency { "inflight".into() } else { quota.window.bucket_key(now) };
    Some(format!("{}:{target}:{bucket}", quota.id))
}

/// 未完成租约在任务取消时保守结算；跨进程 MCP 调用通过 detach/finish_remote 接续。
#[derive(Debug)]
pub struct Lease {
    config: Arc<ConfigStore>,
    tenant: TenantId,
    id: Id,
    completed: bool,
    release_on_drop: bool,
}
impl Lease {
    pub async fn acquire(
        state: &AppState,
        tenant: TenantId,
        agent: Option<Id>,
        session: &str,
        owner: &str,
        estimated: &QuotaConsumption,
    ) -> DomainResult<Self> {
        let quotas = crate::quota_definitions::list(state, tenant).await?;
        let now = Timestamp::now();
        let id = Id::new();
        state
            .configurations
            .mutate::<Ledger, _>(tenant, KIND, tenant_record_id(tenant), |ledger| {
                ledger.roll(now.unix_secs());
                if ledger.reservations.len() >= 10000 {
                    return Err(DomainError::PreconditionFailed("当前并发请求过多，请稍后重试".into()));
                }
                let mut charges = Vec::new();
                for quota in quotas.iter().filter(|q| q.enabled && q.limit > 0) {
                    let Some(key) = counter_key(quota, agent, session, now) else { continue };
                    let amount = estimated.value(quota.dimension).max(0);
                    let counter = ledger.counters.entry(key.clone()).or_insert_with(|| Counter {
                        quota: Some(quota.id),
                        used: 0,
                        expires: if quota.dimension == QuotaDimension::Concurrency {
                            None
                        } else {
                            quota.window.seconds().map(|seconds| now.unix_secs() + seconds + LEASE_SECS)
                        },
                    });
                    let next = counter.used.saturating_add(amount);
                    if next > quota.limit
                        && !matches!(
                            quota.on_exceed,
                            agf_core::enums::PolicyAction::Allow | agf_core::enums::PolicyAction::Audit
                        )
                    {
                        return Err(DomainError::QuotaExceeded {
                            scope: quota.scope.as_str().into(),
                            dimension: quota.dimension.as_str().into(),
                            used: next,
                            limit: quota.limit,
                        });
                    }
                    counter.used = next;
                    charges.push(Charge { key, dimension: quota.dimension, amount });
                }
                ledger
                    .reservations
                    .insert(id, Reservation { expires: now.unix_secs() + LEASE_SECS, owner: owner.into(), charges });
                Ok(())
            })
            .await?;
        Ok(Self { config: state.configurations.clone(), tenant, id, completed: false, release_on_drop: true })
    }

    /// Legacy MCP disconnects do not prove cancellation. Hold that reservation until completion or expiry.
    #[must_use]
    pub fn retain_on_disconnect(mut self) -> Self {
        self.release_on_drop = false;
        self
    }

    /// Extend a live streaming call without charging another request.
    pub async fn renew(&self) -> DomainResult<()> {
        let now = Timestamp::now().unix_secs();
        self.config
            .mutate::<Ledger, _>(self.tenant, KIND, tenant_record_id(self.tenant), |ledger| {
                let row = ledger
                    .reservations
                    .get_mut(&self.id)
                    .filter(|row| row.expires > now)
                    .ok_or_else(|| DomainError::PreconditionFailed("运行时配额租约已失效".into()))?;
                row.expires = now + LEASE_SECS;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn finish(mut self, actual: Option<&QuotaConsumption>) -> DomainResult<()> {
        settle(&self.config, self.tenant, self.id, None, actual).await?;
        self.completed = true;
        Ok(())
    }

    pub fn detach(mut self) -> Id {
        self.completed = true;
        self.id
    }
}

async fn settle(
    config: &ConfigStore,
    tenant: TenantId,
    id: Id,
    owner: Option<&str>,
    actual: Option<&QuotaConsumption>,
) -> DomainResult<()> {
    config
        .mutate::<Ledger, _>(tenant, KIND, tenant_record_id(tenant), |ledger| {
            if let Some(reserved) = ledger.reservations.get(&id) {
                if owner.is_some_and(|owner| reserved.owner != owner) {
                    return Err(DomainError::Forbidden("调用租约不属于当前会话".into()));
                }
            }
            ledger.settle(id, actual);
            Ok(())
        })
        .await?;
    Ok(())
}

pub async fn finish_remote(state: &AppState, tenant: TenantId, id: Id, owner: &str) -> DomainResult<()> {
    settle(&state.configurations, tenant, id, Some(owner), None).await
}

/// Release every reserved dimension when a detached call never reached its upstream.
pub async fn abort_remote(state: &AppState, tenant: TenantId, id: Id, owner: &str) -> DomainResult<()> {
    settle(&state.configurations, tenant, id, Some(owner), Some(&QuotaConsumption::default())).await
}

/// Renew a detached tool call while its legacy SSE response stream is still connected.
pub async fn renew_remote(state: &AppState, tenant: TenantId, id: Id, owner: &str) -> DomainResult<()> {
    let now = Timestamp::now().unix_secs();
    state
        .configurations
        .mutate::<Ledger, _>(tenant, KIND, tenant_record_id(tenant), |ledger| {
            let row =
                ledger.reservations.get_mut(&id).filter(|row| row.owner == owner && row.expires > now).ok_or_else(
                    || DomainError::PreconditionFailed("MCP tool-call lease has expired or changed owner".into()),
                )?;
            row.expires = now + LEASE_SECS;
            Ok(())
        })
        .await?;
    Ok(())
}

pub async fn usage(state: &AppState, tenant: TenantId) -> DomainResult<BTreeMap<Id, i64>> {
    let quotas = crate::quota_definitions::list(state, tenant).await?;
    let now = Timestamp::now();
    let mut ledger =
        state.configurations.get::<Ledger>(tenant, KIND, tenant_record_id(tenant)).await?.unwrap_or_default();
    ledger.roll(now.unix_secs());
    let mut usage = BTreeMap::new();
    for quota in quotas {
        let bucket = if quota.dimension == QuotaDimension::Concurrency {
            "inflight".into()
        } else {
            quota.window.bucket_key(now)
        };
        let used = ledger
            .counters
            .iter()
            .filter(|(key, counter)| counter.quota == Some(quota.id) && key.ends_with(&format!(":{bucket}")))
            .fold(0_i64, |total, (_, counter)| total.saturating_add(counter.used));
        usage.insert(quota.id, used);
    }
    Ok(usage)
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.completed || !self.release_on_drop {
            return;
        }
        let config = self.config.clone();
        let tenant = self.tenant;
        let id = self.id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = settle(&config, tenant, id, None, None).await {
                    tracing::error!(%error, "运行时配额结算失败，等待租约回收");
                }
            });
        }
    }
}
