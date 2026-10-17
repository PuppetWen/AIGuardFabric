//! Synthetic immutable inputs to the actual private quota owner reducers; no clock/environment mutation.
use super::{records::*, reducer};
use crate::{
    gateway_quota::{self, settlement as gateway},
    runtime_quota::settlement as runtime,
};
use agf_core::{
    enums::{LlmProvider, PolicyAction, QuotaDimension, QuotaScope},
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    model::UsageRecord,
    quota::{Quota, QuotaConsumption, QuotaWindow},
    rbac::SubjectKind,
    time::Timestamp,
};
use serde_json::Value;

pub(super) struct Fixture {
    pub(super) fact: Fact,
    pub(super) pending: Pending,
    pub(super) gateway: Value,
    pub(super) runtime: Value,
    pub(super) quotas: Vec<Quota>,
}
pub(super) fn fixture(seconds: i64) -> DomainResult<Fixture> {
    let at = Timestamp::from_unix_secs(seconds).map_err(DomainError::Validation)?;
    let tenant = TenantId::default_tenant();
    let id = Id::new();
    let endpoint = Id::new();
    let plan = gateway::Plan {
        tokens: 20,
        cost: 30,
        endpoint,
        agent: None,
        route: "owned-route".into(),
        route_budget: 0,
        max_total: 0,
    };
    let (gateway, ga) = gateway::reserve(None, &gateway_quota::Limits::default(), &plan, id, seconds)?;
    let quotas = [QuotaDimension::Tokens, QuotaDimension::Requests, QuotaDimension::Concurrency, QuotaDimension::Cost]
        .into_iter()
        .map(|dimension| Quota {
            id: Id::new(),
            tenant_id: tenant,
            name: dimension.as_str().into(),
            scope: QuotaScope::Tenant,
            dimension,
            window: QuotaWindow::Minute,
            limit: 10000,
            soft_threshold: 0,
            on_exceed: PolicyAction::Deny,
            enabled: true,
            target_id: None,
            created_at: at,
            updated_at: at,
        })
        .collect::<Vec<_>>();
    let estimated = QuotaConsumption { tokens: 20, requests: 1, concurrency: 1, cost_micro: 30 };
    let (runtime, ra) = runtime::reserve(
        None,
        &runtime::Reserve {
            tenant,
            agent: None,
            session: "owned-session",
            reservation: id,
            now: at,
            estimated: &estimated,
            quotas: &quotas,
        },
    )?;
    let amounts = ra.charges.iter().map(|charge| charge.amount).collect();
    let origin = Origin {
        tenant,
        identity_tenant: tenant,
        subject: Id::new(),
        kind: SubjectKind::ApiKey,
        bound_agent: None,
        session: None,
        token_expiry: None,
        issued_at_ms: None,
        source_ip: None,
    };
    let usage_id = usage_id(tenant, id);
    let fact = Fact {
        attempt: id,
        usage_id,
        origin: origin.clone(),
        submitted_at: at,
        execute_before: at.offset_secs(110),
        phase: Phase::AwaitingSettlement,
        charge: Some(ChargeSnapshot {
            chats: Vec::new(),
            embedding: None,
            agent_safety: None,
            endpoint,
            session: "owned-session".into(),
            gateway: ga,
            runtime: ra,
            gateway_charged: gateway::Charged::default(),
            runtime_charged: amounts,
            expires_at: at.offset_secs(900),
            state: ChargeState::Reserved,
        }),
    };
    let usage = UsageRecord {
        id: usage_id,
        tenant_id: tenant,
        session_id: "owned-session".into(),
        agent_id: None,
        endpoint_id: endpoint,
        provider: LlmProvider::OpenAi,
        model: "owned-model".into(),
        prompt_tokens: 4,
        completion_tokens: 3,
        cached_tokens: 0,
        cache_write_tokens: 0,
        cache_write_1h_tokens: 0,
        cache_hit: false,
        cost_micro: 11,
        mocked: false,
        latency_ms: 1,
        at,
    };
    let pending = Pending {
        attempt: id,
        origin,
        outcome: KnownOutcome {
            components: Vec::new(),
            semantic: None,
            evidence: Evidence::SentUsageKnown,
            usage: Some(usage),
            rejection: None,
        },
    };
    Ok(Fixture { fact, pending, gateway, runtime, quotas })
}
pub(super) fn write(
    fact: &Fact,
    pending: &Pending,
    gateway: Value,
    runtime: Value,
    now: i64,
) -> DomainResult<reducer::Candidate> {
    match reducer::reduce(fact, pending, Some(gateway), Some(runtime), now)? {
        reducer::Decision::Write(row) => Ok(*row),
        reducer::Decision::Unchanged => Err(DomainError::Internal("Expected settlement candidate".into())),
    }
}
pub(super) fn counter(ledger: &Value, fact: &Fact, dimension: QuotaDimension) -> DomainResult<i64> {
    let charge = fact.charge.as_ref().ok_or_else(|| DomainError::Internal("Missing test snapshot".into()))?;
    let key = &charge
        .runtime
        .charges
        .iter()
        .find(|row| row.dimension == dimension)
        .ok_or_else(|| DomainError::Internal("Missing dimension".into()))?
        .key;
    ledger["counters"][key]["used"]
        .as_i64()
        .ok_or_else(|| DomainError::Internal("Missing exact original counter".into()))
}
