//! Both quota reservations and their stable authenticated anchor commit before a provider can start.
use super::{
    authority::{self, Submission},
    idempotency,
    records::*,
    source::Source,
    store,
};
use crate::{
    gateway_quota, model_routes::tenant_record_id, state::AppState, store::asset_transaction::AssetTransaction,
};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    error::DomainResult,
    quota::QuotaConsumption,
    time::Timestamp,
};
use serde_json::json;
use std::collections::BTreeMap;

pub(super) enum Reservation {
    First(Box<Fact>),
    Duplicate(idempotency::Duplicate),
}

pub(super) struct Input<'a> {
    pub(super) key: Option<&'a idempotency::Binding>,
    pub(super) plan: &'a gateway_quota::settlement::Plan,
    pub(super) embedding: Option<&'a super::components::EmbeddingAnchor>,
    pub(super) chats: &'a [super::chat_components::ChatAnchor],
    pub(super) session: &'a str,
    pub(super) agent_safety: Option<&'a super::agent::AgentSafety>,
    pub(super) semantic: Option<&'a super::semantic_plan::CachePlan>,
}
pub(super) async fn reserve(
    state: &AppState,
    submission: &Submission<'_>,
    attempt: AuthenticatedAttempt,
    source: &Source,
    input: Input<'_>,
) -> DomainResult<Reservation> {
    tokio::time::timeout_at(submission.deadline, transaction(state, submission, attempt, source, input)).await.map_err(
        |_| agf_core::error::DomainError::Timeout("Atomic model admission exhausted its original budget".into()),
    )?
}

async fn transaction(
    state: &AppState,
    submission: &Submission<'_>,
    attempt: AuthenticatedAttempt,
    source: &Source,
    input: Input<'_>,
) -> DomainResult<Reservation> {
    let Input { plan, embedding, chats, session, semantic, agent_safety, key: admission_key } = input;
    let plan = gateway_quota::settlement::Plan {
        tokens: plan.tokens.checked_add(embedding.map_or(0, |row| row.tokens)).ok_or_else(store::missing)?,
        cost: plan.cost.checked_add(embedding.map_or(0, |row| row.cost)).ok_or_else(store::missing)?,
        endpoint: plan.endpoint,
        agent: plan.agent,
        route: plan.route.clone(),
        route_budget: plan.route_budget,
        max_total: plan.max_total,
    };
    let tenant = attempt.origin.tenant;
    let tx = AssetTransaction::begin(authority::database(state)?, tenant).await?;
    tx.tenant_enabled().await?;
    if let Some(binding) = admission_key {
        if let Some(original) = idempotency::existing(state, &tx, submission, binding).await? {
            tx.commit(&state.store).await?;
            original.recheck(state, submission).await?;
            authority::budget(submission.deadline)?;
            return Ok(Reservation::Duplicate(original));
        }
    }
    source.locked(state, &tx, semantic).await?;
    if let Some(safety) = agent_safety {
        safety.current(state).await?;
    }
    submission.models(state, &attempt.origin).await?;
    let key = tenant_record_id(tenant);
    let quotas =
        crate::quota_definitions::parse_locked(store::read(&tx, crate::quota_definitions::KIND, key).await?, tenant)?;
    let limits =
        store::read(&tx, gateway_quota::QUOTAS, key).await?.map(serde_json::from_value).transpose()?.unwrap_or(
            gateway_quota::Limits {
                tenant_tokens_per_day: u64::try_from(state.config.quota.tenant_tokens_per_day).unwrap_or(0),
                ..gateway_quota::Limits::default()
            },
        );
    let gateway = store::read(&tx, GATEWAY, key).await?;
    let runtime = store::read(&tx, RUNTIME, key).await?;
    let mut active = store::active(state, &tx, tenant).await?;
    if active.items.len() >= 512 || active.items.contains_key(&attempt.id) {
        return Err(store::missing());
    }
    if store::read(&tx, FACT, attempt.id).await?.is_some() {
        return Err(store::missing());
    }
    let now = Timestamp::now();
    let (gateway, gateway_anchor) =
        gateway_quota::settlement::reserve(gateway, &limits, &plan, attempt.id, now.unix_secs())?;
    let estimated = QuotaConsumption {
        tokens: i64::try_from(plan.tokens).map_err(|_| store::missing())?,
        requests: 1,
        concurrency: 1,
        cost_micro: i64::try_from(plan.cost).map_err(|_| store::missing())?,
    };
    let (runtime, runtime_anchor) = crate::runtime_quota::settlement::reserve(
        runtime,
        &crate::runtime_quota::settlement::Reserve {
            tenant,
            agent: plan.agent,
            session,
            reservation: attempt.id,
            now,
            estimated: &estimated,
            quotas: &quotas,
        },
    )?;
    let charged = runtime_anchor.charges.iter().map(|charge| charge.amount).collect();
    let id = attempt.id;
    let fact = attempt.into_fact(Some(ChargeSnapshot {
        chats: chats.to_vec(),
        embedding: embedding.cloned(),
        agent_safety: agent_safety.cloned(),
        endpoint: plan.endpoint,
        session: session.into(),
        gateway: gateway_anchor,
        runtime: runtime_anchor,
        gateway_charged: gateway_quota::settlement::Charged::default(),
        runtime_charged: charged,
        expires_at: now.offset_secs(900),
        state: ChargeState::Reserved,
    }));
    active.items.insert(id, now.offset_secs(900));
    let mut writes = BTreeMap::from([
        ((GATEWAY, key), gateway),
        ((RUNTIME, key), runtime),
        ((ACTIVE, key), store::encoded(state, tenant, key, ACTIVE, &active)?),
        ((FACT, id), store::encoded(state, tenant, id, FACT, &fact)?),
    ]);
    if let Some(binding) = admission_key {
        idempotency::append(state, &tx, tenant, binding, &fact, &mut writes).await?;
    }
    let mut audit = AppState::audit_entry(
        tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(submission.principal, "gateway-admission"),
        AuditTarget::new("gateway-admission", Some(id.to_string()), None),
        "",
    );
    audit.request_id = Some(id.to_string());
    audit.after = Some(
        json!({"attemptId":id,"usageId":fact.usage_id,"estimatedTokens":plan.tokens,"estimatedCostMicro":plan.cost}),
    );
    super::sql::budget(tenant, &writes, &audit)?;
    for ((kind, id), value) in std::mem::take(&mut writes) {
        tx.configure(kind, id, Some(value)).await?;
    }
    tx.audit(audit).await?;
    submission.models(state, &fact.origin).await?;
    source.locked(state, &tx, semantic).await?;
    if let Some(safety) = agent_safety {
        safety.current(state).await?;
    }
    // Final current authority is checked after a possibly long source/audit wait too.
    submission.models(state, &fact.origin).await?;
    authority::budget(submission.deadline)?;
    tx.commit(&state.store).await?;
    Ok(Reservation::First(Box::new(fact)))
}
