//! Explicit observation has a permanent read claim; replay never silently repeats a provider request.
use super::{
    audit,
    authority::Submission,
    context,
    input::ObserveInput,
    provider::{self, Guard},
    records::{DETAIL, FACT, Fact, FactOutcome, Observation, Purpose},
    sql::key,
    store::{self, Decision, Mutation},
    util,
};
use crate::state::AppState;
use agf_alicloud::apig::policy_driver::Observation as DriverObservation;
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use serde_json::json;
use std::sync::Arc;

pub(super) async fn observe(
    state: &AppState,
    submission: Arc<Submission>,
    input: ObserveInput,
) -> DomainResult<Observation> {
    observe_original(state, submission, input, None).await
}

pub(super) async fn observe_original(
    state: &AppState,
    submission: Arc<Submission>,
    input: ObserveInput,
    original: Option<Id>,
) -> DomainResult<Observation> {
    input.validate()?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let scope = context::current(state, tenant, Some(input.configuration_version)).await?;
    context::confirm(&scope, input.confirm_live)?;
    let request_hash = util::request_hash(&(&input, &scope, original))?;
    if let Some(fact) = state.configurations.get::<Fact>(tenant, FACT, util::fact_id(tenant, input.request_id)).await? {
        util::match_fact(&fact, tenant, input.request_id, Purpose::Observation, &request_hash)?;
        return load(state, tenant, input.request_id).await?.ok_or_else(|| {
            DomainError::Conflict("此观察编号已领取但没有可用正文；请明确使用新的观察编号，不会自动再次查询".into())
        });
    }
    let main = store::load(state, tenant).await?;
    let evicted = (main.observations.len() == 8).then(|| main.observations[0]);
    let mut related =
        vec![key(FACT, util::fact_id(tenant, input.request_id)), key(DETAIL, record_id(tenant, input.request_id))];
    if let Some(id) = evicted {
        related.push(key(DETAIL, record_id(tenant, id)));
    }
    let started_at = Timestamp::now();
    let fact = Fact {
        tenant,
        request_id: input.request_id,
        purpose: Purpose::Observation,
        request_hash,
        scope: scope.clone(),
        created_at: started_at,
        actor: AppState::audit_actor(&submission.principal, &submission.principal.display()),
        outcome: FactOutcome::Reading { finished_at: None, failed: false },
    };
    store::mutate(
        state,
        Mutation {
            submission: &submission,
            scope: Some(&scope),
            selection: None,
            fence: None,
            source: &[],
            related: &related,
        },
        |candidate, snapshot| {
            if candidate.version != main.version
                || candidate.active.as_ref().is_some_and(|active| active.expires_at > Timestamp::now())
            {
                return Err(util::stale());
            }
            if snapshot
                .related
                .get(&(FACT.into(), util::fact_id(tenant, input.request_id)))
                .and_then(Option::as_ref)
                .is_some()
            {
                return Err(DomainError::Conflict("观察编号刚被另一个实例领取；请读取原回执".into()));
            }
            if let Some(id) = evicted {
                candidate.observations.retain(|known| *known != id);
            }
            candidate.observations.push(input.request_id);
            candidate.latest_observation = Some(input.request_id);
            util::bump(candidate)?;
            let mut writes = super::records::Values::new();
            util::put(&mut writes, FACT, util::fact_id(tenant, input.request_id), &fact)?;
            if let Some(id) = evicted {
                writes.insert((DETAIL.into(), record_id(tenant, id)), None);
            }
            let audit = audit::entry(
                &submission,
                input.request_id,
                "apig-policy-observation-claim",
                AuditAction::Configure,
                json!({"phase":"claimed","targetScopeId":scope.target.target_scope_id}),
            );
            Ok(Decision::Write { related: writes, audit: Box::new(audit) })
        },
    )
    .await?;
    let guard = Arc::new(Guard {
        state: state.clone(),
        submission: submission.clone(),
        scope: scope.clone(),
        fence: None,
        source: Vec::new(),
        operation: None,
    });
    let result = provider::query(guard, input.initialize_mock_fixture).await;
    // A borrowed network future is never spawned. Only the known local result publication owns a task.
    let owned_state = state.clone();
    tokio::spawn(async move { finish(&owned_state, &submission, fact, started_at, original, result).await })
        .await
        .map_err(|_| DomainError::Internal("本地观察保存中断；原编号不得自动重复查询".into()))?
}

async fn finish(
    state: &AppState,
    submission: &Submission,
    mut fact: Fact,
    started_at: Timestamp,
    original: Option<Id>,
    result: DomainResult<DriverObservation>,
) -> DomainResult<Observation> {
    let tenant = fact.tenant;
    let observation = result
        .as_ref()
        .ok()
        .map(|observed| {
            let observed_at = Timestamp::now();
            let text = serde_json::to_string(&Envelope {
                scope: fact.scope.clone(),
                request_id: fact.request_id,
                original_operation_id: original,
                started_at,
                observed_at,
                evidence: observed.exported_evidence(),
            })?;
            Ok::<_, DomainError>(Observation {
                tenant,
                request_id: fact.request_id,
                original_operation_id: original,
                scope: fact.scope.clone(),
                started_at,
                observed_at,
                fingerprint: observed.fingerprint().to_owned(),
                config_hash: observed.config_hash(),
                content_hash: util::hash(text.as_bytes()),
                content_bytes: text.len(),
                content: util::encrypt_content(state, tenant, record_id(tenant, fact.request_id), &text)?,
            })
        })
        .transpose()?;
    fact.outcome = FactOutcome::Reading { finished_at: Some(Timestamp::now()), failed: observation.is_none() };
    let related = [key(FACT, util::fact_id(tenant, fact.request_id)), key(DETAIL, record_id(tenant, fact.request_id))];
    let mut evicted = false;
    store::mutate(
        state,
        Mutation { submission, scope: Some(&fact.scope), selection: None, fence: None, source: &[], related: &related },
        |main, snapshot| {
            let prior: Fact = util::read(&snapshot.related, FACT, util::fact_id(tenant, fact.request_id))?
                .ok_or_else(util::corrupt)?;
            util::match_fact(&prior, tenant, fact.request_id, Purpose::Observation, &fact.request_hash)?;
            let FactOutcome::Reading { finished_at, .. } = prior.outcome else {
                return Err(util::corrupt());
            };
            if finished_at.is_some() {
                return Ok(Decision::Unchanged);
            }
            evicted = !main.observations.contains(&fact.request_id);
            let mut finalized = fact.clone();
            if evicted {
                finalized.outcome = FactOutcome::Reading { finished_at: Some(Timestamp::now()), failed: true };
            }
            let mut writes = super::records::Values::new();
            util::put(&mut writes, FACT, util::fact_id(tenant, fact.request_id), &finalized)?;
            if let Some(observation) = observation.as_ref().filter(|_| !evicted) {
                util::put(&mut writes, DETAIL, record_id(tenant, fact.request_id), observation)?;
            }
            util::bump(main)?;
            let mut audit = audit::entry(
                submission,
                fact.request_id,
                "apig-policy-observation",
                AuditAction::Read,
                json!({"observed":observation.is_some() && !evicted,"evicted":evicted,"targetScopeId":fact.scope.target.target_scope_id}),
            );
            if observation.is_none() || evicted {
                audit.outcome = agf_core::audit::AuditOutcome::Failure;
            }
            Ok(Decision::Write { related: writes, audit: Box::new(audit) })
        },
    )
    .await?;
    if evicted {
        return Err(DomainError::Conflict(
            "该观察在等待期间已被新观察淘汰，原领取已结束且正文未保存；请读取最新观察，原编号不会重复查询".into(),
        ));
    }
    observation.ok_or_else(|| result.err().unwrap_or_else(util::corrupt))
}

pub(super) async fn load(
    state: &AppState,
    tenant: agf_core::ids::TenantId,
    request: Id,
) -> DomainResult<Option<Observation>> {
    let value = state.configurations.get::<Observation>(tenant, DETAIL, record_id(tenant, request)).await?;
    if let Some(row) = &value {
        if (row.tenant, row.request_id) != (tenant, request) || row.scope.tenant != tenant {
            return Err(util::corrupt());
        }
        restore(state, row)?;
    }
    Ok(value)
}
pub(super) fn record_id(tenant: agf_core::ids::TenantId, request: Id) -> Id {
    util::content_id(tenant, request, "observation")
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    scope: super::contract::Scope,
    request_id: Id,
    original_operation_id: Option<Id>,
    started_at: Timestamp,
    observed_at: Timestamp,
    evidence: serde_json::Value,
}
pub(super) fn restore(state: &AppState, row: &Observation) -> DomainResult<DriverObservation> {
    let text = util::decrypt_content(
        state,
        row.tenant,
        record_id(row.tenant, row.request_id),
        &row.content,
        &row.content_hash,
    )?;
    if text.len() != row.content_bytes {
        return Err(util::corrupt());
    }
    let body: Envelope = serde_json::from_str(&text)?;
    if body.scope != row.scope
        || body.request_id != row.request_id
        || body.original_operation_id != row.original_operation_id
        || body.started_at != row.started_at
        || body.observed_at != row.observed_at
    {
        return Err(util::corrupt());
    }
    let baseline = agf_alicloud::apig::policy_driver::restore_evidence(&row.scope.target.binding, &body.evidence)?;
    if baseline.fingerprint() != row.fingerprint || baseline.config_hash() != row.config_hash {
        return Err(util::corrupt());
    }
    Ok(baseline)
}
