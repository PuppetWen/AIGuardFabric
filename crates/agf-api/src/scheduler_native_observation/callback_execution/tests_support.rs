use super::super::{scope, tests_proof_support, util};
use super::{
    identity,
    input::{AdmissionInput, Artifact, Outcome},
    model::*,
};
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use std::collections::BTreeMap;

pub(super) fn context(total: u16) -> DomainResult<Context> {
    let mut target = tests_proof_support::target()?;
    target.mocked = false;
    target.transport_mode = "live".into();
    target.scope_id = scope::identity(&target)?;
    Ok(Context {
        tenant: target.tenant,
        kind: "asset-inventory".into(),
        app_id: "9007199254740997".into(),
        job_id: "9007199254741002".into(),
        job_execution_id: "owned-run-20261001:1".into(),
        partition_total: total,
        binding_version: 3,
        adoption_version: 3,
        target,
        owner: Owner { key_id: Id::new() },
    })
}
pub(super) fn input() -> DomainResult<AdmissionInput> {
    Ok(context(2)?.input(Id::new(), 0))
}
pub(super) fn running() -> DomainResult<Fact> {
    let context = context(2)?;
    let input = context.input(Id::new(), 0);
    let at = Timestamp::now().offset_secs(-10);
    Ok(Fact {
        id: identity::fact(context.tenant, &input)?,
        batch_id: identity::batch(context.tenant, &input)?,
        request_id: input.request_id,
        claim_id: Id::new(),
        input_hash: identity::input_hash(&input)?,
        context,
        partition_index: 0,
        submitted_at: at.offset_secs(-5),
        admitted_at: at,
        start_expires_at: at.offset_secs(110),
        started_at: Some(at.offset_secs(1)),
        execution_expires_at: Some(at.offset_secs(301)),
        finished_at: None,
        state: State::Running,
        outcome: None,
        outcome_hash: None,
        seal: None,
    })
}
pub(super) fn outcome() -> Outcome {
    Outcome {
        ok: true,
        skipped: false,
        degraded: false,
        artifacts: vec![Artifact { sha256: util::hash(b"owned artifact bytes"), bytes: 20 }],
    }
}
pub(super) fn batch(total: u16, finished_at: Timestamp) -> DomainResult<Batch> {
    let context = context(total)?;
    let id = identity::batch(context.tenant, &context.input(Id::new(), 0))?;
    let mut partitions = BTreeMap::new();
    for index in 0..total {
        partitions.insert(
            index,
            Partition {
                fact_id: identity::fact(context.tenant, &context.input(Id::new(), index))?,
                claim_id: Id::new(),
                terminal: Some(Terminal {
                    ok: true,
                    skipped: false,
                    degraded: false,
                    outcome_hash: identity::outcome_hash(&outcome())?,
                    finished_at,
                }),
            },
        );
    }
    Ok(Batch { id, context, admitted_at: finished_at.offset_secs(-20), partitions })
}
pub(super) fn other_tenant() -> TenantId {
    TenantId::new()
}
