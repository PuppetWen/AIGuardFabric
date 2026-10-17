use super::super::{
    authority::Submission,
    binding, eligibility, proof,
    records::{BindingRecord, Values},
    store::Plan,
    util,
};
use super::{
    codec,
    model::{Definition, Index, Journal, Operation, Preview, PreviewRecord, Purpose, State},
    mutation,
};
use crate::state::AppState;
use agf_alicloud::schedulerx3::managed_jobs::{Change, Readback, WriteEvidence, WriteStatus};
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::DomainResult,
    ids::Id,
    time::Timestamp,
};

pub(super) fn apply(
    state: &AppState,
    submission: &Submission,
    values: &Values,
    mut journal: Journal,
    preview_key: (String, Id),
    preview: Box<Preview>,
    mut row: Operation,
    writes: &mut Values,
) -> DomainResult<((Operation, bool), Option<Plan>)> {
    let tenant = row.tenant;
    let target = &row.target;
    let current = super::mock::snapshot(state, target, values)?;
    let (mock, data) = super::mock::change(state, &preview, &current)?;
    let binding_key = util::binding_key(tenant);
    let mut bindings: BindingRecord = util::read(values, &binding_key)?.unwrap_or_default();
    binding::validate(&bindings, tenant)?;
    proof::restore(state, &bindings, tenant)?;
    if bindings.version != preview.input.expected_binding_version {
        return Err(util::stale());
    }
    let now = Timestamp::now();
    if bindings.adoption_version > 0 && bindings.target.as_ref() == Some(target) {
        eligibility::refresh(&mut bindings, &data, target, row.request_id, now)?;
        proof::seal_qualification(state, &mut bindings, tenant)?;
        binding::validate(&bindings, tenant)?;
        util::put(writes, binding_key, &bindings)?;
    }
    // One existing AEAD MockRecord is changed. No second provider or forced callback registration exists.
    util::put(writes, super::mock::key(target), &mock)?;
    row.state = State::Complete;
    row.finished_at = Some(now);
    row.readback = Readback::Matched;
    row.write = Some(WriteEvidence {
        attempted: false,
        status: WriteStatus::Accepted,
        provider_request_id: Some(format!("mock-managed-{}", row.request_id)),
        authority_current: true,
        original_deadline_current: true,
    });
    if let Change::CreateDisabled { declaration } = &preview.input.change {
        journal.definitions.push(Definition {
            scope_id: target.scope_id,
            kind: declaration.kind,
            job_id: row.job_id.clone().ok_or_else(util::corrupt)?,
            request_id: row.request_id,
            total: 1,
        });
    }
    journal.operations.push(row.request_id);
    let old = mutation::encoded_bytes(values, &preview_key)?;
    let bytes = mutation::put(state, tenant, writes, preview_key, &PreviewRecord::Content(preview))?;
    mutation::account(&mut journal, old, bytes)?;
    mutation::operation(state, writes, &mut row)?;
    mutation::account(&mut journal, 0, row.detail_bytes)?;
    mutation::put(
        state,
        tenant,
        writes,
        codec::request_key(tenant, row.request_id),
        &Index {
            tenant,
            request_id: row.request_id,
            purpose: Purpose::Apply,
            actor: row.actor,
            hash: row.input_hash.clone(),
        },
    )?;
    codec::operation(&row, tenant, row.request_id)?;
    let plan = mutation::finish(
        state,
        submission,
        &mut journal,
        std::mem::take(writes),
        row.request_id,
        AuditAction::Execute,
        AuditOutcome::Success,
        "唯一受管 Mock 修改、加密原回执与负面资格核对同事务；未调用真实云或启用 Callback",
    )?;
    Ok(((row, true), Some(plan)))
}
